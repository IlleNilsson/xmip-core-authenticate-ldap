#![forbid(unsafe_code)]

//! Authenticate by LDAP: a simple bind at the directory with the presented
//! username and password.
//!
//! RFC 4511 section 4.2. The node holds no verifier of its own for these
//! users; the directory does, and the way to ask a directory whether a
//! password is right is to bind with it. The first gate reads the name and
//! calls it a `username` claim, with the password riding on
//! `Presented::proof` under `password`. This gate writes the name into the
//! DN template it was configured with — escaped as RFC 4514 says, so a name
//! cannot reach outside its place in the DN — opens a connection to the
//! directory it was configured with, binds, and reads the result:
//! `success` proves the claim, `invalidCredentials` and `noSuchObject`
//! refuse it alike, and anything else is refused with the directory's own
//! words. An empty password is never sent: RFC 4513 makes that an
//! unauthenticated bind, which succeeds and proves nothing.
//!
//! The endpoint is configuration (ADR-0045) and the tests stand a directory
//! up in-process over loopback. The bind travels as the connection carries
//! it, and a simple bind carries the password in the clear: point this at a
//! directory over a protected path. The mechanism keeps its own name,
//! `ldap`, so an Acceptance can say which verifier a Location uses
//! (ADR-0050, amendment 2026-09-16).
//!
//! A directory that binds by user principal name, as Active Directory does,
//! is named with [`LdapAuthenticator::binding_by_principal`]: the bind name
//! is then the name itself, read and written by the identify capability's
//! `UserPrincipalName` and never parsed here (ADR-0054).

pub mod bind;

pub use bind::{BindRequest, BindResponse};

use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use identify::UserPrincipalName;
use identify::evidence::{self, PASSWORD};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use xcore::{Mechanism, mechanism};

/// Where the username goes in a DN template.
pub const PLACEHOLDER: &str = "{username}";

/// How long the directory is given to connect and to answer unless
/// configured otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A value as it may stand inside a DN: RFC 4514 section 2.4's escaping.
#[must_use]
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (at, character) in value.chars().enumerate() {
        match character {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=' => {
                out.push('\\');
                out.push(character);
            }
            '\0' => out.push_str("\\00"),
            '#' | ' ' if at == 0 => {
                out.push('\\');
                out.push(character);
            }
            ' ' if at == last => out.push_str("\\ "),
            _ => out.push(character),
        }
    }
    out
}

/// Verifies a `username` claim with a `password` proof by binding at a
/// directory.
#[derive(Clone, Debug)]
pub struct LdapAuthenticator {
    endpoint: String,
    naming: Naming,
    timeout: Duration,
}

/// How the presented name becomes the name the bind is made as.
#[derive(Clone, Debug)]
enum Naming {
    /// Written into a DN template, in place of `{username}`.
    Template(String),
    /// The user principal name itself, a bare user being looked up in the
    /// default domain where one is configured.
    Principal(Option<String>),
}

impl LdapAuthenticator {
    /// Binds at `endpoint` — `host:port` — as `template` with the username
    /// in place of `{username}`: `uid={username},ou=people,dc=example,dc=org`.
    ///
    /// # Errors
    ///
    /// The template has no `{username}` in it, so every user would bind as
    /// the same entry.
    pub fn new(
        endpoint: impl Into<String>,
        template: impl Into<String>,
    ) -> Result<Self, AuthenticateError> {
        let template = template.into();
        if !template.contains(PLACEHOLDER) {
            return Err(AuthenticateError::new(format!(
                "the DN template '{template}' has no '{PLACEHOLDER}' in it"
            )));
        }
        Ok(Self {
            endpoint: endpoint.into(),
            naming: Naming::Template(template),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Binds at `endpoint` with the user principal name itself as the bind
    /// name, which Active Directory takes in a simple bind. `PARTNERX\jane`
    /// and `jane@partnerx` bind alike as `jane@partnerx`, and a bare `jane`
    /// is looked up in `default_domain` where one is given.
    #[must_use]
    pub fn binding_by_principal(endpoint: impl Into<String>, default_domain: Option<&str>) -> Self {
        Self {
            endpoint: endpoint.into(),
            naming: Naming::Principal(default_domain.map(str::to_string)),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// How long the directory is given to connect, and again to answer.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The directory this binds at.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The account `username` names, where it is a user principal name or
    /// the default domain makes it one.
    fn principal(&self, username: &str) -> Option<UserPrincipalName> {
        UserPrincipalName::parse(username).or_else(|| match &self.naming {
            Naming::Principal(Some(domain)) => UserPrincipalName::of(username, domain),
            _ => None,
        })
    }

    /// Refuse a claim whose `principal.user` evidence names another account
    /// than the one it presents. Evidence is never proof: agreeing with it
    /// proves nothing, and the bind still decides.
    fn same_account(&self, presented: &Presented) -> Result<(), AuthenticateError> {
        let claimed = presented
            .evidence
            .iter()
            .find(|(name, _)| name == evidence::PRINCIPAL_USER)
            .and_then(|(_, value)| UserPrincipalName::parse(value));
        match (claimed, self.principal(&presented.value)) {
            (Some(claimed), Some(read)) if !claimed.is(&read) => {
                Err(AuthenticateError::new(format!(
                    "the claim presents '{read}' and its evidence names '{claimed}': not the \
                     same account"
                )))
            }
            _ => Ok(()),
        }
    }

    /// The name `username` binds as: the DN the template makes of it, or
    /// its user principal name in canonical form.
    ///
    /// # Errors
    ///
    /// This binds by principal, and `username` is not a user principal name
    /// and no default domain makes it one.
    pub fn bind_name(&self, username: &str) -> Result<String, AuthenticateError> {
        let domain = match &self.naming {
            Naming::Template(template) => {
                return Ok(template.replace(PLACEHOLDER, &escape(username)));
            }
            Naming::Principal(domain) => domain.as_deref(),
        };
        self.principal(username)
            .map(|principal| principal.to_string())
            .ok_or_else(|| {
                AuthenticateError::new(match domain {
                    Some(domain) => format!(
                        "'{username}' is not a user principal name, nor a user in the default \
                         domain '{domain}'"
                    ),
                    None => format!(
                        "'{username}' is not a user principal name and no default domain is \
                         configured: the directory binds by principal"
                    ),
                })
            })
    }

    fn unreachable(&self, failure: &dyn std::fmt::Display) -> AuthenticateError {
        AuthenticateError::new(format!(
            "the directory at '{}' cannot be reached: {failure}",
            self.endpoint
        ))
    }

    fn connect(&self) -> Result<TcpStream, AuthenticateError> {
        let addresses = self
            .endpoint
            .to_socket_addrs()
            .map_err(|failure| self.unreachable(&failure))?;
        let mut last = self.unreachable(&"the name resolves to no address");
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.timeout) {
                Ok(stream) => return Ok(stream),
                Err(failure) => last = self.unreachable(&failure),
            }
        }
        Err(last)
    }

    /// Bind as `name` with `password` and answer with what the directory
    /// said.
    ///
    /// # Errors
    ///
    /// The directory cannot be reached, does not answer in time, or answers
    /// with something that is not the response to this bind.
    pub fn bind(&self, name: &str, password: &str) -> Result<BindResponse, AuthenticateError> {
        const MESSAGE_ID: i64 = 1;
        let mut stream = self.connect()?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|failure| self.unreachable(&failure))?;
        let request = BindRequest {
            message_id: MESSAGE_ID,
            name: name.to_string(),
            password: password.to_string(),
        };
        stream
            .write_all(&request.encode())
            .map_err(|failure| self.unreachable(&failure))?;
        let response = BindResponse::decode(&bind::read_message(&mut stream)?)?;
        // A directory does not answer an unbind, and one that has already
        // hung up has lost nothing.
        let _ = stream.write_all(&bind::unbind(MESSAGE_ID + 1));
        if response.message_id != MESSAGE_ID {
            return Err(AuthenticateError::new(format!(
                "the directory answered message {} and the bind was message {MESSAGE_ID}",
                response.message_id
            )));
        }
        Ok(response)
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `ldap`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "ldap"
}

impl Authenticator for LdapAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::ldap()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the LDAP verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let password = presented.proof(evidence::PASSWORD).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PASSWORD}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        if presented.value.is_empty() {
            return Err(AuthenticateError::new("the username presented is empty"));
        }
        if password.is_empty() {
            return Err(AuthenticateError::new(
                "the password presented is empty, and a bind without one proves nothing",
            ));
        }
        let name = self.bind_name(&presented.value)?;
        self.same_account(presented)?;
        let response = self.bind(&name, password)?;
        match response.result_code {
            bind::SUCCESS => Ok(Verified::Proven),
            bind::INVALID_CREDENTIALS | bind::NO_SUCH_OBJECT => Ok(Verified::Refused),
            code => Err(AuthenticateError::new(format!(
                "the directory answered the bind with {code} ({}){}",
                bind::result_name(code),
                if response.diagnostic.is_empty() {
                    String::new()
                } else {
                    format!(": {}", response.diagnostic)
                }
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    const TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=org";

    /// The in-process far end: a directory over loopback that answers
    /// `binds` binds and keeps the DNs it was asked about.
    struct Directory {
        endpoint: String,
        seen: Arc<Mutex<Vec<String>>>,
        serving: JoinHandle<()>,
    }

    fn answer(request: &BindRequest) -> BindResponse {
        let id = request.message_id;
        match (request.name.as_str(), request.password.as_str()) {
            ("uid=alice,ou=people,dc=example,dc=org" | "jane@partnerx", "pencil")
            | ("uid=Smith\\, John,ou=people,dc=example,dc=org", "pen") => {
                BindResponse::answering(id, bind::SUCCESS)
            }
            ("uid=busy,ou=people,dc=example,dc=org", _) => {
                BindResponse::answering(id, 51).saying("try again later")
            }
            ("uid=ghost,ou=people,dc=example,dc=org", _) => {
                BindResponse::answering(id, bind::NO_SUCH_OBJECT)
            }
            ("uid=crossed,ou=people,dc=example,dc=org", _) => {
                BindResponse::answering(id + 40, bind::SUCCESS)
            }
            _ => BindResponse::answering(id, bind::INVALID_CREDENTIALS).saying("80090308"),
        }
    }

    fn directory(binds: usize) -> Directory {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let endpoint = listener.local_addr().expect("bound").to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let serving = thread::spawn(move || {
            for _ in 0..binds {
                let (mut stream, _) = listener.accept().expect("a client");
                let wire = bind::read_message(&mut stream).expect("a message");
                let request = BindRequest::decode(&wire).expect("a bind");
                record
                    .lock()
                    .expect("unpoisoned")
                    .push(request.name.clone());
                stream
                    .write_all(&answer(&request).encode())
                    .expect("answered");
                // The client unbinds before it closes.
                let farewell = bind::read_message(&mut stream).expect("an unbind");
                assert_eq!(farewell, bind::unbind(request.message_id + 1));
            }
        });
        Directory {
            endpoint,
            seen,
            serving,
        }
    }

    impl Directory {
        fn verifier(&self) -> LdapAuthenticator {
            LdapAuthenticator::new(&self.endpoint, TEMPLATE)
                .expect("a template")
                .with_timeout(Duration::from_secs(2))
        }

        fn finish(self) -> Vec<String> {
            self.serving.join().expect("the directory served");
            let seen = self.seen.lock().expect("unpoisoned");
            seen.clone()
        }
    }

    fn claim(username: &str, password: &str) -> Presented {
        Presented::passed(mechanism::username(), username).with_proof(evidence::PASSWORD, password)
    }

    #[test]
    fn a_bind_the_directory_takes_proves_the_username() {
        let directory = directory(2);
        let verifier = directory.verifier();
        assert_eq!(
            verifier
                .verify(&claim("alice", "pencil"))
                .expect("verified"),
            Verified::Proven
        );
        // A claim the first gate already filed under this mechanism reads too.
        let filed =
            Presented::passed(mechanism::ldap(), "alice").with_proof(evidence::PASSWORD, "pencil");
        assert_eq!(verifier.verify(&filed).expect("verified"), Verified::Proven);
        assert_eq!(verifier.mechanism().name(), "ldap");
        assert_eq!(verifier.endpoint(), directory.endpoint);
        assert_eq!(
            directory.finish(),
            ["uid=alice,ou=people,dc=example,dc=org"; 2]
        );
    }

    #[test]
    fn each_spelling_of_one_account_binds_by_the_same_user_principal_name() {
        let directory = directory(3);
        let verifier =
            LdapAuthenticator::binding_by_principal(&directory.endpoint, Some("PartnerX"))
                .with_timeout(Duration::from_secs(2));
        for name in ["PARTNERX\\jane", "jane@PartnerX", "jane"] {
            let filed = claim(name, "pencil").with_evidence(evidence::PRINCIPAL_USER, name);
            assert_eq!(
                verifier.verify(&filed).expect("verified"),
                Verified::Proven,
                "{name}"
            );
        }
        assert_eq!(directory.finish(), ["jane@partnerx"; 3]);
    }

    #[test]
    fn a_bare_name_without_a_default_domain_and_evidence_of_another_account_are_refused() {
        // No directory stands here: nothing may be sent for either claim.
        let verifier = LdapAuthenticator::binding_by_principal("127.0.0.1:9", None);
        let bare = verifier
            .verify(&claim("jane", "pencil"))
            .expect_err("refused");
        assert!(
            bare.message.contains("'jane' is not a user principal name")
                && bare.message.contains("no default domain"),
            "{}",
            bare.message
        );
        let filed = claim("PARTNERX\\jane", "pencil")
            .with_evidence(evidence::PRINCIPAL_USER, "mallory@partnerx");
        let other = verifier.verify(&filed).expect_err("refused");
        assert!(
            other.message.contains("'jane@partnerx'")
                && other.message.contains("'mallory@partnerx'"),
            "{}",
            other.message
        );
    }

    #[test]
    fn a_wrong_password_and_an_entry_the_directory_lacks_are_refused_alike() {
        let directory = directory(2);
        let verifier = directory.verifier();
        assert_eq!(
            verifier.verify(&claim("alice", "pen")).expect("verified"),
            Verified::Refused
        );
        assert_eq!(
            verifier
                .verify(&claim("ghost", "pencil"))
                .expect("verified"),
            Verified::Refused
        );
        directory.finish();
    }

    #[test]
    fn a_name_cannot_reach_outside_its_place_in_the_dn() {
        assert_eq!(escape("Smith, John"), "Smith\\, John");
        assert_eq!(escape(" #a=b+c "), "\\ #a\\=b\\+c\\ ");
        assert_eq!(escape("#lead"), "\\#lead");
        assert_eq!(escape("a\0<b>;\"\\"), "a\\00\\<b\\>\\;\\\"\\\\");

        let directory = directory(2);
        let verifier = directory.verifier();
        assert_eq!(
            verifier
                .verify(&claim("Smith, John", "pen"))
                .expect("verified"),
            Verified::Proven
        );
        // An injected DN binds as nobody the directory knows.
        let injected = "alice,ou=people,dc=example,dc=org";
        assert_eq!(
            verifier
                .verify(&claim(injected, "pencil"))
                .expect("verified"),
            Verified::Refused
        );
        let seen = directory.finish();
        assert_eq!(
            seen[1],
            "uid=alice\\,ou\\=people\\,dc\\=example\\,dc\\=org,ou=people,dc=example,dc=org"
        );
    }

    #[test]
    fn what_the_directory_says_beyond_yes_and_no_is_the_reason() {
        let directory = directory(2);
        let verifier = directory.verifier();
        let busy = verifier
            .verify(&claim("busy", "pencil"))
            .expect_err("refused");
        assert_eq!(
            busy.message,
            "the directory answered the bind with 51 (busy): try again later"
        );
        let crossed = verifier
            .verify(&claim("crossed", "pencil"))
            .expect_err("refused");
        assert!(
            crossed.message.contains("answered message 41"),
            "{}",
            crossed.message
        );
        directory.finish();
    }

    #[test]
    fn an_empty_password_is_never_sent_and_a_missing_one_is_asked_for_by_name() {
        // No directory stands here: nothing may be sent for either claim.
        let verifier = LdapAuthenticator::new("127.0.0.1:9", TEMPLATE).expect("a template");
        let empty = verifier.verify(&claim("alice", "")).expect_err("refused");
        assert!(
            empty.message.contains("proves nothing"),
            "{}",
            empty.message
        );
        let bare = Presented::passed(mechanism::username(), "alice");
        let missing = verifier.verify(&bare).expect_err("refused");
        assert!(
            missing.message.contains("'password' proof"),
            "{}",
            missing.message
        );
        let key = Presented::passed(mechanism::api_key(), "k-1").with_proof("api-key", "s");
        let other = verifier.verify(&key).expect_err("refused");
        assert!(other.message.contains("'api-key'"), "{}", other.message);
    }

    #[test]
    fn a_directory_that_is_not_there_and_a_template_without_a_name_say_so() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            listener.local_addr().expect("bound").port()
        };
        let verifier = LdapAuthenticator::new(format!("127.0.0.1:{port}"), TEMPLATE)
            .expect("a template")
            .with_timeout(Duration::from_millis(500));
        let failure = verifier
            .verify(&claim("alice", "pencil"))
            .expect_err("refused");
        assert!(
            failure.message.contains("cannot be reached"),
            "{}",
            failure.message
        );

        let fixed = LdapAuthenticator::new("127.0.0.1:389", "cn=admin,dc=example,dc=org")
            .expect_err("refused");
        assert!(fixed.message.contains("'{username}'"), "{}", fixed.message);
    }
}
