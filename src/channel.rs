//! The connection a bind travels on, guarded before the password is sent.
//!
//! A simple bind carries the password as it is, so it is sent only inside
//! TLS: `StartTLS` on the directory's ordinary port (RFC 4511 section 4.14,
//! RFC 4513 section 3), or LDAPS, TLS from the first byte. The TLS is the
//! estate's own, `xmip-core-library-tls`, against the operating system's
//! trust store or one the configuration hands over. A bind in the clear is
//! taken only where the directory is this machine: the name must be
//! `localhost` or a loopback address before anything is connected, and the
//! peer connected to must be a loopback address before anything is sent.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use authenticate::AuthenticateError;

use crate::bind;
use crate::start_tls;

/// How a bind's connection is guarded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Protection {
    /// `StartTLS` on the connection, then the bind inside TLS.
    #[default]
    StartTls,
    /// TLS from the first byte, as port 636 speaks it.
    Ldaps,
    /// No TLS: taken only where the directory is on loopback.
    Cleartext,
}

/// A connection a bind can be written to and read from.
pub trait Channel: Read + Write {}

impl<T: Read + Write> Channel for T {}

/// The message id `StartTLS` is asked under; the bind follows it.
pub const START_TLS_ID: i64 = 1;

/// Where the bind goes, and how it is guarded on the way.
#[derive(Clone, Debug)]
pub struct Directory<'a> {
    /// `host:port`.
    pub endpoint: &'a str,
    /// How long the directory has to connect, and again to answer.
    pub timeout: Duration,
    /// How the connection is guarded.
    pub protection: Protection,
    /// The trust store the directory's certificate must reach; `None` is
    /// the operating system's.
    pub trust: Option<&'a Arc<tls::ClientConfig>>,
}

impl Directory<'_> {
    fn unreachable(&self, failure: &dyn std::fmt::Display) -> AuthenticateError {
        AuthenticateError::new(format!(
            "the directory at '{}' cannot be reached: {failure}",
            self.endpoint
        ))
    }

    fn host(&self) -> &str {
        net::authority::host_of(self.endpoint)
    }

    /// The connection, guarded as configured, ready for the bind.
    ///
    /// # Errors
    ///
    /// A bind in the clear to a directory that is not on loopback, a
    /// directory that cannot be reached, a `StartTLS` it refuses, or a TLS
    /// handshake that cannot start.
    pub fn open(&self) -> Result<Box<dyn Channel>, AuthenticateError> {
        if self.protection == Protection::Cleartext && !names_loopback(self.host()) {
            return Err(self.cleartext_refused());
        }
        let mut tcp = net::connect(self.endpoint, Some(self.timeout))
            .map_err(|failure| self.unreachable(&failure))?;
        match self.protection {
            Protection::Cleartext => {
                let peer = tcp
                    .peer_addr()
                    .map_err(|failure| self.unreachable(&failure))?;
                if !peer.ip().is_loopback() {
                    return Err(self.cleartext_refused());
                }
                Ok(Box::new(tcp))
            }
            Protection::Ldaps => self.guard(tcp),
            Protection::StartTls => {
                self.start_tls(&mut tcp)?;
                self.guard(tcp)
            }
        }
    }

    fn cleartext_refused(&self) -> AuthenticateError {
        AuthenticateError::new(format!(
            "a bind in the clear carries the password as it is, and the directory at '{}' is \
             not on loopback: use StartTLS or LDAPS",
            self.endpoint
        ))
    }

    /// Ask for `StartTLS` and read that the directory agreed.
    fn start_tls(&self, tcp: &mut TcpStream) -> Result<(), AuthenticateError> {
        tcp.write_all(&start_tls::request(START_TLS_ID))
            .map_err(|failure| self.unreachable(&failure))?;
        let answer = start_tls::read_response(&bind::read_message(tcp)?)?;
        if answer.message_id != START_TLS_ID {
            return Err(AuthenticateError::new(format!(
                "the directory answered message {} and StartTLS was message {START_TLS_ID}",
                answer.message_id
            )));
        }
        if answer.result_code != bind::SUCCESS {
            return Err(AuthenticateError::new(format!(
                "the directory refused StartTLS with {} ({}){}, and no bind is sent in the \
                 clear",
                answer.result_code,
                bind::result_name(answer.result_code),
                if answer.diagnostic.is_empty() {
                    String::new()
                } else {
                    format!(": {}", answer.diagnostic)
                }
            )));
        }
        Ok(())
    }

    fn guard(&self, tcp: TcpStream) -> Result<Box<dyn Channel>, AuthenticateError> {
        let host = self.host();
        match self.trust {
            Some(config) => tls::client_with(host, tcp, Arc::clone(config)),
            None => tls::client(host, tcp),
        }
        .map(|guarded| Box::new(guarded) as Box<dyn Channel>)
        .map_err(|failure| {
            AuthenticateError::new(format!(
                "the directory at '{}' cannot be guarded with TLS: {}",
                self.endpoint, failure.message
            ))
        })
    }
}

/// Whether `host` names this machine without being resolved: `localhost`,
/// or an address in `127.0.0.0/8` or `::1`.
fn names_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindRequest, BindResponse, LdapAuthenticator};
    use authenticate::Authenticator;
    use context::Verified;
    use identify::Presented;
    use identify::evidence;
    use std::net::TcpListener;
    use std::thread;
    use xcore::mechanism;

    const TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=org";

    fn claim() -> Presented {
        Presented::passed(mechanism::username(), "alice").with_proof(evidence::PASSWORD, "pencil")
    }

    #[test]
    fn a_bind_in_the_clear_to_a_directory_off_loopback_is_refused_before_connecting() {
        for endpoint in [
            "192.0.2.1:389",
            "directory.example:389",
            "[2001:db8::1]:389",
        ] {
            let verifier = LdapAuthenticator::new(endpoint, TEMPLATE)
                .expect("a template")
                .in_the_clear()
                .with_timeout(Duration::from_secs(30));
            let started = std::time::Instant::now();

            let refused = verifier.verify(&claim()).expect_err("refused");

            assert!(refused.message.contains("not on loopback"), "{refused}");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "nothing connected"
            );
        }
    }

    /// A directory over loopback that answers `StartTLS` with `code`, and on
    /// success serves TLS as `localhost` and answers one bind inside it.
    fn directory(code: i64) -> (String, Arc<tls::ClientConfig>, thread::JoinHandle<String>) {
        let signed =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a cert");
        let anchor = signed.cert.pem();
        let server = tls::server_config(
            anchor.as_bytes(),
            signed.signing_key.serialize_pem().as_bytes(),
        )
        .expect("a server config");
        let trust = Arc::new(tls::trusting(anchor.as_bytes()).expect("a trust store"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("bound").port();
        let serving = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().expect("a client");
            let id = start_tls::read_request(&bind::read_message(&mut tcp).expect("a message"))
                .expect("StartTLS");
            let answer = BindResponse::answering(id, code).saying("not today");
            tcp.write_all(&start_tls::response(&answer))
                .expect("answered");
            if code != bind::SUCCESS {
                // Nothing more may arrive in the clear: the client hangs up.
                let mut rest = Vec::new();
                let _ = tcp.read_to_end(&mut rest);
                return String::from_utf8_lossy(&rest).into_owned();
            }
            let mut guarded = tls::server(tcp, Arc::new(server)).expect("tls");
            let wire = bind::read_message(&mut guarded).expect("a bind");
            let request = BindRequest::decode(&wire).expect("a bind");
            let answer = BindResponse::answering(request.message_id, bind::SUCCESS);
            guarded.write_all(&answer.encode()).expect("answered");
            let _ = bind::read_message(&mut guarded);
            request.name
        });
        (format!("localhost:{port}"), trust, serving)
    }

    #[test]
    fn start_tls_then_the_bind_inside_tls_proves_the_username() {
        let (endpoint, trust, serving) = directory(bind::SUCCESS);
        let verifier = LdapAuthenticator::new(endpoint, TEMPLATE)
            .expect("a template")
            .trusting(trust)
            .with_timeout(Duration::from_secs(5));

        assert_eq!(verifier.protection(), Protection::StartTls);
        assert_eq!(verifier.verify(&claim()).expect("bound"), Verified::Proven);
        assert_eq!(
            serving.join().expect("served"),
            "uid=alice,ou=people,dc=example,dc=org"
        );
    }

    #[test]
    fn a_start_tls_the_directory_refuses_sends_no_bind_in_the_clear() {
        let (endpoint, trust, serving) = directory(52);
        let verifier = LdapAuthenticator::new(endpoint, TEMPLATE)
            .expect("a template")
            .trusting(trust)
            .with_timeout(Duration::from_secs(5));

        let refused = verifier.verify(&claim()).expect_err("refused");

        assert!(
            refused
                .message
                .contains("refused StartTLS with 52 (unavailable): not today"),
            "{refused}"
        );
        assert!(!serving.join().expect("served").contains("pencil"));
    }
}
