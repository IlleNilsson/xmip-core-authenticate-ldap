//! The bind: RFC 4511 section 4.2's request and response, and nothing else
//! of LDAP.
//!
//! ```text
//! LDAPMessage  ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { ... } }
//! BindRequest  ::= [APPLICATION 0] SEQUENCE { version INTEGER (3),
//!                    name LDAPDN, authentication CHOICE { simple [0] OCTET STRING } }
//! BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode ENUMERATED,
//!                    matchedDN LDAPDN, diagnosticMessage LDAPString, ... }
//! ```
//!
//! Both directions of both messages are here, because the far end a test
//! stands up reads the request and writes the response.

use asn1::{ENUMERATED, INTEGER, OCTET_STRING, SEQUENCE, expect, integer, read_integer, tlv};
use authenticate::AuthenticateError;
use std::fmt;
use std::io::Read;

/// `[APPLICATION 0]`, constructed: a `BindRequest`.
pub const BIND_REQUEST: u8 = 0x60;
/// `[APPLICATION 1]`, constructed: a `BindResponse`.
pub const BIND_RESPONSE: u8 = 0x61;
/// `[0]`, primitive: the simple authentication choice, a password.
pub const SIMPLE: u8 = 0x80;
/// The protocol version a bind asks for.
pub const VERSION: i64 = 3;

/// `success`: the bind held.
pub const SUCCESS: i64 = 0;
/// `noSuchObject`: the directory holds no such entry.
pub const NO_SUCH_OBJECT: i64 = 32;
/// `invalidCredentials`: the name or the password is wrong.
pub const INVALID_CREDENTIALS: i64 = 49;

/// The largest message this reads off a stream. A bind response is a few
/// dozen bytes; a directory that sends more than this is not answering a
/// bind.
pub const LARGEST: usize = 64 * 1024;

/// One whole `LDAPMessage` off a stream, tag and length included.
///
/// # Errors
///
/// The stream ends or fails first, or the message is larger than
/// [`LARGEST`].
pub fn read_message(stream: &mut impl Read) -> Result<Vec<u8>, AuthenticateError> {
    asn1::read_element(stream, LARGEST).map_err(|failure| {
        AuthenticateError::new(format!("the directory's answer: {}", failure.message))
    })
}

/// An `UnbindRequest` under `message_id`: `[APPLICATION 2]` NULL, which a
/// client sends before it closes and a directory does not answer.
#[must_use]
pub fn unbind(message_id: i64) -> Vec<u8> {
    let mut contents = tlv(INTEGER, &integer(message_id));
    contents.extend_from_slice(&[0x42, 0x00]);
    tlv(SEQUENCE, &contents)
}

/// What RFC 4511 appendix A calls a result code, for the ones a bind meets.
#[must_use]
pub const fn result_name(code: i64) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        13 => "confidentialityRequired",
        32 => "noSuchObject",
        34 => "invalidDNSyntax",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        80 => "other",
        _ => "a result code RFC 4511 does not name for a bind",
    }
}

fn text(contents: &[u8], what: &str) -> Result<String, AuthenticateError> {
    String::from_utf8(contents.to_vec())
        .map_err(|_| AuthenticateError::new(format!("the bind's {what} is not UTF-8")))
}

/// The envelope: the message id, then the operation under `operation`.
fn open(message: &[u8], operation: u8) -> Result<(i64, &[u8]), AuthenticateError> {
    let (envelope, _) = expect(message, SEQUENCE)?;
    let (id, rest) = expect(envelope, INTEGER)?;
    let (body, _) = expect(rest, operation)?;
    Ok((read_integer(id)?, body))
}

/// A simple bind: a DN and its password.
#[derive(Clone, Eq, PartialEq)]
pub struct BindRequest {
    /// The id the response must echo.
    pub message_id: i64,
    /// The DN binding.
    pub name: String,
    /// The password, in the clear as a simple bind carries it.
    pub password: String,
}

impl fmt::Debug for BindRequest {
    /// The password is not printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindRequest")
            .field("message_id", &self.message_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl BindRequest {
    /// The `LDAPMessage` carrying this bind.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bind = tlv(INTEGER, &integer(VERSION));
        bind.extend_from_slice(&tlv(OCTET_STRING, self.name.as_bytes()));
        bind.extend_from_slice(&tlv(SIMPLE, self.password.as_bytes()));
        let mut contents = tlv(INTEGER, &integer(self.message_id));
        contents.extend_from_slice(&tlv(BIND_REQUEST, &bind));
        tlv(SEQUENCE, &contents)
    }

    /// Read an `LDAPMessage` as a simple bind, as a directory does.
    ///
    /// # Errors
    ///
    /// Not a bind request, not version 3, or not a simple bind.
    pub fn decode(message: &[u8]) -> Result<Self, AuthenticateError> {
        let (message_id, body) = open(message, BIND_REQUEST)?;
        let (version, rest) = expect(body, INTEGER)?;
        let version = read_integer(version)?;
        if version != VERSION {
            return Err(AuthenticateError::new(format!(
                "the bind asks for LDAP version {version} and this speaks {VERSION}"
            )));
        }
        let (name, rest) = expect(rest, OCTET_STRING)?;
        let (password, _) = expect(rest, SIMPLE)?;
        Ok(Self {
            message_id,
            name: text(name, "name")?,
            password: text(password, "password")?,
        })
    }
}

/// What the directory made of a bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindResponse {
    /// The id of the request this answers.
    pub message_id: i64,
    /// RFC 4511's result code: [`SUCCESS`], [`INVALID_CREDENTIALS`], the rest.
    pub result_code: i64,
    /// The part of the DN the directory did find, usually empty.
    pub matched_dn: String,
    /// What the directory has to say about it, usually empty.
    pub diagnostic: String,
}

impl BindResponse {
    /// An answer to `message_id` with `result_code` and nothing to add.
    #[must_use]
    pub fn answering(message_id: i64, result_code: i64) -> Self {
        Self {
            message_id,
            result_code,
            matched_dn: String::new(),
            diagnostic: String::new(),
        }
    }

    /// The same answer with a diagnostic message.
    #[must_use]
    pub fn saying(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostic = diagnostic.into();
        self
    }

    /// The `LDAPMessage` carrying this response, as a directory writes it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut result = tlv(ENUMERATED, &integer(self.result_code));
        result.extend_from_slice(&tlv(OCTET_STRING, self.matched_dn.as_bytes()));
        result.extend_from_slice(&tlv(OCTET_STRING, self.diagnostic.as_bytes()));
        let mut contents = tlv(INTEGER, &integer(self.message_id));
        contents.extend_from_slice(&tlv(BIND_RESPONSE, &result));
        tlv(SEQUENCE, &contents)
    }

    /// Read an `LDAPMessage` as a bind response. Referrals and SASL
    /// credentials after the diagnostic message are not read.
    ///
    /// # Errors
    ///
    /// Not a bind response, or one cut short.
    pub fn decode(message: &[u8]) -> Result<Self, AuthenticateError> {
        let (message_id, body) = open(message, BIND_RESPONSE)?;
        let (code, rest) = expect(body, ENUMERATED)?;
        let (matched_dn, rest) = expect(rest, OCTET_STRING)?;
        let (diagnostic, _) = expect(rest, OCTET_STRING)?;
        Ok(Self {
            message_id,
            result_code: read_integer(code)?,
            matched_dn: text(matched_dn, "matched DN")?,
            diagnostic: text(diagnostic, "diagnostic message")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_larger_than_a_bind_response_is_refused_saying_whose() {
        let mut huge: &[u8] = &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff];
        let failure = read_message(&mut huge).expect_err("refused");
        assert!(
            failure.message.starts_with("the directory's answer: "),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("65536"), "{}", failure.message);
    }

    #[test]
    fn a_bind_request_is_rfc_4511s_byte_for_byte_and_reads_back() {
        let request = BindRequest {
            message_id: 1,
            name: "cn=a".to_string(),
            password: "pw".to_string(),
        };
        let wire = request.encode();
        assert_eq!(
            wire,
            [
                0x30, 0x12, 0x02, 0x01, 0x01, 0x60, 0x0d, 0x02, 0x01, 0x03, 0x04, 0x04, b'c', b'n',
                b'=', b'a', 0x80, 0x02, b'p', b'w'
            ]
        );
        assert_eq!(BindRequest::decode(&wire).expect("read"), request);
        assert!(!format!("{request:?}").contains("pw"));
    }

    #[test]
    fn a_bind_response_carries_its_code_and_what_the_directory_says() {
        let response = BindResponse::answering(7, INVALID_CREDENTIALS).saying("80090308: 52e");
        let wire = response.encode();
        assert_eq!(&wire[..7], [0x30, 0x19, 0x02, 0x01, 0x07, 0x61, 0x14]);
        let read = BindResponse::decode(&wire).expect("read");
        assert_eq!(read, response);
        assert_eq!(result_name(read.result_code), "invalidCredentials");
        assert_eq!(result_name(SUCCESS), "success");
        assert_eq!(result_name(NO_SUCH_OBJECT), "noSuchObject");
    }

    #[test]
    fn one_message_is_not_read_as_the_other() {
        let request = BindRequest {
            message_id: 1,
            name: String::new(),
            password: "x".to_string(),
        };
        let failure = BindResponse::decode(&request.encode()).expect_err("refused");
        assert!(failure.message.contains("0x61"), "{}", failure.message);
        let failure = BindRequest::decode(&BindResponse::answering(1, SUCCESS).encode())
            .expect_err("refused");
        assert!(failure.message.contains("0x60"), "{}", failure.message);
        assert!(BindRequest::decode(&unbind(2)).is_err());
    }

    #[test]
    fn an_older_version_and_an_unbind_are_what_they_say() {
        let mut wire = BindRequest {
            message_id: 1,
            name: String::new(),
            password: String::new(),
        }
        .encode();
        wire[9] = 2;
        let failure = BindRequest::decode(&wire).expect_err("refused");
        assert!(failure.message.contains("version 2"), "{}", failure.message);
        assert_eq!(unbind(2), [0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00]);
    }
}
