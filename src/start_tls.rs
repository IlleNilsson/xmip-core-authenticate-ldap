//! `StartTLS`: RFC 4511 section 4.14's extended operation, which turns the
//! connection it is sent on into a TLS one before anything else is said.
//!
//! ```text
//! ExtendedRequest  ::= [APPLICATION 23] SEQUENCE {
//!                        requestName [0] LDAPOID,   1.3.6.1.4.1.1466.20037
//!                        requestValue [1] OCTET STRING OPTIONAL }
//! ExtendedResponse ::= [APPLICATION 24] SEQUENCE { COMPONENTS OF LDAPResult,
//!                        responseName [10] LDAPOID OPTIONAL, ... }
//! ```
//!
//! The handshake starts only on `success`; any other answer leaves the
//! connection in the clear, and the bind is never sent on it. Both
//! directions are here, because the far end a test stands up reads the
//! request and writes the response.

use asn1::ber::expect;
use asn1::{INTEGER, SEQUENCE, integer, tlv};
use authenticate::AuthenticateError;

use crate::bind::{self, BindResponse};

/// `[APPLICATION 23]`, constructed: an `ExtendedRequest`.
pub const EXTENDED_REQUEST: u8 = 0x77;
/// `[APPLICATION 24]`, constructed: an `ExtendedResponse`.
pub const EXTENDED_RESPONSE: u8 = 0x78;
/// `[0]`, primitive: the request's name, an OID as text.
const REQUEST_NAME: u8 = 0x80;
/// The name of the `StartTLS` operation.
pub const START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// The `LDAPMessage` asking for `StartTLS` under `message_id`.
#[must_use]
pub fn request(message_id: i64) -> Vec<u8> {
    let name = tlv(REQUEST_NAME, START_TLS.as_bytes());
    let mut contents = tlv(INTEGER, &integer(message_id));
    contents.extend_from_slice(&tlv(EXTENDED_REQUEST, &name));
    tlv(SEQUENCE, &contents)
}

/// The message id of a `StartTLS` request, read as a directory reads it.
///
/// # Errors
///
/// Not an extended request, or one for another operation.
pub fn read_request(message: &[u8]) -> Result<i64, AuthenticateError> {
    let (message_id, body) = bind::open(message, EXTENDED_REQUEST)?;
    let (name, _) = expect(body, REQUEST_NAME)?;
    if name != START_TLS.as_bytes() {
        return Err(AuthenticateError::new(format!(
            "the extended request is '{}' and not StartTLS",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(message_id)
}

/// The `LDAPMessage` answering a `StartTLS` request, as a directory writes
/// it.
#[must_use]
pub fn response(answer: &BindResponse) -> Vec<u8> {
    answer.encode_as(EXTENDED_RESPONSE)
}

/// A directory's answer to `StartTLS`: its result.
///
/// # Errors
///
/// Not an extended response, or one cut short.
pub fn read_response(message: &[u8]) -> Result<BindResponse, AuthenticateError> {
    BindResponse::decode_as(message, EXTENDED_RESPONSE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_tls_request_is_rfc_4511s_and_reads_back() {
        let wire = request(1);
        assert_eq!(&wire[..7], [0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18]);
        assert_eq!(read_request(&wire).expect("read"), 1);

        let answer = BindResponse::answering(1, 52).saying("no certificate");
        assert_eq!(read_response(&response(&answer)).expect("read"), answer);
        assert!(
            read_response(&answer.encode()).is_err(),
            "a bind's response"
        );
    }
}
