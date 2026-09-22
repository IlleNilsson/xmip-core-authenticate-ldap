//! What a bind takes of X.690: definite lengths, small integers, and one
//! element read off a stream no larger than a bind response honestly is.
//!
//! The reader is the estate's one, `xmip-core-asn1`; this carried its own
//! until 2026-09-22, when the manifest also came to say so.

use authenticate::AuthenticateError;
use std::io::Read;

pub use asn1::{ENUMERATED, INTEGER, OCTET_STRING, SEQUENCE, expect, read, read_integer, tlv};

/// The largest element this reads off a stream. A bind response is a few
/// dozen bytes; a directory that sends more than this is not answering a
/// bind.
pub const LARGEST: usize = 64 * 1024;

/// A two's-complement integer in the fewest bytes, under `tag`: `INTEGER`
/// for a message id, `ENUMERATED` for a result code.
#[must_use]
pub fn integer(tag: u8, value: i64) -> Vec<u8> {
    tlv(tag, &asn1::integer(value))
}

/// One whole element of the directory's answer off a stream, tag and length
/// included.
///
/// # Errors
///
/// The stream ends or fails first, or the element is larger than
/// [`LARGEST`].
pub fn read_element(stream: &mut impl Read) -> Result<Vec<u8>, AuthenticateError> {
    asn1::read_element(stream, LARGEST).map_err(|failure| {
        AuthenticateError::new(format!("the directory's answer: {}", failure.message))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_integer_takes_the_fewest_bytes_under_its_tag() {
        assert_eq!(integer(INTEGER, 3), [0x02, 0x01, 0x03]);
        assert_eq!(integer(INTEGER, 128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(ENUMERATED, 49), [0x0a, 0x01, 0x31]);
        assert_eq!(integer(INTEGER, -1), [0x02, 0x01, 0xff]);
    }

    #[test]
    fn an_answer_larger_than_a_bind_response_is_refused_saying_whose() {
        let mut huge: &[u8] = &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff];
        let failure = read_element(&mut huge).expect_err("refused");
        assert!(
            failure.message.starts_with("the directory's answer: "),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("65536"), "{}", failure.message);
    }
}
