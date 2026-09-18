//! The few lines of X.690 basic encoding a bind needs: a one-byte tag, a
//! length in short or long form, the contents.
//!
//! The estate's fuller BER lives in the transport capability, and the
//! manifest declares no dependency from this technology on it, so what a
//! `BindRequest` and a `BindResponse` take is written here: definite
//! lengths, small integers, and one element read off a stream.

use authenticate::AuthenticateError;
use std::io::Read;

/// The universal tag of an INTEGER: a message id, the protocol version.
pub const INTEGER: u8 = 0x02;
/// The universal tag of an OCTET STRING: a DN, a diagnostic message.
pub const OCTET_STRING: u8 = 0x04;
/// The universal tag of an ENUMERATED: a result code.
pub const ENUMERATED: u8 = 0x0a;
/// The universal tag of a SEQUENCE: the `LDAPMessage` envelope.
pub const SEQUENCE: u8 = 0x30;

/// The largest element this reads off a stream. A bind response is a few
/// dozen bytes; a directory that sends more than this is not answering a
/// bind.
pub const LARGEST: usize = 64 * 1024;

/// One element: `tag`, the definite length of `contents`, `contents`.
#[must_use]
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let bytes = contents.len().to_be_bytes();
    let significant: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    match significant.as_slice() {
        [] => out.push(0),
        [short] if *short < 0x80 => out.push(*short),
        long => {
            // A usize is at most eight bytes wide, so the count fits.
            out.push(0x80 | u8::try_from(long.len()).unwrap_or(8));
            out.extend_from_slice(long);
        }
    }
    out.extend_from_slice(contents);
    out
}

/// A two's-complement integer in the fewest bytes, under `tag`.
#[must_use]
pub fn integer(tag: u8, value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let redundant = (bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    tlv(tag, &bytes[start..])
}

/// The integer in `contents`.
///
/// # Errors
///
/// Empty, or wider than eight bytes.
pub fn read_integer(contents: &[u8]) -> Result<i64, AuthenticateError> {
    if contents.is_empty() || contents.len() > 8 {
        return Err(AuthenticateError::new(format!(
            "a BER integer of {} bytes is not one this node reads",
            contents.len()
        )));
    }
    let negative = contents[0] & 0x80 != 0;
    let mut value: i64 = if negative { -1 } else { 0 };
    for byte in contents {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

/// The definite length that follows a tag: how many bytes it says, and how
/// many bytes saying so took.
fn length(bytes: &[u8]) -> Result<(usize, usize), AuthenticateError> {
    let first = *bytes
        .first()
        .ok_or_else(|| AuthenticateError::new("a BER element ends before its length"))?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > 4 || bytes.len() < 1 + width {
        return Err(AuthenticateError::new(
            "a BER length is indefinite, wider than four bytes, or cut short",
        ));
    }
    let said = bytes[1..=width]
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
    Ok((said, 1 + width))
}

/// The first element of `bytes`: its tag, its contents, and what follows.
///
/// # Errors
///
/// The element is cut short or its length is not one this node reads.
pub fn read(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), AuthenticateError> {
    let (tag, after_tag) = bytes
        .split_first()
        .ok_or_else(|| AuthenticateError::new("a BER element was expected and there is none"))?;
    let (said, took) = length(after_tag)?;
    let rest = &after_tag[took..];
    if rest.len() < said {
        return Err(AuthenticateError::new(format!(
            "a BER element says {said} bytes and {} follow",
            rest.len()
        )));
    }
    let (contents, rest) = rest.split_at(said);
    Ok((*tag, contents, rest))
}

/// The first element of `bytes`, which must carry `tag`.
///
/// # Errors
///
/// As [`read`], or the element carries another tag.
pub fn expect(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8]), AuthenticateError> {
    let (found, contents, rest) = read(bytes)?;
    if found != tag {
        return Err(AuthenticateError::new(format!(
            "a BER element tagged {tag:#04x} was expected and {found:#04x} arrived"
        )));
    }
    Ok((contents, rest))
}

/// One whole element off a stream, tag and length included.
///
/// # Errors
///
/// The stream ends or fails first, or the element is larger than
/// [`LARGEST`].
pub fn read_element(stream: &mut impl Read) -> Result<Vec<u8>, AuthenticateError> {
    let failed = |failure: std::io::Error| {
        AuthenticateError::new(format!("the directory's answer was cut short: {failure}"))
    };
    let mut element = vec![0u8; 2];
    stream.read_exact(&mut element).map_err(failed)?;
    if element[1] >= 0x80 {
        let width = usize::from(element[1] & 0x7f);
        let mut more = vec![0u8; width.min(4)];
        stream.read_exact(&mut more).map_err(failed)?;
        element.extend_from_slice(&more);
    }
    let (said, _) = length(&element[1..])?;
    if said > LARGEST {
        return Err(AuthenticateError::new(format!(
            "the directory's answer says {said} bytes, more than a bind response is"
        )));
    }
    let header = element.len();
    element.resize(header + said, 0);
    stream.read_exact(&mut element[header..]).map_err(failed)?;
    Ok(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_is_short_below_128_and_long_from_there() {
        assert_eq!(tlv(OCTET_STRING, b"hi"), [0x04, 0x02, b'h', b'i']);
        let long = tlv(OCTET_STRING, &[7u8; 300]);
        assert_eq!(&long[..4], [0x04, 0x82, 0x01, 0x2c]);
        let (tag, contents, rest) = read(&long).expect("read");
        assert_eq!((tag, contents.len(), rest.len()), (OCTET_STRING, 300, 0));
    }

    #[test]
    fn an_integer_takes_the_fewest_bytes_and_reads_back() {
        assert_eq!(integer(INTEGER, 3), [0x02, 0x01, 0x03]);
        assert_eq!(integer(INTEGER, 128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(ENUMERATED, 49), [0x0a, 0x01, 0x31]);
        assert_eq!(integer(INTEGER, -1), [0x02, 0x01, 0xff]);
        for value in [
            0,
            1,
            127,
            128,
            255,
            256,
            65_535,
            -1,
            -129,
            i64::MAX,
            i64::MIN,
        ] {
            let encoded = integer(INTEGER, value);
            let (contents, _) = expect(&encoded, INTEGER).expect("read");
            assert_eq!(read_integer(contents).expect("an integer"), value);
        }
    }

    #[test]
    fn what_is_cut_short_indefinite_or_mistagged_is_refused_saying_so() {
        let refused = |bytes: &[u8]| read(bytes).expect_err("refused").message;
        assert!(refused(&[]).contains("there is none"));
        assert!(refused(&[0x04]).contains("before its length"));
        assert!(refused(&[0x04, 0x05, 1, 2]).contains("says 5 bytes and 2 follow"));
        assert!(refused(&[0x30, 0x80, 0, 0]).contains("indefinite"));
        let mistagged = expect(&[0x04, 0x00], INTEGER).expect_err("refused");
        assert!(mistagged.message.contains("0x02"), "{}", mistagged.message);
        assert!(read_integer(&[]).is_err());
    }

    #[test]
    fn one_element_is_read_off_a_stream_and_the_next_is_left() {
        let mut wire = tlv(SEQUENCE, &[9u8; 200]);
        wire.extend_from_slice(&tlv(OCTET_STRING, b"next"));
        let mut stream = wire.as_slice();
        let first = read_element(&mut stream).expect("read");
        assert_eq!(first, tlv(SEQUENCE, &[9u8; 200]));
        assert_eq!(
            read_element(&mut stream).expect("read"),
            tlv(OCTET_STRING, b"next")
        );
        assert!(read_element(&mut stream).is_err());

        let mut huge: &[u8] = &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff];
        let failure = read_element(&mut huge).expect_err("refused");
        assert!(
            failure.message.contains("more than a bind"),
            "{}",
            failure.message
        );
    }
}
