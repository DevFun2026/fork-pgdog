use std::str::from_utf8;
use std::str::from_utf8_unchecked;

use super::code;
use super::prelude::*;

/// NotificationResponse (B).
#[derive(Debug, Clone)]
pub(crate) struct NotificationResponse {
    payload: Bytes,
    channel_len: usize,
    // Parsed off the wire for correctness; no getter needed yet.
    #[allow(dead_code)]
    pid: i32,
}

impl NotificationResponse {
    /// Get the name of the notification channel.
    pub(crate) fn channel(&self) -> &str {
        let start = 1 + 4 + 4;
        let end = start + self.channel_len - 1;

        // SAFETY: FromBytes checks framing and validates this exact channel slice as UTF-8.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { from_utf8_unchecked(&self.payload[start..end]) }
    }
}

impl FromBytes for NotificationResponse {
    fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        if bytes.len() < 11 || bytes.last() != Some(&0) {
            return Err(Error::UnexpectedPayload);
        }
        if i32::from_be_bytes(bytes[1..5].try_into()?) as usize != bytes.len() - 1 {
            return Err(Error::UnexpectedPayload);
        }
        let payload = bytes.clone();

        code!(bytes, 'A');
        let _len = bytes.get_i32();

        let pid = bytes.get_i32();
        let channel_len = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Error::UnexpectedPayload)?
            + 1;
        if channel_len >= bytes.len() {
            return Err(Error::UnexpectedPayload);
        }
        from_utf8(&bytes[..channel_len - 1])?;
        bytes.advance(channel_len);
        from_utf8(&bytes[..bytes.len() - 1])?;

        Ok(Self {
            channel_len,
            pid,
            payload,
        })
    }
}

impl ToBytes for NotificationResponse {
    fn to_bytes(&self) -> Bytes {
        self.payload.clone()
    }
}

impl Protocol for NotificationResponse {
    fn code(&self) -> char {
        'A'
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::BufMut;

    use crate::net::{FromBytes, Payload};

    impl NotificationResponse {
        /// Get message payload.
        pub(crate) fn payload(&self) -> &str {
            let start = 1 + 4 + 4 + self.channel_len;
            // SAFETY: FromBytes checks framing and validates this exact payload slice as UTF-8.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { from_utf8_unchecked(&self.payload[start..self.payload.len() - 1]) }
        }
    }

    #[test]
    fn malformed_frames_return_errors() {
        let valid = Bytes::from_static(b"A\0\0\0\x10\0\0\0\x01chan\0hi\0");
        assert!(NotificationResponse::from_bytes(valid.clone()).is_ok());
        for end in 0..valid.len() {
            assert!(
                NotificationResponse::from_bytes(valid.slice(..end)).is_err(),
                "prefix {end}"
            );
        }
        let mut missing_nul = valid.to_vec();
        *missing_nul.last_mut().unwrap() = b'x';
        assert!(NotificationResponse::from_bytes(missing_nul.into()).is_err());
        let mut invalid_utf8 = valid.to_vec();
        let len = invalid_utf8.len();
        invalid_utf8[len - 2] = 0xff;
        assert!(NotificationResponse::from_bytes(invalid_utf8.into()).is_err());
    }

    #[test]
    fn test_notification_response() {
        let mut bytes = Payload::named('A');
        bytes.put_i32(1234); // pid
        bytes.put_string("channel_name");
        bytes.put_string("payload");

        let payload = bytes.freeze();
        let notification = NotificationResponse::from_bytes(payload).unwrap();
        assert_eq!(notification.channel(), "channel_name");
        assert_eq!(notification.payload(), "payload");
    }
}
