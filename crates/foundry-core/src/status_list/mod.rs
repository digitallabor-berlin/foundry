//! Token Status List (IETF draft-ietf-oauth-status-list-14): bit-packed
//! status arrays, zlib compression, and signed Status List Tokens.

/// A Referenced Token's status (draft-ietf-oauth-status-list-14 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValue {
    Valid,
    Invalid,
    Suspended,
    ApplicationSpecific(u8),
}

impl StatusValue {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => StatusValue::Valid,
            0x01 => StatusValue::Invalid,
            0x02 => StatusValue::Suspended,
            other => StatusValue::ApplicationSpecific(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            StatusValue::Valid => 0x00,
            StatusValue::Invalid => 0x01,
            StatusValue::Suspended => 0x02,
            StatusValue::ApplicationSpecific(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_value_round_trips_known_values() {
        assert_eq!(StatusValue::from_u8(0x00), StatusValue::Valid);
        assert_eq!(StatusValue::from_u8(0x01), StatusValue::Invalid);
        assert_eq!(StatusValue::from_u8(0x02), StatusValue::Suspended);
        assert_eq!(StatusValue::Valid.to_u8(), 0x00);
        assert_eq!(StatusValue::Invalid.to_u8(), 0x01);
        assert_eq!(StatusValue::Suspended.to_u8(), 0x02);
    }

    #[test]
    fn status_value_unknown_is_application_specific() {
        assert_eq!(StatusValue::from_u8(0x03), StatusValue::ApplicationSpecific(3));
        assert_eq!(StatusValue::from_u8(0x0C), StatusValue::ApplicationSpecific(12));
        assert_eq!(StatusValue::ApplicationSpecific(7).to_u8(), 7);
    }
}