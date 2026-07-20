use crate::error::FormatError;

pub fn build_sd_jwt_vc_mock() -> Result<String, FormatError> {
    Ok("mock-sd-jwt".to_string())
}
