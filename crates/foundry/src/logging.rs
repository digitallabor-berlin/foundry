use crate::cli::LogFormat;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init(level: &str, format: LogFormat) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Human => {
            fmt().with_env_filter(filter).init();
        }
        LogFormat::Json => {
            fmt().json().with_env_filter(filter).init();
        }
    }
}