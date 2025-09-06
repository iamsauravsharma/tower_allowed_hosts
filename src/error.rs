/// Enum for different error
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// error raised when host is not allowed
    HostNotAllowed(String),
    /// error when passed forwarded header is invalid
    InvalidForwardedHeader,
    /// error when passed host header is invalid
    InvalidHost,
    /// error when passed host header is missing
    MissingHost,
    /// error when there is multiple host header
    MultipleHostHeader,
    /// error when uri is missing along with host header
    MissingAuthority,
    /// error raised when :authority value and host header mismatch
    MismatchAuthorityHost,
    /// error raised for future http which may not be supported
    UnsupportedHttpVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::HostNotAllowed(host) => write!(f, "host {host} not allowed"),
            Self::InvalidForwardedHeader => write!(f, "invalid forwarded header"),
            Self::InvalidHost => write!(f, "invalid host"),
            Self::MissingHost => write!(f, "missing host"),
            Self::MultipleHostHeader => write!(f, "multiple host header"),
            Self::MissingAuthority => write!(f, "missing :authority pseudo header"),
            Self::MismatchAuthorityHost => {
                write!(f, ":authority pseudo header and host header is mismatched")
            }
            Self::UnsupportedHttpVersion => {
                write!(f, "unsupported http version")
            }
        }
    }
}

impl std::error::Error for Error {}
