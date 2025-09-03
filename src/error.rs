/// Enum for different error
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// error raised when host is not allowed
    HostNotAllowed(String),
    /// error when passed forwarded header is invalid
    InvalidForwardedHeader,
    /// error when passed host header is invalid
    InvalidHostHeader,
    /// error when passed host header is missing
    MissingHostHeader,
    /// error when there is multiple host header
    MultipleHostHeader,
    /// error when uri is missing along with host header
    MissingAuthority,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::HostNotAllowed(host) => write!(f, "host {host} not allowed"),
            Self::InvalidForwardedHeader => write!(f, "invalid forwarded header"),
            Self::InvalidHostHeader => write!(f, "invalid host header"),
            Self::MissingHostHeader => write!(f, "missing host header"),
            Self::MultipleHostHeader => write!(f, "multiple host header"),
            Self::MissingAuthority => write!(f, "missing :authority pseudo header"),
        }
    }
}

impl std::error::Error for Error {}
