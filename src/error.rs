/// Enum for different error generated from crates
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// error raised when host is not allowed
    #[error("host {0} not allowed")]
    HostNotAllowed(String),
    /// error when passed forwarded header is invalid
    #[error("invalid forwarded header")]
    InvalidForwardedHeader,
    /// error when passed host header is invalid
    #[error("invalid host header")]
    InvalidHostHeader,
    /// error when passed host header is missing
    #[error("missing host header")]
    MissingHostHeader,
    /// error when there is multiple host header
    #[error("multiple host header")]
    MultipleHostHeader,
}
