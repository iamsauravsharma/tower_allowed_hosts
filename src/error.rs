/// Enum for different error
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// error when host is failed to resolve
    #[error("failed to resolve host")]
    FailedToResolveHost,
    /// error raised when host is not allowed
    #[error("host not allowed")]
    HostNotAllowed(String),
}
