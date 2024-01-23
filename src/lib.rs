//! Crate which provides allowed hosts layer for tower based service where all
//! non allowed hosts request are blocked
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::{HeaderMap, Request, Response, Uri};
#[cfg(feature = "regex")]
use regex::Regex;
use tower::{BoxError, Layer, Service};

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

/// Enum for different error
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// error when host is failed to resolve
    #[error("failed to resolve host")]
    FailedToResolveHost,
    /// error raised when host is not allowed
    #[error("{0} not allowed")]
    HostNotAllowed(String),
}

/// Allowed hosts layer which implements tower layer trait and contains allowed
/// hosts which are used to resolve server hostname is valid or not
///
/// Hostname is resolved through the following, in order:
/// - `Forwarded` header (if `use_forwarded` is true. Default value is false)
/// - `X-Forwarded-Host` header (if `use_x_forwarded_host` is true. Default
///   value is false)
/// - `Host` header
/// - request target / URI
#[derive(Clone, Default)]
pub struct AllowedHostLayer {
    allowed_hosts: Vec<String>,
    #[cfg(feature = "regex")]
    allowed_hosts_regex: Vec<Regex>,
    use_forwarded: bool,
    use_x_forwarded_host: bool,
}

impl AllowedHostLayer {
    /// Create new allowed hosts layer
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::new(["127.0.0.1"]);
    /// ```
    #[must_use]
    pub fn new<I, T>(allowed_hosts: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Create new allowed hosts layer with regex
    ///
    /// ```rust
    /// use regex::Regex;
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::new_regex(vec![Regex::new("^127.0.0.1$").unwrap()]);
    /// ```
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn new_regex<I>(allowed_hosts_regex: I) -> Self
    where
        I: IntoIterator<Item = Regex>,
    {
        Self {
            allowed_hosts_regex: allowed_hosts_regex.into_iter().collect(),
            ..Default::default()
        }
    }

    /// Extend allowed hosts list
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::default().extend_host("127.0.0.1");
    /// ```
    #[must_use]
    pub fn extend_host<T>(mut self, host: T) -> Self
    where
        T: Into<String>,
    {
        self.allowed_hosts.push(host.into());
        self
    }

    /// Extend allowed hosts regex list
    ///
    /// ```rust
    /// use regex::Regex;
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::new_regex(vec![Regex::new("^127.0.0.1$").unwrap()])
    ///     .extend_regex_host(Regex::new("^localhost$").unwrap());
    /// ```
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn extend_regex_host(mut self, regex: Regex) -> Self {
        self.allowed_hosts_regex.push(regex);
        self
    }

    /// Set `use_forwarded` to provided value. If it is set to true than
    /// `Forwarded` header is used
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::new(["127.0.0.1"]).set_use_forwarded(true);
    /// ```
    #[must_use]
    pub fn set_use_forwarded(mut self, use_forwarded: bool) -> Self {
        self.use_forwarded = use_forwarded;
        self
    }

    /// Set `use_x_forwarded_host` to provided value. If it is set to true than
    /// `X-Forwarded-Host` header is used
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::new(["127.0.0.1"]).set_use_x_forwarded_host(true);
    /// ```
    #[must_use]
    pub fn set_use_x_forwarded_host(mut self, use_x_forwarded_host: bool) -> Self {
        self.use_x_forwarded_host = use_x_forwarded_host;
        self
    }

    /// Get allowed hosts
    #[must_use]
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Get allowed hosts regex
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn allowed_hosts_regex(&self) -> &[Regex] {
        &self.allowed_hosts_regex
    }

    /// Get if `Forwarded` header is used to determine host
    #[must_use]
    pub fn use_forwarded(&self) -> bool {
        self.use_forwarded
    }

    /// Get if `X-Forwarded-Host` header is used to determine host
    #[must_use]
    pub fn use_x_forwarded_host(&self) -> bool {
        self.use_x_forwarded_host
    }

    fn is_domain_allowed(&self, host: &str) -> bool {
        let domain_match: bool = self
            .allowed_hosts
            .iter()
            .any(|allowed_host| allowed_host == host);
        #[cfg(feature = "regex")]
        let domain_match = domain_match
            || self
                .allowed_hosts_regex
                .iter()
                .any(|reg| reg.is_match(host));
        domain_match
    }
}

impl<S> Layer<S> for AllowedHostLayer {
    type Service = AllowedHost<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            layer: self.clone(),
        }
    }
}

/// Allowed hosts service
#[derive(Clone)]
pub struct AllowedHost<S> {
    inner: S,
    layer: AllowedHostLayer,
}
impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AllowedHost<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Into<BoxError>,
{
    type Error = BoxError;
    type Future = AllowedHostFuture<S::Future>;
    type Response = S::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let headers = req.headers().clone();
        let uri = req.uri().clone();
        let response_future = self.inner.call(req);
        AllowedHostFuture {
            response_future,
            headers,
            uri,
            layer: self.layer.clone(),
        }
    }
}

/// Future for Allowed hosts
#[pin_project::pin_project]
pub struct AllowedHostFuture<F> {
    #[pin]
    response_future: F,
    #[pin]
    headers: HeaderMap,
    #[pin]
    uri: Uri,
    #[pin]
    layer: AllowedHostLayer,
}

impl<F, Response, E> Future for AllowedHostFuture<F>
where
    F: Future<Output = Result<Response, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        let Some(host) = get_host(
            &project.headers,
            &project.uri,
            project.layer.use_forwarded,
            project.layer.use_x_forwarded_host,
        ) else {
            let err = Box::new(Error::FailedToResolveHost);
            return Poll::Ready(Err(err));
        };
        if !project.layer.is_domain_allowed(&host) {
            #[cfg(feature = "tracing")]
            tracing::debug!("blocked host: {host}");
            let err = Box::new(Error::HostNotAllowed(host));
            return Poll::Ready(Err(err));
        }
        #[cfg(feature = "tracing")]
        tracing::debug!("allowed host: {host}");

        match project.response_future.poll(cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn get_host(
    headers: &HeaderMap,
    uri: &Uri,
    use_forwarded: bool,
    use_x_forwarded_host: bool,
) -> Option<String> {
    if use_forwarded {
        if let Some(host) = get_forwarded_hosts(headers) {
            return Some(host.to_string());
        }
    }

    if use_x_forwarded_host {
        if let Some(host) = headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Some(host.to_string());
        }
    }

    if let Some(host) = headers.get(HOST).and_then(|host| host.to_str().ok()) {
        return Some(host.to_string());
    }

    if let Some(host) = uri.host() {
        return Some(host.to_string());
    }

    None
}

fn get_forwarded_hosts(headers: &HeaderMap) -> Option<&str> {
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;
    let first_value = forwarded_values.split(',').next()?;
    let forwarded_host = first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    });
    forwarded_host
}
