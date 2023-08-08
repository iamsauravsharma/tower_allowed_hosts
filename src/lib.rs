//! Crate which provides allowed hosts layer for tower based service where all
//! non allowed hosts request are blocked
#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
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
pub enum Error {
    /// error when host is failed to resolve
    #[error("failed to resolve host for server")]
    FailedToResolveHost,
    /// error raised when host is not allowed
    #[error("host not allowed for server")]
    HostNotAllowed,
}

/// Allowed hosts layer which implements tower layer trait and contains allowed
/// hosts which are used to resolve server hostname is valid or not
///
/// Server hostname is resolved through the following, in order:
/// - `Forwarded` header
/// - `X-Forwarded-Host` header
/// - `Host` header
/// - request target / URI
#[derive(Clone)]
pub struct AllowedHostLayer {
    allowed_hosts: Vec<String>,
    #[cfg(feature = "regex")]
    allowed_hosts_regex: Vec<Regex>,
}

impl AllowedHostLayer {
    /// Create new allowed hosts layer
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            allowed_hosts: allowed_hosts.to_vec(),
            #[cfg(feature = "regex")]
            allowed_hosts_regex: vec![],
        }
    }

    /// Create new allowed hosts layer with regex
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn new_regex(allowed_hosts_regex: &[Regex]) -> Self {
        Self {
            allowed_hosts: vec![],
            allowed_hosts_regex: allowed_hosts_regex.to_vec(),
        }
    }

    /// Create new allowed hosts layer with regex
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn new_both(allowed_hosts: &[String], allowed_hosts_regex: &[Regex]) -> Self {
        Self {
            allowed_hosts: allowed_hosts.to_vec(),
            allowed_hosts_regex: allowed_hosts_regex.to_vec(),
        }
    }

    /// Extend allowed hosts
    #[must_use]
    pub fn with_host(mut self, regex: String) -> Self {
        self.allowed_hosts.push(regex);
        self
    }

    /// Extend allowed hosts with regex
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn with_regex_host(mut self, regex: Regex) -> Self {
        self.allowed_hosts_regex.push(regex);
        self
    }
}

impl<S> Layer<S> for AllowedHostLayer {
    type Service = AllowedHost<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            allowed_hosts: self.allowed_hosts.clone(),
            #[cfg(feature = "regex")]
            allowed_hosts_regex: self.allowed_hosts_regex.clone(),
            inner,
        }
    }
}

/// Allowed hosts service
#[derive(Clone)]
pub struct AllowedHost<S> {
    inner: S,
    allowed_hosts: Vec<String>,
    #[cfg(feature = "regex")]
    allowed_hosts_regex: Vec<Regex>,
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
            allowed_hosts: self.allowed_hosts.clone(),
            #[cfg(feature = "regex")]
            allowed_hosts_regex: self.allowed_hosts_regex.clone(),
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
    allowed_hosts: Vec<String>,
    #[pin]
    #[cfg(feature = "regex")]
    allowed_hosts_regex: Vec<Regex>,
}

impl<F, Response, E> Future for AllowedHostFuture<F>
where
    F: Future<Output = Result<Response, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        let Some(host) = get_host(&project.headers, &project.uri) else {
            let err = Box::new(Error::FailedToResolveHost);
            return Poll::Ready(Err(err));
        };
        let domain_match: bool = project
            .allowed_hosts
            .iter()
            .any(|allowed_host| allowed_host == &host);
        #[cfg(feature = "regex")]
        let domain_match = domain_match
            || project
                .allowed_hosts_regex
                .iter()
                .any(|reg| reg.is_match(&host));

        if domain_match {
            let err = Box::new(Error::HostNotAllowed);
            return Poll::Ready(Err(err));
        }
        match project.response_future.poll(cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn get_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    if let Some(host) = get_forwarded_hosts(headers) {
        return Some(host.to_string());
    }

    if let Some(host) = headers
        .get(X_FORWARDED_HOST_HEADER_KEY)
        .and_then(|host| host.to_str().ok())
    {
        return Some(host.to_string());
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
