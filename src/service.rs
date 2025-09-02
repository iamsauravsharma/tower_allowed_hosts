use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::{HeaderMap, Request, Version};
use tower_layer::Layer;
use tower_service::Service;

use crate::Host;
use crate::error::Error;
use crate::matcher::{KeyValueMatcher, Matcher};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A layer that validates and allows incoming requests based on their host.
///
/// This layer checks the hostname of incoming requests against allowed hosts.
/// The hostname is resolved using the `Forwarded` header if `forwarded_matcher`
/// is present and then `Host` header. For HTTP version 2 and 3 along with
/// `HOST` header `:authority` pseudo-header is also used to resolve host of
/// server
///
/// If `forwarded_matcher` is specified, the layer will use the `Forwarded`
/// header to extract the hostname when the specified token-value pair is
/// present in the header. For example, if `forwarded_matcher` is set to
/// `("signature", "random_value")`, the layer will parse the `Forwarded` header
/// and extract the hostname only if the `signature` token matches the value
/// `random_value`. If the token-value pair is not found, the layer will fall
/// back to using the `Host` header.
///
///  # Example of `Forwarded` Header Parsing
///
/// Given the `Forwarded` header:
/// ```text
/// for=10.0.10.11;by=10.1.12.11;host=127.0.0.1;signature=random_value,
/// for=10.0.10.11;by=10.1.12.11;host=127.0.0.3
/// ```
/// If `forwarded_matcher` is set to `("signature", "random_value")`, the
/// layer will extract the host `127.0.0.1` and ignore the other host values.
///
/// # Examples
///
/// ```rust
/// let layer = tower_allowed_hosts::AllowedHostLayer::new("example.com");
/// ```
#[derive(Clone)]
pub struct AllowedHostLayer<H, F> {
    host_matcher: H,
    forwarded_matcher: F,
}

impl<H> AllowedHostLayer<H, ()> {
    /// Create new allowed host layer with provided host matcher
    ///
    /// # Example
    /// ```
    /// let layer = tower_allowed_hosts::AllowedHostLayer::new("example.com");
    /// ```
    pub fn new(host_matcher: H) -> Self {
        Self {
            host_matcher,
            forwarded_matcher: (),
        }
    }
}

impl<H> AllowedHostLayer<H, ()> {
    /// Extend a host matcher with provided forwarded matcher
    ///
    ///
    /// # Example
    /// ```
    /// let layer = tower_allowed_hosts::AllowedHostLayer::new("example.com")
    ///     .with_forwarded_matcher(("by", "example.org"));
    /// ```
    pub fn with_forwarded_matcher<F>(self, forwarded_matcher: F) -> AllowedHostLayer<H, F>
    where
        F: KeyValueMatcher,
    {
        AllowedHostLayer {
            host_matcher: self.host_matcher,
            forwarded_matcher,
        }
    }
}

impl<H, F, S> Layer<S> for AllowedHostLayer<H, F>
where
    H: Clone,
    F: Clone,
{
    type Service = AllowedHost<H, F, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            layer: self.clone(),
        }
    }
}

/// Allowed hosts service that wraps the inner service and validates the request
/// host.
#[derive(Clone)]
pub struct AllowedHost<H, F, S> {
    inner: S,
    layer: AllowedHostLayer<H, F>,
}

impl<H, F, S, ReqBody> Service<Request<ReqBody>> for AllowedHost<H, F, S>
where
    S: Service<Request<ReqBody>>,
    S::Error: Into<BoxError>,
    H: Matcher,
    F: KeyValueMatcher,
{
    type Error = BoxError;
    type Future = AllowedHostFuture<S::Future>;
    type Response = S::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match get_host(&req, &self.layer.forwarded_matcher) {
            Ok(host_val) => {
                let host_allowed = self.layer.host_matcher.matches_value(host_val.as_str());

                if host_allowed {
                    req.extensions_mut().insert(Host(host_val.clone()));
                }

                Self::Future {
                    response_future: self.inner.call(req),
                    host: Ok(host_val),
                    host_allowed,
                }
            }
            Err(err) => {
                Self::Future {
                    response_future: self.inner.call(req),
                    host: Err(err),
                    host_allowed: false,
                }
            }
        }
    }
}

/// Future for `AllowedHost` service.
#[pin_project::pin_project]
pub struct AllowedHostFuture<F> {
    #[pin]
    response_future: F,
    host: Result<String, Error>,
    host_allowed: bool,
}

impl<F, Response, E> Future for AllowedHostFuture<F>
where
    F: Future<Output = Result<Response, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match (&this.host, &this.host_allowed) {
            (Ok(allowed_host), true) => {
                match this.response_future.poll(cx) {
                    Poll::Ready(result) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("allowed host: {}", allowed_host);
                        Poll::Ready(result.map_err(Into::into))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            (Ok(blocked_host), false) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("blocked host: {}", blocked_host);
                Poll::Ready(Err(
                    Box::new(Error::HostNotAllowed(blocked_host.clone())).into()
                ))
            }
            (Err(err), _) => Poll::Ready(Err(Box::new(err.clone()).into())),
        }
    }
}

/// Extract the host from the request headers based on the layer
/// configuration.
fn get_host<F, ReqBody>(req: &Request<ReqBody>, forwarded_matcher: &F) -> Result<String, Error>
where
    F: KeyValueMatcher,
{
    let headers = req.headers();
    let host_header = match extract_from_forwarded(headers, forwarded_matcher)? {
        Some(forwarded_host) => forwarded_host,
        None => {
            match extract_from_host(headers) {
                Ok(host) => host,
                Err(err) => {
                    if [Version::HTTP_2, Version::HTTP_3].contains(&req.version()) {
                        req.uri()
                            .authority()
                            .map(ToString::to_string)
                            .ok_or(Error::MissingAuthority)?
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    };
    Ok(host_header)
}

/// Extract host from `Host` headers.
fn extract_from_host(headers: &HeaderMap) -> Result<String, Error> {
    let mut host_headers = headers.get_all(HOST).iter();
    let first_host = host_headers.next().ok_or(Error::MissingHostHeader)?;
    if host_headers.next().is_some() {
        return Err(Error::MultipleHostHeader);
    }
    let host_str = first_host
        .to_str()
        .map_err(|_| Error::InvalidHostHeader)?
        .trim()
        .trim_matches('"')
        .to_string();
    Ok(host_str)
}

/// Extract host from `Forwarded` headers only extract host header from allowed
/// forwarded by values else return None
fn extract_from_forwarded<F>(
    headers: &HeaderMap,
    forwarded_matcher: &F,
) -> Result<Option<String>, Error>
where
    F: KeyValueMatcher,
{
    for forwarded_header in headers.get_all(FORWARDED) {
        let header_str = String::from_utf8(forwarded_header.as_bytes().to_vec())
            .map_err(|_| Error::InvalidForwardedHeader)?;
        for header_entry in header_str.split(',') {
            let (host_value, token_present) = parse_forwarded_entry(header_entry)?;

            if let Some(host) = host_value
                && forwarded_matcher.matches_key_value(&token_present)
            {
                return Ok(Some(host));
            }
        }
    }
    Ok(None)
}

/// Parse a single Forwarded header entry and extract host + token presence
fn parse_forwarded_entry(entry: &str) -> Result<(Option<String>, HashMap<String, String>), Error> {
    let mut host_value = None;
    let mut token_map = HashMap::new();

    for part in entry.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (key, value) = part.split_once('=').ok_or(Error::InvalidForwardedHeader)?;

        let key = key.trim().to_lowercase();
        let value = value.trim().trim_matches('"').to_string();

        if key.as_str() == "host" {
            host_value = Some(value.clone());
        }
        token_map.insert(key, value);
    }

    Ok((host_value, token_map))
}
