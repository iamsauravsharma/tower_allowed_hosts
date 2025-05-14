use std::collections::HashMap;
use std::convert::Into;
use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::{HeaderMap, Request};
use tower_layer::Layer;
use tower_service::Service;

use crate::Host;
use crate::error::Error;
use crate::matcher::Matcher;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A layer that validates and allows incoming requests based on their host.
///
/// This layer checks the hostname of incoming requests against a list of
/// allowed hosts. The hostname is resolved using the `Forwarded` header if
/// `forwarded_token_value` is present and then `Host` header.
///
/// If `forwarded_token_value` is specified, the layer will use the `Forwarded`
/// header to extract the hostname when the specified token-value pair is
/// present in the header. For example, if `forwarded_token_value` is set to
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
/// If `forwarded_token_value` is set to `("signature", "random_value")`, the
/// layer will extract the host `127.0.0.1` and ignore the other host values.
///
/// # Examples
///
/// ```rust
/// let layer = tower_allowed_hosts::AllowedHostLayer::<_, String>::default()
///     .extend_hosts(vec!["example.com"]);
/// ```
#[derive(Clone)]
pub struct AllowedHostLayer<H, F> {
    hosts: Vec<H>,
    forwarded_token_values: Vec<(String, F)>,
}

impl<H, F> Default for AllowedHostLayer<H, F> {
    fn default() -> Self {
        Self {
            hosts: vec![],
            forwarded_token_values: vec![],
        }
    }
}

impl<H, F> AllowedHostLayer<H, F>
where
    H: Matcher,
    F: Matcher,
{
    /// Add a host to allowed hosts layer
    ///
    /// # Example
    ///
    /// ```rust
    /// let layer =
    ///     tower_allowed_hosts::AllowedHostLayer::<_, String>::default().push_host("example.com");
    /// ```
    #[must_use]
    pub fn push_host(mut self, matcher: H) -> Self {
        self.hosts.push(matcher);
        self
    }

    /// Extend allowed hosts layer with provided hosts
    ///
    /// # Example
    ///
    /// ```rust
    /// let layer = tower_allowed_hosts::AllowedHostLayer::<_, String>::default()
    ///     .extend_hosts(vec!["example.com"]);
    /// ```
    #[must_use]
    pub fn extend_hosts<I>(mut self, matchers: I) -> Self
    where
        I: IntoIterator<Item = H>,
    {
        self.hosts.extend(matchers);
        self
    }

    /// Add a token-value pair for matching in the `Forwarded` header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let layer = tower_allowed_hosts::AllowedHostLayer::default()
    ///     .push_host("example.com")
    ///     .push_forwarded_token_value(("by", "random"));
    /// ```
    ///
    /// In above example only forwarded host name is extracted when host
    /// forwarded header is present and `by` value matches as `random` as well
    #[must_use]
    pub fn push_forwarded_token_value<T, S>(mut self, matcher: T) -> Self
    where
        T: Into<(S, F)>,
        S: Into<String>,
    {
        let (token, val) = matcher.into();
        self.forwarded_token_values
            .push((Into::<String>::into(token).to_lowercase(), val));
        self
    }

    /// Extend allowed hosts layer with provided forwarded header token values
    ///
    /// # Example
    ///
    /// ```rust
    /// let layer = tower_allowed_hosts::AllowedHostLayer::default()
    ///     .push_host("example.com")
    ///     .extend_forwarded_token_values([["signature", "random"]]);
    /// ```
    #[must_use]
    pub fn extend_forwarded_token_values<I, T, S>(mut self, matchers: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<(S, F)>,
        S: Into<String>,
    {
        self.forwarded_token_values.extend(
            matchers
                .into_iter()
                .map(Into::into)
                .map(|(t, v)| (Into::<String>::into(t).to_ascii_lowercase(), v)),
        );
        self
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
    F: Matcher,
{
    type Error = BoxError;
    type Future = AllowedHostFuture<S::Future>;
    type Response = S::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match get_host(req.headers(), &self.layer.forwarded_token_values) {
            Ok(host_val) => {
                let host_allowed = self
                    .layer
                    .hosts
                    .iter()
                    .any(|host_matcher| host_matcher.matches_value(host_val.as_str()));

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

/// Future for AllowedHost service.
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
fn get_host<F>(headers: &HeaderMap, forwarded_token_value: &[(String, F)]) -> Result<String, Error>
where
    F: Matcher,
{
    let host_header = match extract_from_forwarded(headers, forwarded_token_value)? {
        Some(host) => host,
        None => extract_from_host(headers)?,
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
    let host_str = String::from_utf8(first_host.as_bytes().to_vec())
        .map_err(|_| Error::InvalidHostHeader)?
        .to_string();
    Ok(host_str)
}

/// Extract host from `Forwarded` headers only extract host header from allowed
/// forwarded by values else return None
fn extract_from_forwarded<F>(
    headers: &HeaderMap,
    forwarded_token_values: &[(String, F)],
) -> Result<Option<String>, Error>
where
    F: Matcher,
{
    if !forwarded_token_values.is_empty() {
        for forwarded_header in headers.get_all(FORWARDED) {
            let header_str = String::from_utf8(forwarded_header.as_bytes().to_vec())
                .map_err(|_| Error::InvalidForwardedHeader)?;
            for header in header_str.split(',') {
                let mut forwarded_host_token = None;
                let mut token_value_map = HashMap::new();
                for part in header.split(';') {
                    if let Some((key, value)) = part.split_once('=') {
                        let key = key.to_lowercase();
                        let value = value.to_string();

                        if key == "host" {
                            forwarded_host_token = Some(value);
                        } else {
                            token_value_map.insert(key, value);
                        }
                    }
                }
                if forwarded_host_token.is_some()
                    && forwarded_token_values.iter().any(|(token, matcher)| {
                        token_value_map
                            .get(token)
                            .is_some_and(|token_value| matcher.matches_value(token_value))
                    })
                {
                    return Ok(forwarded_host_token);
                }
            }
        }
    }
    Ok(None)
}
