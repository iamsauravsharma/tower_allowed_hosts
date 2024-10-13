use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::{HeaderMap, Request};
use tower_layer::Layer;
use tower_service::Service;

use crate::error::Error;
use crate::matcher::Matcher;
use crate::Host;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Allowed hosts layer to check if the provided host is valid.
///
/// The hostname is resolved through `Forwarded` header and `Host` header
///
/// If `allowed_forwarded_token_value` is non empty than host header are
/// obtained from such forwarded value which have provided token
#[derive(Clone)]
pub struct AllowedHostLayer<H, F> {
    allowed_hosts: Vec<H>,
    allowed_forwarded_token_value: Vec<(String, F)>,
}

impl<H, F> Default for AllowedHostLayer<H, F> {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![],
            allowed_forwarded_token_value: vec![],
        }
    }
}

impl<H, F> AllowedHostLayer<H, F>
where
    H: Matcher,
    F: Matcher,
{
    /// Add a matcher to allowed hosts layer
    #[must_use]
    pub fn push_allowed_hosts(mut self, matcher: H) -> Self {
        self.allowed_hosts.push(matcher);
        self
    }

    /// Extend allowed hosts layer with provided matchers
    #[must_use]
    pub fn extend_allowed_hosts<I>(mut self, matchers: I) -> Self
    where
        I: IntoIterator<Item = H>,
    {
        self.allowed_hosts.extend(matchers);
        self
    }

    /// Add a matcher to allowed hosts layer
    #[must_use]
    pub fn push_allowed_forwarded_token_value(mut self, matcher: (String, F)) -> Self {
        self.allowed_forwarded_token_value.push(matcher);
        self
    }

    /// Extend allowed hosts layer with provided matchers
    #[must_use]
    pub fn extend_allowed_forwarded_token_value<I>(mut self, matchers: I) -> Self
    where
        I: IntoIterator<Item = (String, F)>,
    {
        self.allowed_forwarded_token_value.extend(matchers);
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
        match get_host(req.headers(), &self.layer.allowed_forwarded_token_value) {
            Ok(host_val) => {
                let host_allowed = self
                    .layer
                    .allowed_hosts
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
        let host = self.host.clone();
        let this = self.project();

        match (host, &this.host_allowed) {
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
                Poll::Ready(Err(Box::new(Error::HostNotAllowed(blocked_host)).into()))
            }
            (Err(err), _) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("{}", err);
                Poll::Ready(Err(Box::new(err).into()))
            }
        }
    }
}

/// Extract the host from the request headers based on the layer
/// configuration.
fn get_host<F>(
    headers: &HeaderMap,
    allowed_forwarded_token_value: &[(String, F)],
) -> Result<String, Error>
where
    F: Matcher,
{
    let host_header = match extract_from_forwarded(headers, allowed_forwarded_token_value)? {
        Some(host) => host,
        None => extract_from_host(headers)?,
    };
    Ok(host_header)
}

/// Extract host from Host headers.
fn extract_from_host(headers: &HeaderMap) -> Result<String, Error> {
    let mut host_headers = headers.get_all(HOST).iter();
    let first_host = host_headers.next().ok_or(Error::MissingHostHeader)?;
    if host_headers.next().is_some() {
        return Err(Error::MultipleHostHeader);
    }
    let host_str = first_host
        .to_str()
        .map_err(|_| Error::InvalidHostHeader)?
        .to_string();
    Ok(host_str)
}

/// Extract host from Forwarded headers only extract host header from allowed
/// forwarded by values else return None
fn extract_from_forwarded<F>(
    headers: &HeaderMap,
    allowed_forwarded_token_value: &[(String, F)],
) -> Result<Option<String>, Error>
where
    F: Matcher,
{
    if !allowed_forwarded_token_value.is_empty() {
        for forwarded_header in headers.get_all(FORWARDED) {
            let header_str = forwarded_header
                .to_str()
                .map_err(|_| Error::InvalidForwardedHeader)?;
            for header in header_str.split(',') {
                let mut forwarded_token_value = HashMap::new();
                for part in header.split(';') {
                    if let Some((key, value)) = part.split_once('=') {
                        forwarded_token_value.insert(key.to_string(), value.to_string());
                    }
                }
                if let Some(host_value) = forwarded_token_value.get("host") {
                    if allowed_forwarded_token_value.iter().any(
                        |(allowed_forwarded_token, allowed_forwarded_value)| {
                            if let Some(token_value) =
                                forwarded_token_value.get(allowed_forwarded_token)
                            {
                                allowed_forwarded_value.matches_value(token_value)
                            } else {
                                false
                            }
                        },
                    ) {
                        return Ok(Some(host_value.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}
