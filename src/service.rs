use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::{HeaderMap, Request, Response, Uri};
#[cfg(feature = "regex")]
use regex::Regex;
use tower::{BoxError, Layer, Service};
#[cfg(feature = "wildcard")]
use wildmatch::WildMatch;

use crate::error::Error;

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

/// Allowed hosts layer which implements tower layer trait and contains allowed
/// hosts which are used to resolve server hostname is valid or not
///
/// Hostname is resolved through the following, in order:
/// - `Forwarded` header (if `use_forwarded` is true. Default value is false)
/// - `X-Forwarded-Host` header (if `use_x_forwarded_host` is true. Default
///   value is false)
/// - `Host` header
///
/// All headers will get first host value for analyzing if any headers contains
/// multiple header value than subsequent value gets ignored and not used for
/// analyzing whether host is allowed or not
#[derive(Clone, Default)]
pub struct AllowedHostLayer {
    allowed_hosts: Vec<String>,
    #[cfg(feature = "wildcard")]
    allowed_hosts_wildcard: Vec<WildMatch>,
    #[cfg(feature = "regex")]
    allowed_hosts_regex: Vec<Regex>,
    use_forwarded: bool,
    use_x_forwarded_host: bool,
}

impl AllowedHostLayer {
    /// Extend allowed hosts list using normal string. To match host value
    /// should be same as given value
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::default().extend(["127.0.0.1"]);
    /// ```
    #[must_use]
    pub fn extend<I, T>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.allowed_hosts.extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Extend allowed hosts list using wildcard.
    /// - `?` matches exactly one occurrence of any character.
    /// - `*` matches arbitrary many (including zero) occurrences of any
    ///   character.
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::default().extend_wildcard(["*.example.com"]);
    /// ```
    #[must_use]
    #[cfg(feature = "wildcard")]
    pub fn extend_wildcard<I, T>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.allowed_hosts_wildcard
            .extend(hosts.into_iter().map(|h| WildMatch::new(&h.into())));
        self
    }

    /// Extend allowed hosts list using regex. Regex is check to verify if
    /// header is allowed or not
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default();
    /// let _ = layer.extend_regex([regex::Regex::new("^127.0.0.1$").unwrap()]);
    /// ```
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn extend_regex<I>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = Regex>,
    {
        self.allowed_hosts_regex
            .extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Set `use_forwarded` to provided value. If it is set to true than
    /// `Forwarded` header is used
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::default().set_use_forwarded(true);
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
    /// let _ = AllowedHostLayer::default().set_use_x_forwarded_host(true);
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

    fn is_host_allowed(&self, host: &Uri) -> bool {
        let is_allowed = self
            .allowed_hosts
            .iter()
            .any(|allowed_host| allowed_host == &host.to_string());

        #[cfg(feature = "wildcard")]
        let is_allowed = is_allowed
            || self
                .allowed_hosts_wildcard
                .iter()
                .any(|allowed_host_wildcard| allowed_host_wildcard.matches(&host.to_string()));

        #[cfg(feature = "regex")]
        let is_allowed = is_allowed
            || self
                .allowed_hosts_regex
                .iter()
                .any(|allowed_host_regex| allowed_host_regex.is_match(&host.to_string()));

        is_allowed
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

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let host = get_host(req.headers(), &self.layer);
        let host_allowed = host.clone().is_some_and(|h| self.layer.is_host_allowed(&h));
        // if there is any host value and that host value is allowed than add extension
        // to request
        if let Some(host_uri) = &host {
            if host_allowed {
                req.extensions_mut()
                    .insert(crate::extension::Host(host_uri.clone()));
            }
        }
        let response_future = self.inner.call(req);
        AllowedHostFuture {
            response_future,
            host,
            host_allowed,
        }
    }
}

/// Future for Allowed hosts
#[pin_project::pin_project]
pub struct AllowedHostFuture<F> {
    #[pin]
    response_future: F,
    #[pin]
    host: Option<Uri>,
    #[pin]
    host_allowed: bool,
}

impl<F, Response, E> Future for AllowedHostFuture<F>
where
    F: Future<Output = Result<Response, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        let Some(host) = &*project.host else {
            let err = Box::new(Error::FailedToResolveHost);
            return Poll::Ready(Err(err));
        };
        if !*project.host_allowed {
            #[cfg(feature = "tracing")]
            tracing::debug!("blocked host: {host}");
            let err = Box::new(Error::HostNotAllowed(host.to_string()));
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

fn get_host(headers: &HeaderMap, layer: &AllowedHostLayer) -> Option<Uri> {
    let host_str = get_host_str(headers, layer)?;
    let host = host_str.parse::<Uri>().ok()?;
    host.host()?;
    // if host contains path, scheme or query than return None for host since it is
    // not valid host header
    if !host.path().is_empty() || host.query().is_some() || host.scheme().is_some() {
        return None;
    }
    Some(host)
}

fn get_host_str(headers: &HeaderMap, layer: &AllowedHostLayer) -> Option<String> {
    // get first forwarded value for value for host
    if layer.use_forwarded {
        let forwarded_headers = headers.get_all(FORWARDED);
        for forwarded_header in forwarded_headers {
            let header_str = forwarded_header.to_str().ok()?;
            let splitted_headers = header_str.split(',');
            for splitted_header in splitted_headers {
                let (key, value) = splitted_header.split_once('=')?;
                if key.trim().to_ascii_lowercase() != "host" {
                    return Some(value.trim().trim_matches('"').to_string());
                }
            }
        }
    }

    // get first x forwarded host header for host
    if layer.use_x_forwarded_host {
        if let Some(host) = headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Some(host.to_string());
        }
    }

    // get host header value. This will return first host header
    headers
        .get(HOST)
        .and_then(|host| host.to_str().map(ToString::to_string).ok())
}
