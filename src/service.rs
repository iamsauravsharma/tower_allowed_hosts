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
use crate::Host;

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

/// Allowed hosts layer to check if provided host is valid or not
///
/// Hostname is resolved through the following, in order:
/// - `Forwarded` header (if `use_forwarded` is true. Default value is false)
/// - `X-Forwarded-Host` header (if `use_x_forwarded_host` is true. Default
///   value is false)
/// - `Host` header
///
/// Determined host are always lowercase so use lowercase value when creating
/// allowed host layer otherwise layer may reject host and block request
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
    reject_multiple_hosts: bool,
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

    /// Reject request is one header have multiple host. For example if there is
    /// two `HOST` header than it will reject such request since server cannot
    /// determine which header to use for validation. Default value of this is
    /// false and it will get first value and will not reject request if
    /// multiple host is present for one header
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let _ = AllowedHostLayer::default().set_reject_multiple_hosts(true);
    /// ```
    #[must_use]
    pub fn set_reject_multiple_hosts(mut self, reject_multiple_hosts: bool) -> Self {
        self.reject_multiple_hosts = reject_multiple_hosts;
        self
    }

    fn is_host_allowed(&self, host: &str) -> bool {
        let is_allowed = self
            .allowed_hosts
            .iter()
            .any(|allowed_host| allowed_host == &host.to_string());

        #[cfg(feature = "wildcard")]
        let is_allowed = is_allowed
            || self
                .allowed_hosts_wildcard
                .iter()
                .any(|allowed_host_wildcard| allowed_host_wildcard.matches(host));

        #[cfg(feature = "regex")]
        let is_allowed = is_allowed
            || self
                .allowed_hosts_regex
                .iter()
                .any(|allowed_host_regex| allowed_host_regex.is_match(host));

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
        if let Some(host_val) = &host {
            if host_allowed {
                req.extensions_mut().insert(Host(host_val.to_string()));
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
    host: Option<String>,
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

/// get host from different supported header name
fn get_host(headers: &HeaderMap, layer: &AllowedHostLayer) -> Option<String> {
    let host_str = get_host_str(headers, layer)?.to_ascii_lowercase();
    let uri = host_str.parse::<Uri>().ok()?;
    let authority = uri.authority()?;
    // if uri contains path, scheme or query than return None for uri since it is
    // not valid `HOST` header
    if !uri.path().is_empty() || uri.query().is_some() || uri.scheme().is_some() {
        return None;
    }
    Some(authority.as_str().to_string())
}

fn get_host_str(headers: &HeaderMap, layer: &AllowedHostLayer) -> Option<String> {
    // get `Forwarded` header value
    if layer.use_forwarded {
        let forwarded_headers = headers.get_all(FORWARDED);
        let mut obtained_hosts = vec![];
        for forwarded_header in forwarded_headers {
            let header_str = forwarded_header.to_str().ok()?;
            let splitted_headers = header_str.split(',');
            for splitted_header in splitted_headers {
                let (key, value) = splitted_header.split_once('=')?;
                if key.trim().to_ascii_lowercase() == "host" {
                    obtained_hosts.push(value.trim().trim_matches('"'));
                }
            }
        }
        let mut obtained_hosts_iter = obtained_hosts.iter();
        if let Some(&host) = obtained_hosts_iter.next() {
            if layer.reject_multiple_hosts && obtained_hosts_iter.next().is_some() {
                return None;
            }
            return Some(host.to_string());
        }
    }

    // get `x-forwarded-host` value
    if layer.use_x_forwarded_host {
        let x_forwarded_headers = headers.get_all(X_FORWARDED_HOST_HEADER_KEY);
        let mut obtained_hosts = vec![];
        for x_forwarded_header in x_forwarded_headers {
            let header_str = x_forwarded_header.to_str().ok()?;
            let splitted_headers = header_str.split(',');
            for splitted_header in splitted_headers {
                obtained_hosts.push(splitted_header);
            }
        }
        let mut obtained_hosts_iter = obtained_hosts.iter();
        if let Some(&host) = obtained_hosts_iter.next() {
            if layer.reject_multiple_hosts && obtained_hosts_iter.next().is_some() {
                return None;
            }
            return Some(host.to_string());
        }
    }

    // get host header value.
    let host_headers = headers.get_all(HOST);
    let mut obtained_hosts = vec![];
    for host_header in host_headers {
        let header_str = host_header.to_str().ok()?;
        let splitted_headers = header_str.split(',');
        for splitted_header in splitted_headers {
            obtained_hosts.push(splitted_header);
        }
    }
    let mut obtained_hosts_iter = obtained_hosts.iter();
    if let Some(&host) = obtained_hosts_iter.next() {
        if layer.reject_multiple_hosts && obtained_hosts_iter.next().is_some() {
            return None;
        }
        return Some(host.to_string());
    }
    None
}
