use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::uri::Authority;
use http::{HeaderMap, Request, Uri};
#[cfg(feature = "regex")]
use regex::Regex;
use tower_layer::Layer;
use tower_service::Service;
#[cfg(feature = "wildcard")]
use wildmatch::WildMatch;

use crate::error::Error;
use crate::Host;

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Allowed hosts layer to check if the provided host is valid.
///
/// The hostname is resolved through the following, in order:
/// - `Forwarded` header (if `use_forwarded` is true)
/// - `X-Forwarded-Host` header (if `use_x_forwarded_host` is true)
/// - `Host` header
///
/// Determined hosts are always lowercase. Ensure to use lowercase values when
/// creating the allowed host layer to avoid unintended request blocking.
///
/// By default, the first host value from the headers is used. If multiple
/// host values are present, subsequent values are ignored unless
/// `reject_multiple_hosts` is enabled, which will reject the request.
///
/// # Examples
///
/// ```rust
/// use tower_allowed_hosts::AllowedHostLayer;
/// let layer = AllowedHostLayer::default()
///     .extend(["example.com", "api.example.com"])
///     .set_use_forwarded(true)
///     .set_reject_multiple_hosts(true);
/// ```
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
    /// Extend allowed hosts list using exact string matches.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().extend(["127.0.0.1", "localhost"]);
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

    /// Extend allowed hosts list using wildcard patterns.
    /// - `?` matches exactly one occurrence of any character.
    /// - `*` matches arbitrary many (including zero) occurrences of any
    ///   character.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().extend_wildcard(["*.example.com"]);
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

    /// Extend allowed hosts list using regular expressions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use regex::Regex;
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().extend_regex([
    ///     Regex::new(r"^127\.0\.0\.1$").unwrap(),
    ///     Regex::new(r"^localhost$").unwrap(),
    /// ]);
    /// ```
    #[must_use]
    #[cfg(feature = "regex")]
    pub fn extend_regex<I>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = Regex>,
    {
        self.allowed_hosts_regex.extend(hosts);
        self
    }

    /// Enable or disable the use of the `Forwarded` header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().set_use_forwarded(true);
    /// ```
    #[must_use]
    pub fn set_use_forwarded(mut self, use_forwarded: bool) -> Self {
        self.use_forwarded = use_forwarded;
        self
    }

    /// Enable or disable the use of the `X-Forwarded-Host` header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().set_use_x_forwarded_host(true);
    /// ```
    #[must_use]
    pub fn set_use_x_forwarded_host(mut self, use_x_forwarded_host: bool) -> Self {
        self.use_x_forwarded_host = use_x_forwarded_host;
        self
    }

    /// Configure the layer to reject requests with multiple host values in a
    /// single header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::default().set_reject_multiple_hosts(true);
    /// ```
    #[must_use]
    pub fn set_reject_multiple_hosts(mut self, reject: bool) -> Self {
        self.reject_multiple_hosts = reject;
        self
    }

    /// Check if the provided authority (host) is allowed.
    ///
    /// The host is converted to lowercase before matching.
    fn is_host_allowed(&self, authority: &Authority) -> bool {
        let host = authority.as_str().to_ascii_lowercase();

        // Exact match using HashSet for O(1) lookup
        if self.allowed_hosts.contains(&host) {
            return true;
        }

        // Wildcard match
        #[cfg(feature = "wildcard")]
        {
            if self
                .allowed_hosts_wildcard
                .iter()
                .any(|pattern| pattern.matches(&host))
            {
                return true;
            }
        }

        // Regex match
        #[cfg(feature = "regex")]
        {
            if self
                .allowed_hosts_regex
                .iter()
                .any(|regex| regex.is_match(&host))
            {
                return true;
            }
        }

        false
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

/// Allowed hosts service that wraps the inner service and validates the request
/// host.
#[derive(Clone)]
pub struct AllowedHost<S> {
    inner: S,
    layer: AllowedHostLayer,
}

impl<S, ReqBody> Service<Request<ReqBody>> for AllowedHost<S>
where
    S: Service<Request<ReqBody>>,
    S::Error: Into<BoxError>,
{
    type Error = BoxError;
    type Future = AllowedHostFuture<S::Future>;
    type Response = S::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let host = get_authority(req.headers(), &self.layer);
        let host_allowed = host.as_ref().is_some_and(|h| self.layer.is_host_allowed(h));

        // If the host is allowed, insert it into the request extensions
        let mut req = req;
        if let Some(ref host_val) = host {
            if host_allowed {
                req.extensions_mut().insert(Host(host_val.clone()));
            }
        }

        AllowedHostFuture {
            response_future: self.inner.call(req),
            host,
            host_allowed,
        }
    }
}

/// Future for AllowedHost service.
#[pin_project::pin_project]
pub struct AllowedHostFuture<F> {
    #[pin]
    response_future: F,
    host: Option<Authority>,
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

        match (&this.host, this.host_allowed) {
            (Some(host), true) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("allowed host: {}", host);
                // Proceed to poll the inner future
                match this.response_future.poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
                    Poll::Pending => Poll::Pending,
                }
            }
            (Some(host), false) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("blocked host: {}", host);
                Poll::Ready(Err(Box::new(Error::HostNotAllowed(host.to_string()))))
            }
            (None, _) => Poll::Ready(Err(Box::new(Error::FailedToResolveHost))),
        }
    }
}

/// Extract the authority (host) from the request headers based on the layer
/// configuration.
fn get_authority(headers: &HeaderMap, layer: &AllowedHostLayer) -> Option<Authority> {
    // Attempt to extract host from Forwarded headers
    if layer.use_forwarded {
        if let Some(authority) = extract_from_forwarded(headers, layer.reject_multiple_hosts) {
            return Some(authority);
        }
    }

    // Attempt to extract host from X-Forwarded-Host headers
    if layer.use_x_forwarded_host {
        if let Some(authority) = extract_from_x_forwarded_host(headers, layer.reject_multiple_hosts)
        {
            return Some(authority);
        }
    }

    // Fallback to Host headers
    extract_from_host(headers, layer.reject_multiple_hosts)
}

/// Extract host from Forwarded headers.
fn extract_from_forwarded(headers: &HeaderMap, reject_multiple: bool) -> Option<Authority> {
    let mut obtained_hosts = Vec::new();

    for forwarded_header in headers.get_all(FORWARDED) {
        let header_str = forwarded_header.to_str().ok()?;
        for header in header_str.split(',') {
            for part in header.split(';') {
                if let Some((key, value)) = part.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("host") {
                        obtained_hosts.push(value.trim().trim_matches('"').to_string());
                    }
                }
            }
        }
    }

    validate_and_parse_hosts(&obtained_hosts, reject_multiple)
}

/// Extract host from X-Forwarded-Host headers.
fn extract_from_x_forwarded_host(headers: &HeaderMap, reject_multiple: bool) -> Option<Authority> {
    let mut obtained_hosts = Vec::new();

    for header in headers.get_all(X_FORWARDED_HOST_HEADER_KEY) {
        let header_str = header.to_str().ok()?;
        obtained_hosts.extend(header_str.split(',').map(|s| s.trim().to_string()));
    }

    validate_and_parse_hosts(&obtained_hosts, reject_multiple)
}

/// Extract host from Host headers.
fn extract_from_host(headers: &HeaderMap, reject_multiple: bool) -> Option<Authority> {
    let mut obtained_hosts = Vec::new();

    for host_header in headers.get_all(HOST) {
        let header_str = host_header.to_str().ok()?;
        obtained_hosts.extend(header_str.split(',').map(|s| s.trim().to_string()));
    }

    validate_and_parse_hosts(&obtained_hosts, reject_multiple)
}

/// Validate the extracted hosts and parse the first valid authority.
/// If `reject_multiple` is true and multiple hosts are present, return None.
fn validate_and_parse_hosts(obtained_hosts: &[String], reject_multiple: bool) -> Option<Authority> {
    let mut hosts_iter = obtained_hosts.iter();

    let first_host = hosts_iter.next()?;
    if reject_multiple && hosts_iter.next().is_some() {
        return None;
    }

    let uri = first_host.parse::<Uri>().ok()?;

    if (uri.path() != "/" && !uri.path().is_empty())
        || uri.query().is_some()
        || uri.scheme().is_some()
    {
        return None;
    }

    let authority = uri.authority()?;
    // Ensure authority does not contain user info
    if authority.as_str().contains('@') {
        return None;
    }

    Some(authority.clone())
}
