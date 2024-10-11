use std::future::Future;
#[cfg(feature = "cache")]
use std::num::NonZeroUsize;
use std::pin::Pin;
#[cfg(feature = "cache")]
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::header::{FORWARDED, HOST};
use http::uri::Authority;
use http::{HeaderMap, Request, Uri};
#[cfg(feature = "cache")]
use lru::LruCache;
use tower_layer::Layer;
use tower_service::Service;

use crate::error::Error;
use crate::matcher::Matcher;
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
/// # Example
///
/// ```rust
/// use tower_allowed_hosts::AllowedHostLayer;
/// let layer = AllowedHostLayer::default()
///     .extend(["example.com", "api.example.com"])
///     .set_use_forwarded(true)
///     .set_reject_multiple_hosts(true);
/// ```
///
/// # Supporting Multiple Match Types
/// To support matching against multiple types you can use an `enum` to wrap
/// different matcher types and implement `Matcher` for that enum.
///
/// # Example with Enum
/// ```rust
/// use tower_allowed_hosts::Matcher;
/// enum MultiMatcher {
///     Exact(String),
///     #[cfg(feature = "wildcard")]
///     Wildcard(wildmatch::WildMatch),
///     #[cfg(feature = "regex")]
///     Regex(regex::Regex),
/// }
///
/// impl Matcher for MultiMatcher {
///     fn matches_host(&self, host: &str) -> bool {
///         match self {
///             MultiMatcher::Exact(value) => value.matches_host(host),
///             #[cfg(feature = "wildcard")]
///             MultiMatcher::Wildcard(pattern) => pattern.matches_host(host),
///             #[cfg(feature = "regex")]
///             MultiMatcher::Regex(regex) => regex.matches_host(host),
///         }
///     }
/// }
///
/// let mut layer = tower_allowed_hosts::AllowedHostLayer::new([MultiMatcher::Exact(
///     "example.com".to_string(),
/// )])
/// .set_use_forwarded(true)
/// .set_reject_multiple_hosts(true);
/// #[cfg(feature = "wildcard")]
/// {
///     layer = layer.push(MultiMatcher::Wildcard(wildmatch::WildMatch::new(
///         "127.0.0.?",
///     )));
/// }
/// #[cfg(feature = "regex")]
/// {
///     layer = layer.push(MultiMatcher::Regex(
///         regex::Regex::new("^[a-z]+.example.com$").unwrap(),
///     ));
/// }
/// ```
#[derive(Clone, Default)]
pub struct AllowedHostLayer<M> {
    matchers: Vec<M>,
    use_forwarded: bool,
    use_x_forwarded_host: bool,
    reject_multiple_hosts: bool,
    #[cfg(feature = "cache")]
    cache: Option<Arc<Mutex<LruCache<String, bool>>>>,
}

impl<M> AllowedHostLayer<M>
where
    M: Matcher,
{
    /// Create new allowed hosts layer with provided matchers
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::new(vec!["127.0.0.1".to_string()]);
    /// ```
    #[must_use]
    pub fn new<I>(matchers: I) -> Self
    where
        I: IntoIterator<Item = M>,
    {
        Self {
            matchers: matchers.into_iter().collect(),
            use_forwarded: false,
            use_x_forwarded_host: false,
            reject_multiple_hosts: false,
            #[cfg(feature = "cache")]
            cache: None,
        }
    }

    /// Create new allowed hosts layer with provided matchers and cap size
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::new_with_cache_cap(
    ///     vec!["127.0.0.1".to_string()],
    ///     std::num::NonZeroUsize::new(24).unwrap(),
    /// );
    /// ```
    #[cfg(feature = "cache")]
    #[must_use]
    pub fn new_with_cache_cap<I>(matchers: I, cap: NonZeroUsize) -> Self
    where
        I: IntoIterator<Item = M>,
    {
        Self {
            matchers: matchers.into_iter().collect(),
            use_forwarded: false,
            use_x_forwarded_host: false,
            reject_multiple_hosts: false,
            cache: Some(Arc::new(Mutex::new(LruCache::new(cap)))),
        }
    }

    /// Add a matcher to allowed hosts layer
    #[must_use]
    pub fn push(mut self, matcher: M) -> Self {
        self.matchers.push(matcher);
        self
    }

    /// Extend allowed hosts layer with provided matchers
    #[must_use]
    pub fn extend<I>(mut self, matchers: I) -> Self
    where
        I: IntoIterator<Item = M>,
    {
        self.matchers.extend(matchers);
        self
    }

    /// Set lru cache cap
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::<String>::default()
    ///     .set_cap_size(std::num::NonZeroUsize::new(20).unwrap());
    /// ```
    #[cfg(feature = "cache")]
    #[must_use]
    pub fn set_cap_size(mut self, cap: NonZeroUsize) -> Self {
        self.cache = Some(Arc::new(Mutex::new(LruCache::new(cap))));
        self
    }

    /// Disable cache
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::<String>::default()
    ///     .set_cap_size(std::num::NonZeroUsize::new(20).unwrap())
    ///     .disable_cache();
    /// ```
    #[cfg(feature = "cache")]
    #[must_use]
    pub fn disable_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    /// Enable or disable the use of the `Forwarded` header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_allowed_hosts::AllowedHostLayer;
    /// let layer = AllowedHostLayer::<String>::default().set_use_forwarded(true);
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
    /// let layer = AllowedHostLayer::<&str>::default().set_use_x_forwarded_host(true);
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
    /// let layer = AllowedHostLayer::<String>::default().set_reject_multiple_hosts(true);
    /// ```
    #[must_use]
    pub fn set_reject_multiple_hosts(mut self, reject: bool) -> Self {
        self.reject_multiple_hosts = reject;
        self
    }
}

impl<M, S> Layer<S> for AllowedHostLayer<M>
where
    M: Clone,
{
    type Service = AllowedHost<M, S>;

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
pub struct AllowedHost<M, S> {
    inner: S,
    layer: AllowedHostLayer<M>,
}

impl<M, S, ReqBody> Service<Request<ReqBody>> for AllowedHost<M, S>
where
    S: Service<Request<ReqBody>>,
    S::Error: Into<BoxError>,
    M: Matcher,
{
    type Error = BoxError;
    type Future = AllowedHostFuture<S::Future>;
    type Response = S::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        if let Some(host_val) = get_authority(req.headers(), &self.layer) {
            #[cfg(feature = "cache")]
            if let Some(cache) = &self.layer.cache {
                if let Ok(mut mutex_guard) = cache.lock() {
                    if let Some(&host_allowed) = mutex_guard.get(host_val.as_str()) {
                        if host_allowed {
                            req.extensions_mut().insert(Host(host_val.clone()));
                        }
                        return Self::Future {
                            response_future: self.inner.call(req),
                            host: Some(host_val),
                            host_allowed,
                        };
                    }
                }
            }

            let host_allowed = self
                .layer
                .matchers
                .iter()
                .any(|m| m.matches_host(host_val.as_str()));

            if host_allowed {
                req.extensions_mut().insert(Host(host_val.clone()));
            }

            #[cfg(feature = "cache")]
            if let Some(cache) = &self.layer.cache {
                if let Ok(mut mutex_guard) = cache.lock() {
                    mutex_guard.put(host_val.to_string(), host_allowed);
                }
            }
            return Self::Future {
                response_future: self.inner.call(req),
                host: Some(host_val),
                host_allowed,
            };
        }

        // if no host is found than request is not allowed
        AllowedHostFuture {
            response_future: self.inner.call(req),
            host: None,
            host_allowed: false,
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

        let poll = match (&this.host, &this.host_allowed) {
            (Some(_), true) => {
                match this.response_future.poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
                    Poll::Pending => Poll::Pending,
                }
            }
            (Some(host), false) => {
                Poll::Ready(Err(Box::new(Error::HostNotAllowed(host.to_string())).into()))
            }
            (None, _) => Poll::Ready(Err(Box::new(Error::FailedToResolveHost).into())),
        };
        #[cfg(feature = "tracing")]
        {
            if let Some(host) = &this.host {
                if poll.is_ready() {
                    match this.host_allowed {
                        true => tracing::debug!("allowed host: {}", host),
                        false => tracing::debug!("blocked host: {}", host),
                    }
                }
            }
        }
        poll
    }
}

/// Extract the authority (host) from the request headers based on the layer
/// configuration.
fn get_authority<M>(headers: &HeaderMap, layer: &AllowedHostLayer<M>) -> Option<Authority> {
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
