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
/// This layer inspects the request authority/host and compares it against
/// the configured list of allowed hosts. The authority is determined
/// according to HTTP specifications, with optional support for trusted
/// `Forwarded` headers. Requests whose host cannot be resolved or is not
/// allowed are rejected without ever reaching the inner service.
///
/// ## Host resolution priority
///
/// 1. If `forwarded_matcher` is configured and matches, the `host` parameter
///    from the `Forwarded` header is used as the effective host. This applies
///    to **all HTTP versions**.
/// 2. Otherwise, host resolution falls back to protocol-specific rules:
///    - For **HTTP/2 and HTTP/3**:
///      - The `:authority` pseudo-header (via `req.uri().authority()`) is the
///        canonical source.
///      - If a `Host` header is present, it must match `:authority` (compared
///        case-insensitively) or the request will be rejected.
///      - If `:authority` is missing, the request is rejected.
///    - For **HTTP/1.x and older**:
///      - If the request target is in absolute form, its authority is used (RFC
///        9112 §3.2.2). The `Host` header must match it (compared
///        case-insensitively) or the request will be rejected; for HTTP/1.1 the
///        `Host` header is required even in absolute form (RFC 9112 §3.2),
///        while for HTTP/1.0 and earlier it may be absent.
///      - Otherwise the `Host` header is used.
///      - If the `Host` header is missing, invalid, or appears multiple times,
///        the request is rejected (invalid per RFC 9112 §3.2).
///
/// ## Forwarded header usage
///
/// When `forwarded_matcher` is set, the layer attempts to extract the `host`
/// parameter from the `Forwarded` header only if the specified token-value
/// pair is present in that header. This allows the layer to recover the
/// client-facing host even if one or more proxies have rewritten the `Host`
/// header or `:authority`.
///
/// For example:
///
/// ```text
/// Forwarded: for=10.0.10.11;by=10.1.12.11;host=127.0.0.1;signature=random_value,
///            for=10.0.10.11;by=10.1.12.11;host=127.0.0.3
/// ```
///
/// With `forwarded_matcher = ("signature", "random_value")`, the extracted
/// host will be `127.0.0.1`. Other entries are ignored.
///
/// When no forwarded matcher is configured (i.e. it is `()` or another
/// matcher that can never match), `Forwarded` headers are not parsed at all,
/// so malformed `Forwarded` headers cannot cause a rejection.
///
/// ## ⚠️ Security warning
///
/// The `Forwarded` header can be spoofed by clients unless it is **sanitized
/// or injected by a trusted proxy**. Only enable `forwarded_matcher` if:
/// - You fully control the proxies in front of this service, and
/// - You trust them to strip any untrusted `Forwarded` headers.
///
/// In all other cases, rely solely on `:authority` (HTTP/2/3) or `Host`
/// (HTTP/1.1) for determining the request authority.
///
/// ## Examples
///
/// ```rust
/// let layer = tower_allowed_hosts::AllowedHostLayer::new("example.com");
/// ```
#[derive(Clone, Debug)]
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

    /// Extend a host matcher with provided forwarded matcher
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
#[derive(Clone, Debug)]
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
        let resolved_host = get_host(&req, &self.layer.forwarded_matcher).and_then(|host| {
            if self.layer.host_matcher.matches_value(host.as_str()) {
                Ok(host)
            } else {
                Err(Error::HostNotAllowed(host))
            }
        });

        match resolved_host {
            Ok(host) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("allowed host: {host}");
                req.extensions_mut().insert(Host(host));
                Self::Future {
                    state: FutureState::Allowed {
                        future: self.inner.call(req),
                    },
                }
            }
            Err(error) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("request rejected: {error}");
                Self::Future {
                    state: FutureState::Rejected { error },
                }
            }
        }
    }
}

/// Future for `AllowedHost` service.
///
/// Resolves with the inner service response when the host is allowed,
/// otherwise resolves immediately with an error. The inner service is never
/// invoked for rejected requests.
#[pin_project::pin_project]
pub struct AllowedHostFuture<F> {
    #[pin]
    state: FutureState<F>,
}

#[pin_project::pin_project(project = FutureStateProj)]
enum FutureState<F> {
    Allowed {
        #[pin]
        future: F,
    },
    Rejected {
        error: Error,
    },
}

impl<F, Response, E> Future for AllowedHostFuture<F>
where
    F: Future<Output = Result<Response, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().state.project() {
            FutureStateProj::Allowed { future } => future.poll(cx).map_err(Into::into),
            FutureStateProj::Rejected { error } => Poll::Ready(Err(error.clone().into())),
        }
    }
}

/// Extract the host from the request headers based on the layer configuration.
fn get_host<F, ReqBody>(req: &Request<ReqBody>, forwarded_matcher: &F) -> Result<String, Error>
where
    F: KeyValueMatcher,
{
    let headers = req.headers();

    if let Some(forwarded_host) = extract_from_forwarded(headers, forwarded_matcher)? {
        return Ok(forwarded_host);
    }

    match req.version() {
        // HTTP/2 and HTTP/3 use the :authority pseudo-header; Host is optional
        Version::HTTP_2 | Version::HTTP_3 => {
            let Some(authority) = req.uri().authority() else {
                return Err(Error::MissingAuthority);
            };
            check_host_matches_authority(headers, authority.as_str(), false)?;
            Ok(authority.to_string())
        }
        // HTTP/1.1 and earlier: absolute-form request target takes precedence
        // over the Host header (RFC 9112 §3.2.2), otherwise Host is used. The
        // Host header is mandatory for HTTP/1.1 (RFC 9112 §3.2), optional for
        // HTTP/1.0 and earlier
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
            if let Some(authority) = req.uri().authority() {
                let host_required = req.version() == Version::HTTP_11;
                check_host_matches_authority(headers, authority.as_str(), host_required)?;
                return Ok(authority.to_string());
            }
            extract_from_host(headers)
        }
        // Future-proof fallback
        _ => Err(Error::UnsupportedHttpVersion),
    }
}

/// Check that the `Host` header agrees with the request target authority
/// (compared case-insensitively).
fn check_host_matches_authority(
    headers: &HeaderMap,
    authority: &str,
    host_required: bool,
) -> Result<(), Error> {
    match extract_from_host(headers) {
        Ok(host) => {
            if host.eq_ignore_ascii_case(authority) {
                Ok(())
            } else {
                Err(Error::MismatchAuthorityHost)
            }
        }
        Err(Error::MissingHost) if !host_required => Ok(()),
        Err(err) => Err(err),
    }
}

/// Extract host from `Host` headers.
fn extract_from_host(headers: &HeaderMap) -> Result<String, Error> {
    let mut host_headers = headers.get_all(HOST).iter();
    let first_host = host_headers.next().ok_or(Error::MissingHost)?;
    if host_headers.next().is_some() {
        return Err(Error::MultipleHostHeader);
    }
    let host_str = first_host
        .to_str()
        .map_err(|_| Error::InvalidHost)?
        .trim()
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
    // do not parse (and possibly reject) Forwarded headers which would never
    // be trusted anyway
    if forwarded_matcher.never_matches() {
        return Ok(None);
    }
    for forwarded_header in headers.get_all(FORWARDED) {
        let header_str = forwarded_header
            .to_str()
            .map_err(|_| Error::InvalidForwardedHeader)?;
        for header_entry in split_outside_quotes(header_str, ',') {
            let (host_value, token_map) = parse_forwarded_entry(header_entry)?;

            if let Some(host) = host_value
                && forwarded_matcher.matches_key_value(&token_map)
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

    for part in split_outside_quotes(entry, ';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (key, value) = part.split_once('=').ok_or(Error::InvalidForwardedHeader)?;

        let key = key.trim().to_lowercase();
        let value = unquote_forwarded_value(value.trim())?;

        if key.as_str() == "host" {
            host_value = Some(value.clone());
        }
        token_map.insert(key, value);
    }

    Ok((host_value, token_map))
}

/// Split on `delimiter` occurrences that are outside RFC 7239 quoted-strings,
/// so quoted values containing `,` or `;` do not shift parameter boundaries
fn split_outside_quotes(value: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == delimiter && !in_quotes {
            parts.push(&value[start..index]);
            start = index + 1;
        }
    }
    parts.push(&value[start..]);
    parts
}

/// Resolve an RFC 7239 parameter value: quoted-strings are unquoted with
/// `\`-escapes processed, unquoted tokens are returned as-is
fn unquote_forwarded_value(value: &str) -> Result<String, Error> {
    let Some(quoted) = value.strip_prefix('"') else {
        if value.contains('"') {
            return Err(Error::InvalidForwardedHeader);
        }
        return Ok(value.to_string());
    };
    let inner = quoted
        .strip_suffix('"')
        .ok_or(Error::InvalidForwardedHeader)?;
    let mut unescaped = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => unescaped.push(chars.next().ok_or(Error::InvalidForwardedHeader)?),
            '"' => return Err(Error::InvalidForwardedHeader),
            _ => unescaped.push(ch),
        }
    }
    Ok(unescaped)
}

#[cfg(test)]
mod tests {
    use super::{split_outside_quotes, unquote_forwarded_value};

    #[test]
    fn split_respects_quotes() {
        assert_eq!(split_outside_quotes("a=1;b=2", ';'), vec!["a=1", "b=2"]);
        assert_eq!(
            split_outside_quotes(r#"a="1;2";b=3"#, ';'),
            vec![r#"a="1;2""#, "b=3"]
        );
        assert_eq!(
            split_outside_quotes(r#"a="1,2",b=3"#, ','),
            vec![r#"a="1,2""#, "b=3"]
        );
        assert_eq!(
            split_outside_quotes(r#"a="1\";2";b=3"#, ';'),
            vec![r#"a="1\";2""#, "b=3"]
        );
    }

    #[test]
    fn unquote_values() {
        assert_eq!(unquote_forwarded_value("plain").unwrap(), "plain");
        assert_eq!(unquote_forwarded_value(r#""quoted""#).unwrap(), "quoted");
        assert_eq!(unquote_forwarded_value(r#""""#).unwrap(), "");
        assert_eq!(unquote_forwarded_value(r#""a\"b""#).unwrap(), "a\"b");
        assert!(unquote_forwarded_value(r#""unterminated"#).is_err());
        assert!(unquote_forwarded_value(r#"stray"quote"#).is_err());
        assert!(unquote_forwarded_value(r#""bad"inner""#).is_err());
    }
}
