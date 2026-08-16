use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Request, Response, Version};
use http_body_util::BodyExt as _;
use tower::{BoxError, Layer as _, ServiceExt as _, service_fn};

use crate::matcher::Any;
use crate::{AllowedHostLayer, Error};

type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

fn empty_body() -> BoxBody {
    http_body_util::Empty::new()
        .map_err(Into::into)
        .boxed_unsync()
}

async fn inner_svc(_: Request<BoxBody>) -> Result<Response<BoxBody>, Infallible> {
    Ok(Response::builder().body(empty_body()).unwrap())
}

#[tokio::test]
async fn normal() {
    let allowed_host_layer = AllowedHostLayer::new("127.0.0.1".to_string())
        .with_forwarded_matcher(("signature", "random_value"));
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let empty_res = svc.clone().oneshot(Request::new(empty_body())).await;
    assert!(empty_res.is_err());

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let invalid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.2")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(invalid_host_header_res.is_err());

    let valid_forwarded_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "host=example.com")
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.1;signature=random_value,for=10.0.\
                     10.11;by=10.1.12.11;host=127.0.0.3",
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_forwarded_header_res.is_ok());

    let invalid_forwarded_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.2;signature=random_value",
                )
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.1,for=10.0.10.11;by=10.1.12.11;\
                     host=example.com",
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(invalid_forwarded_header_res.is_err());
}

#[cfg(feature = "wildcard")]
#[tokio::test]
async fn wildcard() {
    let allowed_host_layer = AllowedHostLayer::new(wildmatch::WildMatch::new("127.0.0.?"));
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let empty_res = svc.clone().oneshot(Request::new(empty_body())).await;
    assert!(empty_res.is_err());

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let another_ok = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.2")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(another_ok.is_ok());

    let multiple_issue = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.20")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(multiple_issue.is_err());
}

#[cfg(feature = "regex")]
#[tokio::test]
async fn regex() {
    let allowed_host_layer =
        AllowedHostLayer::new(regex::Regex::new("^[a-z]+.example.com$").unwrap());
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let empty_res = svc.clone().oneshot(Request::new(empty_body())).await;
    assert!(empty_res.is_err());

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "ab.example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let another_ok = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "test.example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(another_ok.is_ok());

    let issue_no_1 = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "ab1.example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(issue_no_1.is_err());

    let issue_no_2 = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "a.example.com.np")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(issue_no_2.is_err());

    let issue_no_3 = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "a.example.org")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(issue_no_3.is_err());
}

#[tokio::test]
async fn any() {
    let allowed_host_layer = AllowedHostLayer::new(Any).with_forwarded_matcher(("by", Any));
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let empty_res = svc.clone().oneshot(Request::new(empty_body())).await;
    assert!(empty_res.is_err());

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let any_value_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "any_value")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(any_value_host_header_res.is_ok());
}

#[tokio::test]
async fn inner_service_not_called_when_blocked() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let svc = AllowedHostLayer::new("127.0.0.1").layer(service_fn(move |req: Request<BoxBody>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            inner_svc(req).await
        }
    }));

    let blocked_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.2")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(blocked_res.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let allowed_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(allowed_res.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn multiple_host_headers_rejected() {
    let svc = AllowedHostLayer::new("127.0.0.1").layer(service_fn(inner_svc));

    let res = svc
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .header("HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let err = res.unwrap_err();
    assert!(matches!(
        err.downcast_ref::<Error>(),
        Some(Error::MultipleHostHeader)
    ));
}

#[tokio::test]
async fn malformed_forwarded_ignored_without_forwarded_matcher() {
    let svc = AllowedHostLayer::new("127.0.0.1").layer(service_fn(inner_svc));

    let res = svc
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.1")
                .header("FORWARDED", "malformed entry without equals")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn forwarded_quoted_values() {
    let svc = AllowedHostLayer::new("127.0.0.1")
        .with_forwarded_matcher(("signature", "random_value"))
        .layer(service_fn(inner_svc));

    let quoted_delimiters_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header(
                    "FORWARDED",
                    r#"for="10.0.10.11;fake=1,x";signature=random_value;host=127.0.0.1"#,
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(quoted_delimiters_res.is_ok());

    let quoted_host_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", r#"signature="random_value";host="127.0.0.1""#)
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(quoted_host_res.is_ok());

    let smuggled_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("HOST", "127.0.0.2")
                .header(
                    "FORWARDED",
                    r#"for="x;host=127.0.0.1;signature=random_value""#,
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(smuggled_res.is_err());
}

#[tokio::test]
async fn http2_authority() {
    let svc = AllowedHostLayer::new("example.com").layer(service_fn(inner_svc));

    let authority_only_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_2)
                .uri("https://example.com/path")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(authority_only_res.is_ok());

    let case_insensitive_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_2)
                .uri("https://example.com/path")
                .header("HOST", "EXAMPLE.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(case_insensitive_res.is_ok());

    let mismatch_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_2)
                .uri("https://example.com/path")
                .header("HOST", "other.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let mismatch_err = mismatch_res.unwrap_err();
    assert!(matches!(
        mismatch_err.downcast_ref::<Error>(),
        Some(Error::MismatchAuthorityHost)
    ));

    let multiple_host_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_2)
                .uri("https://example.com/path")
                .header("HOST", "example.com")
                .header("HOST", "example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let multiple_host_err = multiple_host_res.unwrap_err();
    assert!(matches!(
        multiple_host_err.downcast_ref::<Error>(),
        Some(Error::MultipleHostHeader)
    ));

    let missing_authority_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_2)
                .header("HOST", "example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let missing_authority_err = missing_authority_res.unwrap_err();
    assert!(matches!(
        missing_authority_err.downcast_ref::<Error>(),
        Some(Error::MissingAuthority)
    ));
}

#[tokio::test]
async fn http1_absolute_form_uri_takes_precedence() {
    let svc = AllowedHostLayer::new("example.com").layer(service_fn(inner_svc));

    let missing_host_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .uri("http://example.com/path")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let missing_host_err = missing_host_res.unwrap_err();
    assert!(matches!(
        missing_host_err.downcast_ref::<Error>(),
        Some(Error::MissingHost)
    ));

    let http10_authority_only_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .version(Version::HTTP_10)
                .uri("http://example.com/path")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(http10_authority_only_res.is_ok());

    let matching_host_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .uri("http://example.com/path")
                .header("HOST", "EXAMPLE.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(matching_host_res.is_ok());

    let mismatch_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .uri("http://other.com/path")
                .header("HOST", "example.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let mismatch_err = mismatch_res.unwrap_err();
    assert!(matches!(
        mismatch_err.downcast_ref::<Error>(),
        Some(Error::MismatchAuthorityHost)
    ));

    let disallowed_authority_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .uri("http://other.com/path")
                .header("HOST", "other.com")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    let disallowed_authority_err = disallowed_authority_res.unwrap_err();
    assert!(matches!(
        disallowed_authority_err.downcast_ref::<Error>(),
        Some(Error::HostNotAllowed(host)) if host == "other.com"
    ));
}
