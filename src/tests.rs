use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt as _;
use tower::{BoxError, Layer as _, ServiceExt as _, service_fn};

use crate::AllowedHostLayer;
use crate::matcher::Any;

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
