use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use tower::{service_fn, BoxError, Layer, ServiceExt};

use crate::AllowedHostLayer;

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
    let allowed_host_layer = AllowedHostLayer::default().extend(["127.0.0.1".to_string()]);
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
                .header("FORWARDED", "host=127.0.0.1")
                .header("X-FORWARDED-HOST", "127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(invalid_host_header_res.is_err());
}

#[tokio::test]
async fn normal_forwarded() {
    let allowed_host_layer = AllowedHostLayer::default()
        .set_use_forwarded(true)
        .push("example.com");
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "host=example.com")
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.30,for=10.0.10.11;by=10.1.12.11;\
                     host=127.0.0.3",
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let invalid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "for=10.0.10.11;by=10.1.12.11;host=127.0.0.2")
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.3,for=10.0.10.11;by=10.1.12.11;\
                     host=example.com",
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(invalid_host_header_res.is_err());
}

#[tokio::test]
async fn normal_x_forwarded() {
    let allowed_host_layer = AllowedHostLayer::default()
        .set_use_x_forwarded_host(true)
        .extend(["127.10.0.1"]);
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let valid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "host=127.10.0.1")
                .header("X-FORWARDED-HOST", "127.10.0.1,127.0.0.2")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(valid_host_header_res.is_ok());

    let invalid_host_header_res = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "for=10.0.10.11;by=10.1.12.11;host=127.10.0.10")
                .header("X-FORWARDED-HOST", "127.0.0.2,127.10.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(invalid_host_header_res.is_err());
}

#[tokio::test]
async fn reject_multiples() {
    let allowed_host_layer = AllowedHostLayer::default()
        .set_reject_multiple_hosts(true)
        .set_use_forwarded(true)
        .extend(["127.0.0.1"]);
    let svc = allowed_host_layer.layer(service_fn(inner_svc));

    let single = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "for=10.0.10.11;by=10.1.12.11;host=127.0.0.1")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(single.is_ok());

    let multiple_comma = svc
        .clone()
        .oneshot(
            Request::builder()
                .header(
                    "FORWARDED",
                    "for=10.0.10.11;by=10.1.12.11;host=127.0.0.1,for=10.0.10.11;by=10.1.12.11;\
                     host=127.0.0.10",
                )
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(multiple_comma.is_err());

    let multiple_header = svc
        .clone()
        .oneshot(
            Request::builder()
                .header("FORWARDED", "for=10.0.10.11;by=10.1.12.11;host=127.0.0.1")
                .header("FORWARDED", "for=10.0.10.11;by=10.1.12.11;host=127.0.0.10")
                .body(empty_body())
                .unwrap(),
        )
        .await;
    assert!(multiple_header.is_err());
}

#[cfg(feature = "wildcard")]
#[tokio::test]
async fn wildcard() {
    let allowed_host_layer =
        AllowedHostLayer::default().push(wildmatch::WildMatch::new("127.0.0.?"));
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
        AllowedHostLayer::new([regex::Regex::new("^[a-z]+.example.com$").unwrap()]);
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
