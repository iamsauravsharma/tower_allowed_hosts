# TOWER ALLOWED HOSTS

**Project status & info:**

|                    License                     |              Crates Version               |                 Docs                 |
| :--------------------------------------------: | :---------------------------------------: | :----------------------------------: |
| [![License: MIT][license_badge]][license_link] | [![Crate][cratesio_badge]][cratesio_link] | [![Docs][docsrs_badge]][docsrs_link] |

Tower service which limits request from only hosts 


## Add as dependencies

Edit Cargo.toml file to add tower_allowed_hosts as dependencies

```toml
[dependencies]
tower_allowed_hosts = "0.4.0"
```

# Usage

To use non regex based hosts you can use

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::default().extend(&["127.0.0.1".to_string()]);
```

If you need to use wildcard based host matching you need to enable `wildcard` feature for crate than you can use

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::default().extend_wildcard(&["127.0.0.*".to_string()]);
```
If you need to use regex based host matching you need to enable `regex` feature for crate than you can use

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::default().extend_regex(&[regex::Regex::new("^127.0.0.1$")?]);
```

After creation of layer you can use layer in library which supports tower as component

For example to use tower allowed hosts in axum you also needs to add HandleErrorLayer so error gets handled properly

```rust
use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    Router
};
use tower::ServiceBuilder;
use tower_allowed_hosts::AllowedHostLayer;

fn router() -> Router {
    let handle_error_layer = HandleErrorLayer::new(handle_box_error);

    let allowed_hosts_layer = AllowedHostLayer::new_regex(&[regex::Regex::new("^127.0.0.1$")?]);

     let layer = ServiceBuilder::new()
        .layer(handle_error_layer)
        .layer(allowed_hosts_layer);

    Router::new().layer(layer)
}

async fn handle_box_error(err: tower::BoxError) -> (StatusCode, String) {
    if err.is::<tower_allowed_hosts::Error>() {
        return (StatusCode::BAD_REQUEST, err.to_string());
    }
    return (StatusCode::INTERNAL_SERVER_ERROR, "".to_string())
}
```

[license_badge]: https://img.shields.io/github/license/iamsauravsharma/tower_allowed_hosts.svg?style=for-the-badge
[license_link]: LICENSE
[cratesio_badge]: https://img.shields.io/crates/v/tower_allowed_hosts.svg?style=for-the-badge
[cratesio_link]: https://crates.io/crates/tower_allowed_hosts
[docsrs_badge]: https://img.shields.io/docsrs/tower_allowed_hosts/latest?style=for-the-badge
[docsrs_link]: https://docs.rs/tower_allowed_hosts
