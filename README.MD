# TOWER ALLOWED HOSTS

**Project status & info:**

|                    License                     |              Crates Version               |                 Docs                 |
| :--------------------------------------------: | :---------------------------------------: | :----------------------------------: |
| [![License: MIT][license_badge]][license_link] | [![Crate][cratesio_badge]][cratesio_link] | [![Docs][docsrs_badge]][docsrs_link] |

Tower service which limits request from only specified hosts
All hostnames are automatically converted to lowercase before matching.

## Add as dependencies

In your `Cargo.toml` file, add `tower_allowed_hosts` as a dependency:

```toml
[dependencies]
tower_allowed_hosts = "0.7.0"
```

# Usage

### Basic

To restrict access to specific basic hosts, you can use the following code:

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::default()
    .extend_allowed_hosts(&["127.0.0.1".to_string()]);
```

### Wildcard

If you need wildcard-based host matching, enable the `wildcard` feature in your `Cargo.toml`:

```toml
[dependencies]
tower_allowed_hosts = { version = "0.7.0", features = ["wildcard"] }
```

You can then restrict hosts using wildcards:

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::default()
    .extend_allowed_hosts(&[wildmatch::WildMatch::new("127.0.0.*")]);
```

### Regex

If you need regex-based host matching, enable the `regex` feature in your `Cargo.toml`:

```toml
[dependencies]
tower_allowed_hosts = { version = "0.7.0", features = ["regex"] }
```

You can then restrict hosts using regex patterns:

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::new(&[regex::Regex::new("^127.0.0.1$")?]);
```

# Integrating with a Tower-Compatible Library

After creating the `AllowedHostLayer`, it can be integrated into any library that supports `tower` components. Here's an example of how to use this layer in an `axum` application. You will also need to handle errors properly using `HandleErrorLayer`:

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

    let allowed_hosts_layer = AllowedHostLayer::default()
        .extend_allowed_hosts(&[wildmatch::WildMatch::new("127.0.0.*")]);

     let layer = ServiceBuilder::new()
        .layer(handle_error_layer)
        .layer(allowed_hosts_layer);

    Router::new().layer(layer)
}

async fn handle_box_error(err: tower::BoxError) -> (StatusCode, String) {
    if err.is::<tower_allowed_hosts::error::Error>() {
        return (StatusCode::BAD_REQUEST, err.to_string());
    }
    return (StatusCode::INTERNAL_SERVER_ERROR, "".to_string())
}
```

There is also extension added after successfully parsing allowed host and allowing host which can be access using
`tower_allowed_hosts::Host` struct Extension

[license_badge]: https://img.shields.io/github/license/iamsauravsharma/tower_allowed_hosts.svg?style=for-the-badge
[license_link]: LICENSE
[cratesio_badge]: https://img.shields.io/crates/v/tower_allowed_hosts.svg?style=for-the-badge
[cratesio_link]: https://crates.io/crates/tower_allowed_hosts
[docsrs_badge]: https://img.shields.io/docsrs/tower_allowed_hosts/latest?style=for-the-badge
[docsrs_link]: https://docs.rs/tower_allowed_hosts
