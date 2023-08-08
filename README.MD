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
tower_allowed_hosts = "0.2.0"
```

# Usage

To use non regex based hosts you can use

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::new(vec!["127.0.0.1"]);
```

If you need to use regex based host matching you need to enable `regex` feature for crate than you can use

```rust
let tower_layer = tower_allowed_hosts::AllowedHostLayer::new_regex(vec![regex::Regex::new("^127.0.0.1$")]);
```

[license_badge]: https://img.shields.io/github/license/iamsauravsharma/tower_allowed_hosts.svg?style=for-the-badge
[license_link]: LICENSE
[cratesio_badge]: https://img.shields.io/crates/v/tower_allowed_hosts.svg?style=for-the-badge
[cratesio_link]: https://crates.io/crates/tower_allowed_hosts
[docsrs_badge]: https://img.shields.io/docsrs/tower_allowed_hosts/latest?style=for-the-badge
[docsrs_link]: https://docs.rs/tower_allowed_hosts
