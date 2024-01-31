//! Crate which provides allowed hosts layer for tower based service where all
//! non allowed hosts request are blocked
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use http::Uri;

/// module for error
pub mod error;

/// module for layer, service and future
pub mod service;

/// Extension to store allowed host value.
#[derive(Clone)]
pub struct AllowedHostExtension(pub Uri);

#[doc(inline)]
pub use service::AllowedHostLayer;
