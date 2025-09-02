//! Crate which provides allowed hosts layer for tower based service
//!
//! To use crate with any service you can create layer with any matcher
//!
//! # Examples
//! ```rust
//! let layer = tower_allowed_hosts::AllowedHostLayer::new("example.com");
//! ```
//!
//! Check `README.MD` or documentation of [`AllowedHostLayer`] for more detailed
//! information
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[doc(inline)]
pub use service::AllowedHostLayer;

/// module for error
pub mod error;

/// module for matcher
pub mod matcher;

/// module for layer, service and future
pub mod service;

/// Module for tests
#[cfg(test)]
mod tests;

/// Struct which holds value of host
///
/// This struct is added as a extension to request after successfully resolving
/// host and verifying host is valid host which can be used in server if needed
/// for further uses
#[derive(Clone)]
pub struct Host(pub String);
