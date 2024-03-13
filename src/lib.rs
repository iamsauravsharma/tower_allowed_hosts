//! Crate which provides allowed hosts layer for tower based service where all
//! non allowed hosts request are blocked
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

/// module for error
pub mod error;

/// module for layer, service and future
pub mod service;

/// Module for tests
#[cfg(test)]
mod tests;

/// Struct which holds value of host along with its port if present which was
/// parsed and allowed by allowed host layer. This struct is added as a
/// extension to request after successfully resolving host and verifying host is
/// valid host which can be used in server if needed for further uses
#[derive(Clone)]
pub struct Host(pub String);

#[doc(inline)]
pub use service::AllowedHostLayer;
