//! Crate which provides allowed hosts layer for tower based service where all
//! non allowed hosts request are blocked
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

/// module for error
pub mod error;

/// Module for extension
pub mod extension;

/// module for layer, service and future
pub mod service;

pub use service::AllowedHostLayer;
