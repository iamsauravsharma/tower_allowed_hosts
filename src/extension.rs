use http::Uri;

/// Extension to store allowed host value.
#[derive(Clone)]
pub struct Host(pub Uri);
