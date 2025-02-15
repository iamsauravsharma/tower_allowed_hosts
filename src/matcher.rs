#[cfg(feature = "regex")]
use regex::Regex;
#[cfg(feature = "wildcard")]
use wildmatch::WildMatchPattern;

/// Trait for checking if a given value matches a specific pattern.
///
/// `Matcher` trait is currently used in two places checking `Host` header as
/// well as `Forwarded` header value. Both can have custom `Matcher` which
/// differs from each others
///
/// The `Matcher` trait is designed to be highly versatile and extensible,
/// allowing it to be implemented for a variety of pattern matching scenarios.
/// Beyond simple string comparisons `Matcher` can be extended to support
/// complex operations according to requirements
pub trait Matcher: Clone {
    /// Checks if provided value matches according to matcher
    fn matches_value(&self, value: &str) -> bool;
}

/// Asterisk matcher which always returns true and matches any host
#[derive(Clone)]
pub struct Asterisk;

impl Matcher for Asterisk {
    fn matches_value(&self, _value: &str) -> bool {
        true
    }
}

impl Matcher for String {
    fn matches_value(&self, value: &str) -> bool {
        self.eq(value)
    }
}

impl Matcher for &str {
    fn matches_value(&self, value: &str) -> bool {
        self.eq(&value)
    }
}

#[cfg(feature = "wildcard")]
impl<const MULTI_WILDCARD: char, const SINGLE_WILDCARD: char> Matcher
    for WildMatchPattern<MULTI_WILDCARD, SINGLE_WILDCARD>
{
    fn matches_value(&self, value: &str) -> bool {
        self.matches(value)
    }
}

#[cfg(feature = "regex")]
impl Matcher for Regex {
    fn matches_value(&self, value: &str) -> bool {
        self.is_match(value)
    }
}

impl<M> Matcher for Box<M>
where
    M: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        (**self).matches_value(value)
    }
}

impl<M> Matcher for &M
where
    M: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        (**self).matches_value(value)
    }
}

impl<M> Matcher for Vec<M>
where
    M: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        self.iter().all(|matcher| matcher.matches_value(value))
    }
}
