#[cfg(feature = "regex")]
use regex::Regex;
#[cfg(feature = "wildcard")]
use wildmatch::WildMatchPattern;

/// Trait for matcher
pub trait Matcher {
    /// Check if provided host value matches with matcher
    fn matches_host(&self, host: &str) -> bool;
}

impl Matcher for String {
    fn matches_host(&self, host: &str) -> bool {
        self.eq(host)
    }
}

impl Matcher for &str {
    fn matches_host(&self, host: &str) -> bool {
        self.eq(&host)
    }
}

#[cfg(feature = "wildcard")]
impl<const MULTI_WILDCARD: char, const SINGLE_WILDCARD: char> Matcher
    for WildMatchPattern<MULTI_WILDCARD, SINGLE_WILDCARD>
{
    fn matches_host(&self, host: &str) -> bool {
        self.matches(host)
    }
}

#[cfg(feature = "regex")]
impl Matcher for Regex {
    fn matches_host(&self, host: &str) -> bool {
        self.is_match(host)
    }
}
