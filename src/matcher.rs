#[cfg(feature = "regex")]
use regex::Regex;
#[cfg(feature = "wildcard")]
use wildmatch::WildMatchPattern;

/// Trait for matcher
pub trait Matcher {
    /// Check if provided value value matches with matcher
    fn matches_value(&self, value: &str) -> bool;
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
