use std::collections::HashMap;

#[cfg(feature = "regex")]
use regex::Regex;
#[cfg(feature = "wildcard")]
use wildmatch::WildMatchPattern;

/// Trait for matching against the value
///
/// A `Matcher` is responsible for checking whether a given value is consider to
/// match with a provided matcher
pub trait Matcher {
    /// Checks if provided value matches according to matcher
    fn matches_value(&self, value: &str) -> bool;
}

/// Trait for matching the presence and values of parameters in a `Forwarded`
/// header.
///
/// When `AllowedHostLayer` is configured with a `KeyValueMatcher`, it will
/// only consider the `host=` value from a `Forwarded` header if the matcher
/// determines that the header’s parameters are acceptable.
///
/// The matcher receives a map of all key–value pairs in the `Forwarded` entry
/// (e.g. `for=...;by=...;host=...;token=value`)
pub trait KeyValueMatcher {
    /// Checks if provided value matches according to matcher
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool;
}

/// Any matcher which always returns true and matches any host
#[derive(Clone)]
pub struct Any;

impl Matcher for Any {
    fn matches_value(&self, _value: &str) -> bool {
        true
    }
}

impl KeyValueMatcher for Any {
    fn matches_key_value(&self, _values: &HashMap<String, String>) -> bool {
        true
    }
}

/// And matcher which matches only when both left and right matches
pub struct And<L, R> {
    left: L,
    right: R,
}

impl<L, R> And<L, R> {
    /// Create new and matcher
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }
}

impl<L, R> Matcher for And<L, R>
where
    L: Matcher,
    R: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        self.left.matches_value(value) && self.right.matches_value(value)
    }
}

impl<L, R> KeyValueMatcher for And<L, R>
where
    L: KeyValueMatcher,
    R: KeyValueMatcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        self.left.matches_key_value(values) && self.right.matches_key_value(values)
    }
}

/// Or matcher which matches when either left and right matches
pub struct Or<L, R> {
    left: L,
    right: R,
}

impl<L, R> Or<L, R> {
    /// Create new or matcher
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }
}

impl<L, R> KeyValueMatcher for Or<L, R>
where
    L: KeyValueMatcher,
    R: KeyValueMatcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        self.left.matches_key_value(values) || self.right.matches_key_value(values)
    }
}

impl<L, R> Matcher for Or<L, R>
where
    L: Matcher,
    R: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        self.left.matches_value(value) || self.right.matches_value(value)
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

impl Matcher for () {
    fn matches_value(&self, _value: &str) -> bool {
        false
    }
}

impl KeyValueMatcher for () {
    fn matches_key_value(&self, _values: &HashMap<String, String>) -> bool {
        false
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

impl<M> Matcher for Option<M>
where
    M: Matcher,
{
    fn matches_value(&self, value: &str) -> bool {
        if let Some(matcher) = self {
            matcher.matches_value(value)
        } else {
            false
        }
    }
}

impl<M> KeyValueMatcher for Option<M>
where
    M: KeyValueMatcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        if let Some(matcher) = self {
            matcher.matches_key_value(values)
        } else {
            false
        }
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

impl<M> KeyValueMatcher for Box<M>
where
    M: KeyValueMatcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        (**self).matches_key_value(values)
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

impl<M> KeyValueMatcher for &M
where
    M: KeyValueMatcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        (**self).matches_key_value(values)
    }
}

impl<S, M> KeyValueMatcher for (S, M)
where
    S: Matcher,
    M: Matcher,
{
    fn matches_key_value(&self, values: &HashMap<String, String>) -> bool {
        let (key_matcher, value_matcher) = self;
        values
            .iter()
            .any(|(k, v)| key_matcher.matches_value(k) && value_matcher.matches_value(v))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::matcher::{And, Any, KeyValueMatcher as _, Matcher as _, Or};

    fn forwarded_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn any_host_always_matches() {
        let m = Any;
        assert!(m.matches_value("example.com"));
        assert!(m.matches_value("random"));
    }

    #[test]
    fn any_forwarded_always_matches() {
        let m = Any;
        let data = forwarded_map(&[("by", "server1")]);
        assert!(m.matches_key_value(&data));
    }

    #[test]
    fn string_and_str_matchers() {
        let m1 = "example.com".to_string();
        let m2 = "example.com";
        assert!(m1.matches_value("example.com"));
        assert!(!m1.matches_value("other.com"));
        assert!(m2.matches_value("example.com"));
        assert!(!m2.matches_value("other.com"));
    }

    #[test]
    fn unit_matchers_never_match() {
        let host_m: () = ();
        let fwd_m: () = ();
        assert!(!host_m.matches_value("anything"));
        let data = forwarded_map(&[("foo", "bar")]);
        assert!(!fwd_m.matches_key_value(&data));
    }

    #[test]
    fn and_matcher() {
        let m1 = "example.com".to_string();
        let m2 = "example.com";
        let and = And::new(m1, m2);
        assert!(and.matches_value("example.com"));
        assert!(!and.matches_value("other.com"));
    }

    #[test]
    fn or_matcher() {
        let m1 = "foo.com".to_string();
        let m2 = "bar.com".to_string();
        let or = Or::new(m1, m2);
        assert!(or.matches_value("foo.com"));
        assert!(or.matches_value("bar.com"));
        assert!(!or.matches_value("baz.com"));
    }

    #[test]
    fn option_and_box_wrappers() {
        let some: Option<String> = Some("host.com".to_string());
        assert!(some.matches_value("host.com"));
        assert!(!some.matches_value("other.com"));

        let none: Option<String> = None;
        assert!(!none.matches_value("host.com"));

        let boxed: Box<String> = Box::new("host.com".to_string());
        assert!(boxed.matches_value("host.com"));
    }

    #[test]
    fn forwarded_tuple_matcher() {
        let fwd = ("by", "proxy1");
        let data = forwarded_map(&[("by", "proxy1"), ("host", "example.com")]);
        assert!(fwd.matches_key_value(&data));

        let data2 = forwarded_map(&[("by", "proxy2")]);
        assert!(!fwd.matches_key_value(&data2));
    }

    #[test]
    fn forwarded_and_or_matchers() {
        let m1 = ("by", "proxy1");
        let m2 = ("sig", "123");
        let and = And::new(m1, m2);
        let or = Or::new(m1, m2);

        let data = forwarded_map(&[("by", "proxy1"), ("sig", "123")]);
        assert!(and.matches_key_value(&data));
        assert!(or.matches_key_value(&data));

        let data2 = forwarded_map(&[("by", "proxy2"), ("sig", "123")]);
        assert!(!and.matches_key_value(&data2));
        assert!(or.matches_key_value(&data2));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regex_matcher() {
        use regex::Regex;

        let m = Regex::new(r"^.*\.com$").unwrap();
        assert!(m.matches_value("example.com"));
        assert!(!m.matches_value("example.org"));
    }

    #[cfg(feature = "wildcard")]
    #[test]
    fn wildcard_matcher() {
        use wildmatch::WildMatch;

        let m = WildMatch::new("*.example.com");
        assert!(m.matches_value("api.example.com"));
        assert!(m.matches_value("www.example.com"));
        assert!(!m.matches_value("example.org"));
    }
}
