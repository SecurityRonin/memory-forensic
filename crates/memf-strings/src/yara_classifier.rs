//! YARA-X rule-based string classifier.
//!
//! Scans strings against compiled YARA rules and returns matches
//! as `StringCategory::YaraMatch(rule_name)`.

use crate::classify::StringClassifier;
use crate::{Error, StringCategory};
use std::path::Path;

/// A classifier that matches strings against YARA-X rules.
pub struct YaraClassifier {
    rules: yara_x::Rules,
}

impl YaraClassifier {
    /// Compile YARA rules from source text.
    pub fn from_source(source: &str) -> crate::Result<Self> {
        todo!()
    }

    /// Load and compile all `.yar` / `.yara` files from a directory.
    pub fn from_rules_dir(dir: &Path) -> crate::Result<Self> {
        todo!()
    }

    /// Scan a single string against the compiled rules.
    pub fn scan_string(&self, input: &str) -> Vec<(StringCategory, f32)> {
        todo!()
    }
}

impl StringClassifier for YaraClassifier {
    fn name(&self) -> &str {
        "yara"
    }

    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)> {
        self.scan_string(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_simple_rule() {
        let source = r#"
rule test_url {
    strings:
        $url = /https?:\/\/[^\s]+/
    condition:
        $url
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("https://malware.example.com/payload");
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0].0, StringCategory::YaraMatch(ref name) if name == "test_url"));
    }

    #[test]
    fn no_match() {
        let source = r#"
rule test_never {
    strings:
        $never = "THIS_WILL_NEVER_MATCH_ANYTHING_12345"
    condition:
        $never
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("hello world");
        assert!(matches.is_empty());
    }

    #[test]
    fn multiple_rules() {
        let source = r#"
rule has_ip {
    strings:
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        $ip
}

rule has_http {
    strings:
        $http = "http"
    condition:
        $http
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("http://10.0.0.1/shell");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn invalid_rule_source_errors() {
        let result = YaraClassifier::from_source("not valid yara");
        assert!(result.is_err());
    }
}
