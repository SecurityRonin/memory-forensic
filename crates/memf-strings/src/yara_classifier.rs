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
        let rules = yara_x::compile(source).map_err(|e| Error::Yara(e.to_string()))?;
        Ok(Self { rules })
    }

    /// Load and compile all `.yar` / `.yara` files from a directory.
    pub fn from_rules_dir(dir: &Path) -> crate::Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut found = false;

        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        let source = std::fs::read_to_string(&path)?;
                        compiler
                            .add_source(source.as_str())
                            .map_err(|e| Error::Yara(e.to_string()))?;
                        found = true;
                    }
                }
            }
        }

        if !found {
            return Err(Error::Yara(format!(
                "no .yar/.yara files found in {}",
                dir.display()
            )));
        }

        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scan a single string against the compiled rules.
    pub fn scan_string(&self, input: &str) -> Vec<(StringCategory, f32)> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        match scanner.scan(input.as_bytes()) {
            Ok(scan_results) => scan_results
                .matching_rules()
                .map(|rule| {
                    (
                        StringCategory::YaraMatch(rule.identifier().to_string()),
                        0.85,
                    )
                })
                .collect(),
            Err(_) => Vec::new(),
        }
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

    #[test]
    fn from_rules_dir_with_yar_files() {
        let dir = std::env::temp_dir().join("memf_test_yara_rules_dir");
        std::fs::create_dir_all(&dir).unwrap();
        let rule_path = dir.join("test_rule.yar");
        std::fs::write(
            &rule_path,
            r#"
rule detect_hello {
    strings:
        $hello = "HELLO_MARKER"
    condition:
        $hello
}
"#,
        )
        .unwrap();

        let classifier = YaraClassifier::from_rules_dir(&dir).unwrap();
        let matches = classifier.scan_string("HELLO_MARKER is here");
        assert_eq!(matches.len(), 1);
        assert!(
            matches!(matches[0].0, StringCategory::YaraMatch(ref name) if name == "detect_hello")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_rules_dir_empty_directory() {
        let dir = std::env::temp_dir().join("memf_test_yara_empty_dir");
        std::fs::create_dir_all(&dir).unwrap();
        // Remove any stale .yar files
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .map_or(false, |e| e == "yar" || e == "yara")
            {
                std::fs::remove_file(entry.path()).ok();
            }
        }

        let result = YaraClassifier::from_rules_dir(&dir);
        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_msg = format!("{e}");
                assert!(err_msg.contains("no .yar/.yara files found"));
            }
            Ok(_) => panic!("expected error for empty directory"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn classifier_name() {
        let source = r#"
rule dummy {
    strings:
        $x = "dummy"
    condition:
        $x
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        assert_eq!(classifier.name(), "yara");
    }
}
