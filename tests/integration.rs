//! End-to-end integration tests for the memf pipeline.

use memf_format::test_builders::{AvmlBuilder, LimeBuilder};
use memf_strings::classify::classify_strings;
use memf_strings::extract::{extract_strings, ExtractConfig};
use memf_strings::StringCategory;

#[test]
fn lime_extract_and_classify_url() {
    let mut data = vec![0u8; 256];
    let url = b"https://malware.example.com/shell.elf";
    data[32..32 + url.len()].copy_from_slice(url);

    let dump = LimeBuilder::new().add_range(0x1000, &data).build();
    let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();

    let config = ExtractConfig {
        min_length: 4,
        ascii: true,
        utf16le: false,
    };
    let mut strings = extract_strings(&provider, &config);
    classify_strings(&mut strings);

    let url_matches: Vec<_> = strings
        .iter()
        .filter(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::Url))
        .collect();
    assert_eq!(url_matches.len(), 1);
    assert!(url_matches[0].value.contains("malware.example.com"));
}

#[test]
fn avml_extract_and_classify_ip() {
    let mut data = vec![0u8; 256];
    let ip = b"192.168.1.100";
    data[64..64 + ip.len()].copy_from_slice(ip);

    let dump = AvmlBuilder::new().add_range(0x2000, &data).build();
    let provider = memf_format::avml::AvmlProvider::from_bytes(&dump).unwrap();

    let mut strings = extract_strings(&provider, &ExtractConfig::default());
    classify_strings(&mut strings);

    let ip_matches: Vec<_> = strings
        .iter()
        .filter(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::IpV4))
        .collect();
    assert!(!ip_matches.is_empty());
}

#[test]
fn from_file_and_classify() {
    use std::io::Write;

    let path = std::env::temp_dir().join("memf_integration_strings");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "https://c2.evil.org/beacon").unwrap();
        writeln!(f, "192.168.0.1").unwrap();
        writeln!(f, "user@example.com").unwrap();
        writeln!(f, "random garbage text").unwrap();
        writeln!(f, "/etc/shadow").unwrap();
    }

    let mut strings = memf_strings::from_file::from_strings_file(&path).unwrap();
    classify_strings(&mut strings);

    let classified: Vec<_> = strings
        .iter()
        .filter(|s| !s.categories.is_empty())
        .collect();
    assert!(
        classified.len() >= 4,
        "expected >= 4 classified, got {}",
        classified.len()
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn yara_classifier_with_custom_rule() {
    let rule = r#"
rule suspicious_powershell {
    strings:
        $ps = "powershell" nocase
    condition:
        $ps
}
"#;
    let classifier = memf_strings::yara_classifier::YaraClassifier::from_source(rule).unwrap();
    let matches = classifier.scan_string("powershell -enc ZWNobyBoZWxsbw==");
    assert_eq!(matches.len(), 1);
    assert!(
        matches!(matches[0].0, StringCategory::YaraMatch(ref name) if name == "suspicious_powershell")
    );
}
