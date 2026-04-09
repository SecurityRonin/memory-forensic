//! YARA-X memory region scanner.
//!
//! Scans raw byte buffers (process memory regions) against compiled YARA rules
//! to detect malware signatures, shellcode patterns, and IoC indicators in
//! process address spaces. Unlike `yara_classifier` which scans individual
//! strings, this module scans arbitrary binary data — critical for detecting
//! packed/encrypted payloads, injected code, and fileless malware.

use std::path::Path;

/// A match from scanning a memory region against YARA rules.
#[derive(Debug, Clone)]
pub struct YaraScanMatch {
    /// YARA rule identifier that matched.
    pub rule_name: String,
    /// Rule tags (e.g., "malware", "apt", "ransomware").
    pub tags: Vec<String>,
    /// Offset within the scanned buffer where the first pattern matched.
    pub match_offset: u64,
    /// Virtual address of the region that was scanned.
    pub region_base: u64,
    /// Length of the scanned region.
    pub region_size: usize,
    /// Matched string identifiers and their offsets within the buffer.
    pub matched_strings: Vec<MatchedPattern>,
}

/// A single pattern match within a YARA scan result.
#[derive(Debug, Clone)]
pub struct MatchedPattern {
    /// The YARA string identifier (e.g., "$mz_header", "$shellcode").
    pub identifier: String,
    /// Offset within the buffer where this pattern matched.
    pub offset: u64,
    /// The matched bytes (truncated to first 64 bytes if longer).
    pub data: Vec<u8>,
}

/// Scanner that applies compiled YARA rules to raw memory buffers.
pub struct YaraMemoryScanner {
    rules: yara_x::Rules,
}

impl YaraMemoryScanner {
    /// Compile YARA rules from source text.
    pub fn from_source(source: &str) -> crate::Result<Self> {
        let rules = yara_x::compile(source).map_err(|e| crate::Error::Yara(e.to_string()))?;
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
                            .map_err(|e| crate::Error::Yara(e.to_string()))?;
                        found = true;
                    }
                }
            }
        }

        if !found {
            return Err(crate::Error::Yara(format!(
                "no .yar/.yara files found in {}",
                dir.display()
            )));
        }

        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scan a raw byte buffer against the compiled rules.
    ///
    /// `region_base` is the virtual address of the memory region being scanned
    /// (used for reporting, not for the scan itself).
    pub fn scan_region(
        &self,
        data: &[u8],
        region_base: u64,
    ) -> crate::Result<Vec<YaraScanMatch>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut scanner = yara_x::Scanner::new(&self.rules);
        let scan_results = scanner
            .scan(data)
            .map_err(|e| crate::Error::Yara(e.to_string()))?;

        let mut matches = Vec::new();

        for rule in scan_results.matching_rules() {
            let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();

            let mut matched_strings = Vec::new();
            let mut first_offset = u64::MAX;

            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    let offset = m.range().start as u64;
                    if offset < first_offset {
                        first_offset = offset;
                    }
                    let matched_data: Vec<u8> = data
                        [m.range().start..m.range().end.min(m.range().start + 64)]
                        .to_vec();
                    matched_strings.push(MatchedPattern {
                        identifier: pattern.identifier().to_string(),
                        offset,
                        data: matched_data,
                    });
                }
            }

            if first_offset == u64::MAX {
                first_offset = 0;
            }

            matches.push(YaraScanMatch {
                rule_name: rule.identifier().to_string(),
                tags,
                match_offset: first_offset,
                region_base,
                region_size: data.len(),
                matched_strings,
            });
        }

        Ok(matches)
    }

    /// Scan multiple memory regions and aggregate results.
    ///
    /// Each tuple is `(region_base_vaddr, region_bytes)`.
    pub fn scan_regions(
        &self,
        regions: &[(u64, &[u8])],
    ) -> crate::Result<Vec<YaraScanMatch>> {
        let mut all_matches = Vec::new();
        for &(base, data) in regions {
            let mut region_matches = self.scan_region(data, base)?;
            all_matches.append(&mut region_matches);
        }
        Ok(all_matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_RULE: &str = r#"
rule detect_mz_header {
    meta:
        description = "Detects MZ PE header"
    strings:
        $mz = { 4D 5A 90 00 }
    condition:
        $mz
}
"#;

    const TAGGED_RULE: &str = r#"
rule shellcode_nopsled : shellcode suspicious {
    meta:
        description = "Detects NOP sled"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}
"#;

    const MULTI_RULE: &str = r#"
rule detect_mz {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}

rule detect_elf {
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf
}
"#;

    #[test]
    fn from_source_compiles_valid_rules() {
        let scanner = YaraMemoryScanner::from_source(SIMPLE_RULE).unwrap();
        // Should succeed without error — scanner is created
        let _ = scanner;
    }

    #[test]
    fn from_source_rejects_invalid_rules() {
        let result = YaraMemoryScanner::from_source("this is not valid yara");
        assert!(result.is_err());
    }

    #[test]
    fn scan_region_detects_mz_header() {
        let scanner = YaraMemoryScanner::from_source(SIMPLE_RULE).unwrap();

        // Buffer with MZ header at offset 0
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        data[2] = 0x90;
        data[3] = 0x00;

        let matches = scanner.scan_region(&data, 0x7FFE_0000).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "detect_mz_header");
        assert_eq!(matches[0].region_base, 0x7FFE_0000);
        assert_eq!(matches[0].region_size, 256);
        assert!(!matches[0].matched_strings.is_empty());
        assert_eq!(matches[0].matched_strings[0].identifier, "$mz");
        assert_eq!(matches[0].matched_strings[0].offset, 0);
    }

    #[test]
    fn scan_region_no_match() {
        let scanner = YaraMemoryScanner::from_source(SIMPLE_RULE).unwrap();

        // Buffer with no MZ header
        let data = vec![0xCCu8; 256];
        let matches = scanner.scan_region(&data, 0x1000).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_region_with_tags() {
        let scanner = YaraMemoryScanner::from_source(TAGGED_RULE).unwrap();

        // Buffer with NOP sled
        let mut data = vec![0u8; 256];
        for i in 0..16 {
            data[i] = 0x90; // NOP
        }

        let matches = scanner.scan_region(&data, 0x4000).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "shellcode_nopsled");
        assert!(matches[0].tags.contains(&"shellcode".to_string()));
        assert!(matches[0].tags.contains(&"suspicious".to_string()));
    }

    #[test]
    fn scan_regions_aggregates_results() {
        let scanner = YaraMemoryScanner::from_source(MULTI_RULE).unwrap();

        // Region 1: MZ header
        let mut region1 = vec![0u8; 128];
        region1[0] = 0x4D;
        region1[1] = 0x5A;

        // Region 2: ELF header
        let mut region2 = vec![0u8; 128];
        region2[0] = 0x7F;
        region2[1] = 0x45; // E
        region2[2] = 0x4C; // L
        region2[3] = 0x46; // F

        let regions: Vec<(u64, &[u8])> = vec![
            (0x1000, &region1),
            (0x2000, &region2),
        ];
        let matches = scanner.scan_regions(&regions).unwrap();

        // Should find detect_mz in region1 and detect_elf in region2
        assert_eq!(matches.len(), 2);
        let rule_names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(rule_names.contains(&"detect_mz"));
        assert!(rule_names.contains(&"detect_elf"));

        // Verify correct region_base assignment
        let mz_match = matches.iter().find(|m| m.rule_name == "detect_mz").unwrap();
        assert_eq!(mz_match.region_base, 0x1000);
        let elf_match = matches.iter().find(|m| m.rule_name == "detect_elf").unwrap();
        assert_eq!(elf_match.region_base, 0x2000);
    }

    #[test]
    fn scan_empty_buffer_returns_no_matches() {
        let scanner = YaraMemoryScanner::from_source(SIMPLE_RULE).unwrap();
        let matches = scanner.scan_region(&[], 0x0).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn matched_pattern_data_truncated_to_64_bytes() {
        // Rule that matches a long pattern
        let rule = r#"
rule long_match {
    strings:
        $zeros = { 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $zeros
}
"#;
        let scanner = YaraMemoryScanner::from_source(rule).unwrap();
        let data = vec![0u8; 256];
        let matches = scanner.scan_region(&data, 0x5000).unwrap();
        assert_eq!(matches.len(), 1);
        // The matched data should be at most 64 bytes
        for mp in &matches[0].matched_strings {
            assert!(mp.data.len() <= 64);
        }
    }
}
