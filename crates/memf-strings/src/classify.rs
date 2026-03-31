//! Classifier pipeline orchestration.

use crate::{ClassifiedString, StringCategory};

/// A classifier that examines a string and returns matching categories.
pub trait StringClassifier: Send + Sync {
    /// Human-readable name for this classifier.
    fn name(&self) -> &str;

    /// Classify a string. Returns a list of (category, confidence) pairs.
    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)>;
}

inventory::collect!(&'static dyn StringClassifier);

/// Run all registered classifiers on a list of strings, populating their categories.
pub fn classify_strings(strings: &mut [ClassifiedString]) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StringEncoding;

    fn make_string(value: &str) -> ClassifiedString {
        ClassifiedString {
            value: value.to_string(),
            physical_offset: 0,
            encoding: StringEncoding::Ascii,
            categories: Vec::new(),
        }
    }

    #[test]
    fn classify_populates_categories_via_inventory() {
        // The RegexClassifier is registered via inventory::submit! and should
        // classify URLs and IPs when classify_strings is called.
        let mut strings = vec![
            make_string("https://evil.com/malware.exe"),
            make_string("192.168.1.100"),
            make_string("just plain text"),
        ];

        classify_strings(&mut strings);

        // URL should be classified
        assert!(
            !strings[0].categories.is_empty(),
            "URL string should have categories"
        );
        // IP should be classified
        assert!(
            !strings[1].categories.is_empty(),
            "IP string should have categories"
        );
        // Plain text should remain uncategorized
        assert!(
            strings[2].categories.is_empty(),
            "plain text should have no categories"
        );
    }

    #[test]
    fn classify_empty_slice_is_noop() {
        let mut strings: Vec<ClassifiedString> = Vec::new();
        classify_strings(&mut strings);
        assert!(strings.is_empty());
    }

    #[test]
    fn classify_preserves_existing_categories() {
        let mut strings = vec![ClassifiedString {
            value: "https://example.com".to_string(),
            physical_offset: 0x100,
            encoding: StringEncoding::Ascii,
            categories: vec![(crate::StringCategory::Url, 0.5)],
        }];

        classify_strings(&mut strings);

        // Should have at least the pre-existing category plus any from classifiers
        assert!(
            strings[0].categories.len() >= 2,
            "should preserve existing + add new: got {}",
            strings[0].categories.len()
        );
    }
}
