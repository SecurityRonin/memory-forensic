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
    for s in strings.iter_mut() {
        for classifier in inventory::iter::<&'static dyn StringClassifier> {
            let matches = classifier.classify(&s.value);
            s.categories.extend(matches);
        }
    }
}
