#![deny(unsafe_code)]
#![warn(missing_docs)]
//! String extraction and IoC classification for memory forensics.

pub mod classify;
pub mod extract;
pub mod from_file;
pub mod regex_classifier;
pub mod yara_classifier;

/// A string extracted from memory, classified into zero or more categories.
#[derive(Debug, Clone)]
pub struct ClassifiedString {
    /// The extracted string value.
    pub value: String,
    /// Physical offset in the memory dump (0 if from a file).
    pub physical_offset: u64,
    /// How this string was encoded in memory.
    pub encoding: StringEncoding,
    /// Classification results (may be empty for uncategorized strings).
    pub categories: Vec<(StringCategory, f32)>,
}

/// String encoding as found in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// ASCII (printable bytes 0x20-0x7E).
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 Little Endian.
    Utf16Le,
}

/// Classification category for an extracted string.
#[derive(Debug, Clone, PartialEq)]
pub enum StringCategory {
    /// URL (http, https, ftp, file, data).
    Url,
    /// IPv4 address.
    IpV4,
    /// IPv6 address.
    IpV6,
    /// Email address.
    Email,
    /// Unix file path.
    UnixPath,
    /// Windows file path.
    WindowsPath,
    /// Windows registry key path.
    RegistryKey,
    /// Domain name.
    DomainName,
    /// Cryptocurrency address (Bitcoin, Ethereum, Monero).
    CryptoAddress,
    /// Private key material (PEM, SSH, etc.).
    PrivateKey,
    /// Base64-encoded blob (20+ chars).
    Base64Blob,
    /// Shell command or reverse shell indicator.
    ShellCommand,
    /// YARA rule match (rule name stored in string).
    YaraMatch(String),
}

/// Error type for memf-strings operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error from the format crate.
    #[error("format error: {0}")]
    Format(#[from] memf_format::Error),

    /// YARA compilation error.
    #[error("YARA error: {0}")]
    Yara(String),
}

/// Result alias for memf-strings.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_string_basic() {
        let cs = ClassifiedString {
            value: "https://example.com".into(),
            physical_offset: 0x1234,
            encoding: StringEncoding::Ascii,
            categories: vec![(StringCategory::Url, 0.95)],
        };
        assert_eq!(cs.value, "https://example.com");
        assert_eq!(cs.physical_offset, 0x1234);
        assert_eq!(cs.categories.len(), 1);
    }
}
