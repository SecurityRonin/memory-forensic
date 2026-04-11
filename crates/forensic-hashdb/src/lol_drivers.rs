use crate::types::DriverInfo;
use std::sync::OnceLock;

fn parse_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
    }
    out
}

static LOL_DRIVERS: OnceLock<Vec<DriverInfo>> = OnceLock::new();

fn lol_drivers() -> &'static [DriverInfo] {
    LOL_DRIVERS.get_or_init(|| {
        vec![
            // RTCore64.sys — MSI Afterburner driver, used in many BYOVD attacks
            DriverInfo {
                name: "RTCore64.sys",
                sha256: parse_hex(
                    "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
                ),
                cves: &["CVE-2019-16098"],
                description:
                    "MSI Afterburner driver — arbitrary kernel R/W, widely used in BYOVD attacks",
            },
            // DBUtil_2_3.sys — Dell BIOS update driver
            DriverInfo {
                name: "DBUtil_2_3.sys",
                sha256: parse_hex(
                    "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
                ),
                cves: &["CVE-2021-21551"],
                description:
                    "Dell BIOS update driver — privilege escalation, used in BYOVD campaigns",
            },
            // WinRing0x64.sys — hardware access driver used by many monitoring tools
            DriverInfo {
                name: "WinRing0x64.sys",
                sha256: parse_hex(
                    "4f76a29fccf423e65c31cb95b254e944d66c9f1fc25a275e716f77c5b9b9bf8f",
                ),
                cves: &[],
                description: "WinRing0 hardware monitoring driver — kernel R/W primitive",
            },
            // gdrv.sys — Gigabyte driver
            DriverInfo {
                name: "gdrv.sys",
                sha256: parse_hex(
                    "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
                ),
                cves: &["CVE-2018-19320"],
                description: "Gigabyte driver — kernel memory R/W, used in ransomware BYOVD",
            },
            // AsrDrv104.sys — ASRock driver (verified SHA-256 from loldrivers.io)
            DriverInfo {
                name: "AsrDrv104.sys",
                sha256: parse_hex(
                    "b64ef01bc68f63a06b9c7da4a7ef7df1f1ccc36e5c0a07f0a5c1fcbfb6e2f4e1",
                ),
                cves: &["CVE-2020-15368"],
                description:
                    "ASRock driver — arbitrary kernel memory R/W, BYOVD attack surface",
            },
        ]
    })
}

/// Look up a driver by its SHA-256 hash.
///
/// Returns `Some(&DriverInfo)` if the hash matches a known-vulnerable driver,
/// `None` otherwise.
pub fn lookup_driver(sha256: &[u8; 32]) -> Option<&'static DriverInfo> {
    lol_drivers().iter().find(|d| &d.sha256 == sha256)
}

/// Returns `true` if the hash matches a known-vulnerable driver.
pub fn is_vulnerable_driver(sha256: &[u8; 32]) -> bool {
    lookup_driver(sha256).is_some()
}

/// Returns the full list of embedded known-vulnerable driver entries.
pub fn all_drivers() -> &'static [DriverInfo] {
    lol_drivers()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtcore64_sha256() -> [u8; 32] {
        parse_hex("01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd")
    }

    fn dbutil_sha256() -> [u8; 32] {
        parse_hex("0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5")
    }

    #[test]
    fn rtcore64_is_vulnerable_driver() {
        assert!(is_vulnerable_driver(&rtcore64_sha256()));
    }

    #[test]
    fn dbutil_is_vulnerable_driver() {
        assert!(is_vulnerable_driver(&dbutil_sha256()));
    }

    #[test]
    fn unknown_driver_hash_returns_none() {
        assert!(lookup_driver(&[0xffu8; 32]).is_none());
    }

    #[test]
    fn lookup_driver_returns_correct_name() {
        let info = lookup_driver(&rtcore64_sha256()).unwrap();
        assert_eq!(info.name, "RTCore64.sys");
    }

    #[test]
    fn lookup_driver_returns_cve_info() {
        let info = lookup_driver(&rtcore64_sha256()).unwrap();
        assert!(info.cves.contains(&"CVE-2019-16098"));
    }

    #[test]
    fn all_drivers_nonempty() {
        assert!(!all_drivers().is_empty());
        assert!(all_drivers().len() >= 5);
    }

    #[test]
    fn driver_info_has_description() {
        for driver in all_drivers() {
            assert!(!driver.description.is_empty(), "{} has no description", driver.name);
        }
    }
}
