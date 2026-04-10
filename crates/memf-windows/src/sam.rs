//! Windows SAM (Security Account Manager) user account extraction.
//!
//! The SAM registry hive (`\REGISTRY\MACHINE\SAM`) stores local user
//! account metadata: usernames, RIDs, account flags, and (encrypted)
//! password hashes. Extracting SAM data from memory enables:
//!
//! - Identifying all local accounts (including hidden/disabled ones)
//! - Detecting recently created accounts (persistence via new user)
//! - Recovering account metadata when disk SAM is locked/encrypted
//!
//! The SAM hive is structured as:
//! `SAM\Domains\Account\Users\<RID>\V` — per-user binary data
//! `SAM\Domains\Account\Users\Names\<username>` — name→RID mapping

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of SAM user entries to walk (safety limit).
const MAX_USERS: usize = 4096;

/// Information about a local user account recovered from the SAM hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SamUserInfo {
    /// User account name.
    pub username: String,
    /// Relative Identifier (RID) — unique per-user on the local machine.
    pub rid: u32,
    /// Account flags (USER_ACCOUNT_CONTROL): disabled, locked out, etc.
    pub account_flags: u32,
    /// Whether the account is currently disabled.
    pub is_disabled: bool,
    /// Whether the account has an empty (blank) password hint.
    pub has_empty_password: bool,
    /// Last login time (FILETIME).
    pub last_login_time: u64,
    /// Last password change time (FILETIME).
    pub last_password_change: u64,
    /// Account creation time (FILETIME, from F value).
    pub account_created: u64,
    /// Login count.
    pub login_count: u32,
    /// Whether this account looks suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Account flag constants from USER_ACCOUNT_CONTROL.
pub const UAC_ACCOUNT_DISABLED: u32 = 0x0001;
pub const UAC_LOCKOUT: u32 = 0x0010;
pub const UAC_PASSWORD_NOT_REQUIRED: u32 = 0x0020;
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;

/// Classify a SAM user account as suspicious.
///
/// Returns `true` for accounts that match patterns of attacker-created
/// persistence accounts:
/// - Username ends with '$' (hidden account convention)
/// - Account has admin-like RID (500) but unusual name
/// - Recently created account with password-not-required flag
/// - Username matches known attack tool default accounts
pub fn classify_sam_user(username: &str, rid: u32, flags: u32) -> bool {
    if username.is_empty() {
        return false;
    }

    let lower = username.to_ascii_lowercase();

    // Hidden accounts end with '$' (a Windows convention)
    if lower.ends_with('$') && !lower.ends_with("machine$") {
        return true;
    }

    // RID 500 is the built-in Administrator — if renamed to something unusual
    if rid == 500 && lower != "administrator" && lower != "admin" {
        return true;
    }

    // Password not required is suspicious for normal accounts
    if (flags & UAC_PASSWORD_NOT_REQUIRED) != 0 && (flags & UAC_NORMAL_ACCOUNT) != 0 {
        return true;
    }

    // Known attack tool default account names
    const SUSPICIOUS_NAMES: &[&str] = &[
        "defaultaccount0",
        "support_388945a0",
        "svc_admin",
        "backdoor",
        "hacker",
        "test123",
    ];
    if SUSPICIOUS_NAMES.iter().any(|&s| lower == s) {
        return true;
    }

    false
}

/// Extract local user accounts from the SAM registry hive in memory.
///
/// Reads the SAM hive at `hive_addr` and walks
/// `SAM\Domains\Account\Users` to enumerate user accounts.
/// Returns an empty `Vec` if the hive is unreadable or the path is missing.
pub fn walk_sam_users<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> crate::Result<Vec<SamUserInfo>> {
    if hive_addr == 0 {
        return Ok(Vec::new());
    }

    // Read _HHIVE.BaseBlock pointer (at offset 0x10 typically) to get _HBASE_BLOCK.
    let base_block_off = reader
        .symbols()
        .field_offset("_HHIVE", "BaseBlock")
        .unwrap_or(0x10);

    let base_block_addr = match reader.read_bytes(hive_addr + base_block_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if base_block_addr == 0 {
        return Ok(Vec::new());
    }

    // Read root cell offset from _HBASE_BLOCK (at offset 0x24, u32).
    let root_cell_off = match reader.read_bytes(base_block_addr + 0x24, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if root_cell_off == 0 || root_cell_off == u32::MAX {
        return Ok(Vec::new());
    }

    // The storage base is at _HHIVE + Hive.Storage[Stable].Map or we can compute
    // cell addresses as hive_addr + 0x1000 (hbin start) + cell_offset + 4 (cell header).
    // For simplicity, we use the dual-mapping approach: read from base_block + 0x1000 + offset.
    let storage_base = reader
        .symbols()
        .field_offset("_HHIVE", "Storage")
        .unwrap_or(0x30);

    // Try to read the flat storage base pointer (Stable storage BlockList).
    let flat_base = match reader.read_bytes(hive_addr + storage_base, 8) {
        Ok(bytes) if bytes.len() == 8 => {
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr != 0 {
                addr
            } else {
                base_block_addr + 0x1000
            }
        }
        _ => base_block_addr + 0x1000,
    };

    // Navigate: root → SAM → Domains → Account → Users → Names
    // Each _CM_KEY_NODE has Signature at 0x0 (should be "nk" = 0x6B6E),
    // SubKeyCount at 0x18 (u32), SubKeyLists at 0x20 (u32 offset).
    // We navigate by reading subkey lists and matching key names.
    let root_addr = read_cell_addr(reader, flat_base, root_cell_off);
    if root_addr == 0 {
        return Ok(Vec::new());
    }

    // Walk SAM\Domains\Account\Users\Names to get username→RID mappings,
    // then read the F/V values from SAM\Domains\Account\Users\<RID>.
    // For the simplified walker, we enumerate child keys under the
    // Users\Names path and extract metadata from each user's RID key.

    // Navigate: root → SAM → Domains → Account → Users
    let sam_key = find_subkey_by_name(reader, flat_base, root_addr, "SAM");
    if sam_key == 0 {
        return Ok(Vec::new());
    }
    let domains_key = find_subkey_by_name(reader, flat_base, sam_key, "Domains");
    if domains_key == 0 {
        return Ok(Vec::new());
    }
    let account_key = find_subkey_by_name(reader, flat_base, domains_key, "Account");
    if account_key == 0 {
        return Ok(Vec::new());
    }
    let users_key = find_subkey_by_name(reader, flat_base, account_key, "Users");
    if users_key == 0 {
        return Ok(Vec::new());
    }

    // Read the Names subkey to get username→RID mappings.
    let names_key = find_subkey_by_name(reader, flat_base, users_key, "Names");

    let mut users = Vec::new();

    // Enumerate RID subkeys under Users (hex RID strings like "000001F4").
    let subkey_count: u32 = match reader.read_bytes(users_key + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    };

    if subkey_count == 0 || subkey_count > MAX_USERS as u32 {
        return Ok(users);
    }

    let subkey_list_off: u32 = match reader.read_bytes(users_key + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(users),
    };

    let list_addr = read_cell_addr(reader, flat_base, subkey_list_off);
    if list_addr == 0 {
        return Ok(users);
    }

    // Read list signature (lf/lh/li).
    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return Ok(users),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return Ok(users),
    };

    for i in 0..count.min(MAX_USERS as u16) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                // lf/lh: 8-byte entries (offset + hash) starting at +4
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => {
                // li: 4-byte entries (offset only) starting at +4
                match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        // Read key name (at offset 0x4C in _CM_KEY_NODE, length at 0x4A).
        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let key_name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        // Skip the "Names" subkey — we only want RID keys (hex strings).
        if key_name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Parse RID from hex key name (e.g., "000001F4" → 500).
        let rid = match u32::from_str_radix(&key_name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Try to find the username from the Names subkey.
        let username = if names_key != 0 {
            find_name_for_rid(reader, flat_base, names_key, rid)
        } else {
            format!("RID-{}", rid)
        };

        // Read the F value for account metadata.
        // F value is at the Values list of this key.
        let (account_flags, last_login_time, last_password_change, account_created, login_count) =
            read_f_value(reader, flat_base, key_addr);

        let is_disabled = (account_flags & UAC_ACCOUNT_DISABLED) != 0;
        let has_empty_password = (account_flags & UAC_PASSWORD_NOT_REQUIRED) != 0;
        let is_suspicious = classify_sam_user(&username, rid, account_flags);

        users.push(SamUserInfo {
            username,
            rid,
            account_flags,
            is_disabled,
            has_empty_password,
            last_login_time,
            last_password_change,
            account_created,
            login_count,
            is_suspicious,
        });
    }

    Ok(users)
}

/// Read a cell address from the flat storage base + cell offset.
fn read_cell_addr<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    cell_off: u32,
) -> u64 {
    // Cell data starts 4 bytes after the cell offset (cell size header).
    let addr = flat_base + (cell_off as u64) + 4;
    // Verify we can read from this address.
    match reader.read_bytes(addr, 2) {
        Ok(bytes) if bytes.len() == 2 => addr,
        _ => 0,
    }
}

/// Find a subkey by name under a parent _CM_KEY_NODE.
fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
    let subkey_count: u32 = match reader.read_bytes(parent_addr + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    if subkey_count == 0 || subkey_count > 4096 {
        return 0;
    }

    let list_off: u32 = match reader.read_bytes(parent_addr + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    let list_addr = read_cell_addr(reader, flat_base, list_off);
    if list_addr == 0 {
        return 0;
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return 0,
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return 0,
    };

    for i in 0..count.min(4096) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
            _ => return 0,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        if name.eq_ignore_ascii_case(target_name) {
            return key_addr;
        }
    }

    0
}

/// Find the username associated with a RID from the Names subkey.
fn find_name_for_rid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    names_key: u64,
    target_rid: u32,
) -> String {
    // Under Names, each subkey's name IS the username, and the default value
    // type encodes the RID. We read each subkey name and check the value type.
    let subkey_count: u32 = match reader.read_bytes(names_key + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return format!("RID-{}", target_rid),
    };

    if subkey_count == 0 || subkey_count > 4096 {
        return format!("RID-{}", target_rid);
    }

    let list_off: u32 = match reader.read_bytes(names_key + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return format!("RID-{}", target_rid),
    };

    let list_addr = read_cell_addr(reader, flat_base, list_off);
    if list_addr == 0 {
        return format!("RID-{}", target_rid);
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return format!("RID-{}", target_rid),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return format!("RID-{}", target_rid),
    };

    for i in 0..count.min(4096) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
            _ => break,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        // The default value's type field encodes the RID.
        // In the Names key, each name key has a single default value
        // whose data type is the RID (a Windows registry trick).
        // The value list offset is at _CM_KEY_NODE + 0x2C, count at +0x28.
        let val_count: u32 = match reader.read_bytes(key_addr + 0x28, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        if val_count == 0 {
            continue;
        }

        let val_list_off: u32 = match reader.read_bytes(key_addr + 0x2C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
        if val_list_addr == 0 {
            continue;
        }

        // Read first value offset.
        let val_off: u32 = match reader.read_bytes(val_list_addr, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_addr = read_cell_addr(reader, flat_base, val_off);
        if val_addr == 0 {
            continue;
        }

        // _CM_KEY_VALUE: Type at offset 0x10 (u32).
        let val_type: u32 = match reader.read_bytes(val_addr + 0x10, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        if val_type == target_rid {
            // Read the key name as the username.
            let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
                Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
                _ => continue,
            };

            if name_len > 0 && name_len <= 256 {
                if let Ok(bytes) = reader.read_bytes(key_addr + 0x4C, name_len as usize) {
                    return String::from_utf8_lossy(&bytes).to_string();
                }
            }
        }
    }

    format!("RID-{}", target_rid)
}

/// Read account metadata from the F value of a user's RID key.
/// Returns (flags, last_login, last_pw_change, created, login_count).
fn read_f_value<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
) -> (u32, u64, u64, u64, u32) {
    let default = (0u32, 0u64, 0u64, 0u64, 0u32);

    // Read value count and list.
    let val_count: u32 = match reader.read_bytes(key_addr + 0x28, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return default,
    };

    if val_count == 0 {
        return default;
    }

    let val_list_off: u32 = match reader.read_bytes(key_addr + 0x2C, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return default,
    };

    let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
    if val_list_addr == 0 {
        return default;
    }

    // Scan values for "F".
    for v in 0..val_count.min(64) {
        let val_off: u32 = match reader.read_bytes(val_list_addr + (v as u64) * 4, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_addr = read_cell_addr(reader, flat_base, val_off);
        if val_addr == 0 {
            continue;
        }

        // _CM_KEY_VALUE: NameLength at 0x02 (u16), Name at 0x18.
        let vname_len: u16 = match reader.read_bytes(val_addr + 0x02, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if vname_len != 1 {
            continue;
        }

        let vname = match reader.read_bytes(val_addr + 0x18, 1) {
            Ok(bytes) if !bytes.is_empty() => bytes[0],
            _ => continue,
        };

        if vname != b'F' {
            continue;
        }

        // F value data: DataLength at 0x08 (u32), DataOffset at 0x0C (u32).
        let data_len: u32 = match reader.read_bytes(val_addr + 0x08, 4) {
            Ok(bytes) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0x7FFFFFFF
            }
            _ => return default,
        };

        if data_len < 0x38 {
            return default;
        }

        let data_off: u32 = match reader.read_bytes(val_addr + 0x0C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => return default,
        };

        let data_addr = read_cell_addr(reader, flat_base, data_off);
        if data_addr == 0 {
            return default;
        }

        // F value layout:
        // 0x08: last login time (FILETIME, 8 bytes)
        // 0x18: last password change (FILETIME, 8 bytes)
        // 0x20: account creation time (FILETIME, 8 bytes)
        // 0x30: account flags (u16)
        // 0x38: login count (u16)
        let last_login = match reader.read_bytes(data_addr + 0x08, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let last_pw = match reader.read_bytes(data_addr + 0x18, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let created = match reader.read_bytes(data_addr + 0x20, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let flags_raw: u16 = match reader.read_bytes(data_addr + 0x30, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => 0,
        };

        let login_cnt: u16 = match reader.read_bytes(data_addr + 0x38, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => 0,
        };

        return (
            flags_raw as u32,
            last_login,
            last_pw,
            created,
            login_cnt as u32,
        );
    }

    default
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_struct("_CM_KEY_NODE", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No SAM hive address → empty Vec.
    #[test]
    fn walk_sam_users_no_hive() {
        let reader = make_reader();
        let result = walk_sam_users(&reader, 0).unwrap();
        assert!(result.is_empty());
    }

    /// Non-zero but unmapped hive address → empty Vec (graceful degradation).
    #[test]
    fn walk_sam_users_unmapped_hive_graceful() {
        let reader = make_reader();
        let result = walk_sam_users(&reader, 0xDEAD_BEEF_0000).unwrap();
        assert!(result.is_empty());
    }

    // ── classify_sam_user exhaustive tests ───────────────────────────

    /// Normal Administrator account is not suspicious.
    #[test]
    fn classify_sam_normal_admin() {
        assert!(!classify_sam_user("Administrator", 500, UAC_NORMAL_ACCOUNT));
    }

    /// "admin" (lowercase) as RID-500 name is also benign.
    #[test]
    fn classify_sam_admin_lowercase_benign() {
        assert!(!classify_sam_user("admin", 500, UAC_NORMAL_ACCOUNT));
    }

    /// Renamed Administrator (RID 500) is suspicious.
    #[test]
    fn classify_sam_renamed_admin() {
        assert!(classify_sam_user("notadmin", 500, UAC_NORMAL_ACCOUNT));
    }

    /// RID 500 with weird name is suspicious regardless of flags.
    #[test]
    fn classify_sam_rid500_weird_name_suspicious() {
        assert!(classify_sam_user("svc_admin", 500, 0));
    }

    /// Hidden account ending with '$' is suspicious.
    #[test]
    fn classify_sam_hidden_account() {
        assert!(classify_sam_user("backdoor$", 1001, UAC_NORMAL_ACCOUNT));
    }

    /// Dollar-sign account that IS a machine$ account is benign.
    #[test]
    fn classify_sam_machine_account_benign() {
        assert!(!classify_sam_user(
            "WORKSTATION$MACHINE$",
            1000,
            UAC_NORMAL_ACCOUNT
        ));
    }

    /// Dollar-sign accounts with other suffixes are suspicious.
    #[test]
    fn classify_sam_dollar_not_machine_suspicious() {
        assert!(classify_sam_user("evil$", 1005, UAC_NORMAL_ACCOUNT));
    }

    /// Password-not-required on normal account is suspicious.
    #[test]
    fn classify_sam_no_password() {
        assert!(classify_sam_user(
            "testuser",
            1002,
            UAC_NORMAL_ACCOUNT | UAC_PASSWORD_NOT_REQUIRED
        ));
    }

    /// Password-not-required on non-normal account is NOT suspicious by this flag alone.
    #[test]
    fn classify_sam_no_password_non_normal_not_suspicious() {
        // UAC_PASSWORD_NOT_REQUIRED without UAC_NORMAL_ACCOUNT
        assert!(!classify_sam_user("svcuser", 1010, UAC_PASSWORD_NOT_REQUIRED));
    }

    /// Known attack tool account names are suspicious.
    #[test]
    fn classify_sam_known_bad_names() {
        assert!(classify_sam_user("backdoor", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("hacker", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("test123", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("svc_admin", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("defaultaccount0", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("support_388945a0", 1003, UAC_NORMAL_ACCOUNT));
    }

    /// Known bad names are case-insensitive.
    #[test]
    fn classify_sam_known_bad_name_case_insensitive() {
        assert!(classify_sam_user("Backdoor", 1003, UAC_NORMAL_ACCOUNT));
        assert!(classify_sam_user("HACKER", 1003, UAC_NORMAL_ACCOUNT));
    }

    /// Regular user account is not suspicious.
    #[test]
    fn classify_sam_regular_user() {
        assert!(!classify_sam_user("john.doe", 1004, UAC_NORMAL_ACCOUNT));
    }

    /// Regular user with RID > 500 and normal flags is benign.
    #[test]
    fn classify_sam_normal_user_benign() {
        assert!(!classify_sam_user("alice", 1006, UAC_NORMAL_ACCOUNT));
    }

    /// Empty username is not suspicious.
    #[test]
    fn classify_sam_empty_benign() {
        assert!(!classify_sam_user("", 0, 0));
    }

    /// Empty username with suspicious flags is still benign (early return).
    #[test]
    fn classify_sam_empty_with_flags_benign() {
        assert!(!classify_sam_user(
            "",
            500,
            UAC_NORMAL_ACCOUNT | UAC_PASSWORD_NOT_REQUIRED
        ));
    }

    // ── UAC constant correctness ───────────────────────────────────────

    #[test]
    fn uac_constants_correct_values() {
        assert_eq!(UAC_ACCOUNT_DISABLED, 0x0001);
        assert_eq!(UAC_LOCKOUT, 0x0010);
        assert_eq!(UAC_PASSWORD_NOT_REQUIRED, 0x0020);
        assert_eq!(UAC_NORMAL_ACCOUNT, 0x0200);
    }

    // ── SamUserInfo construction ──────────────────────────────────────

    #[test]
    fn sam_user_info_fields() {
        let info = SamUserInfo {
            username: "alice".to_string(),
            rid: 1001,
            account_flags: UAC_NORMAL_ACCOUNT,
            is_disabled: false,
            has_empty_password: false,
            last_login_time: 132_000_000_000_000_000,
            last_password_change: 131_000_000_000_000_000,
            account_created: 130_000_000_000_000_000,
            login_count: 42,
            is_suspicious: false,
        };
        assert_eq!(info.username, "alice");
        assert_eq!(info.rid, 1001);
        assert_eq!(info.login_count, 42);
        assert!(!info.is_disabled);
        assert!(!info.has_empty_password);
        assert!(!info.is_suspicious);
    }

    #[test]
    fn sam_user_info_disabled_flag() {
        let flags_val = UAC_ACCOUNT_DISABLED | UAC_NORMAL_ACCOUNT;
        let is_disabled = (flags_val & UAC_ACCOUNT_DISABLED) != 0;
        assert!(is_disabled);
    }

    // ── SamUserInfo serialization ─────────────────────────────────────

    #[test]
    fn sam_user_info_serialization() {
        let info = SamUserInfo {
            username: "testuser".to_string(),
            rid: 500,
            account_flags: UAC_NORMAL_ACCOUNT,
            is_disabled: false,
            has_empty_password: false,
            last_login_time: 0,
            last_password_change: 0,
            account_created: 0,
            login_count: 1,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"rid\":500"));
        assert!(json.contains("\"is_suspicious\":true"));
    }

    // ── MAX_USERS constant ────────────────────────────────────────────

    #[test]
    fn max_users_constant_reasonable() {
        assert!(MAX_USERS > 0);
        assert!(MAX_USERS <= 65536);
    }

    // ── walk_sam_users body coverage ─────────────────────────────────
    //
    // These tests exercise the walk body past the hive_addr=0 guard by
    // providing minimal synthetic physical memory.  All addresses are
    // kept well below 16 MB so they fit inside the SyntheticPhysMem
    // image that PageTableBuilder allocates.

    /// Hive at a mapped vaddr whose page contains a non-zero BaseBlock
    /// pointer.  Navigation fails gracefully once the BaseBlock page
    /// returns a zero root_cell_off → empty Vec.
    #[test]
    fn walk_sam_users_mapped_hive_base_block_zero_root_cell() {
        // Layout (all virtual = physical for simplicity):
        //   hive_vaddr  = 0x0020_0000  (mapped → paddr 0x0020_0000)
        //   base_block  = 0x0021_0000  (mapped → paddr 0x0021_0000)
        //
        // At hive_vaddr + 0x10 (BaseBlock offset) we write base_block.
        // At base_block  + 0x24 (root_cell_off) we write 0 → early return.
        let hive_vaddr: u64 = 0x0020_0000;
        let hive_paddr: u64 = 0x0020_0000;
        let base_block: u64 = 0x0021_0000;
        let base_block_paddr: u64 = 0x0021_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell_off at offset 0x24 = 0 → early return
        bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_sam_users(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty(), "zero root_cell_off should return empty Vec");
    }

    /// Hive with a non-zero root_cell_off exercises the storage/flat_base
    /// code path and then cell navigation, which fails (no hbin data) →
    /// empty Vec.
    #[test]
    fn walk_sam_users_mapped_hive_nonzero_root_cell_no_hbin() {
        let hive_vaddr: u64 = 0x0030_0000;
        let hive_paddr: u64 = 0x0030_0000;
        let base_block: u64 = 0x0031_0000;
        let base_block_paddr: u64 = 0x0031_0000;

        let mut hive_page = vec![0u8; 0x1000];
        // BaseBlock at offset 0x10
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        // Storage at offset 0x30 = 0 → flat_base = base_block + 0x1000
        hive_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        // root_cell_off at 0x24 = 0x20 (non-zero, non-MAX)
        bb_page[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // flat_base = base_block + 0x1000 = 0x0032_0000; cell addr not mapped
        // → read_cell_addr returns 0 → empty Vec
        let result = walk_sam_users(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }

    /// Exercises the Storage fallback: Storage pointer is non-zero.
    /// Cell navigation fails because the hbin area is not fully mapped.
    #[test]
    fn walk_sam_users_storage_ptr_nonzero_graceful() {
        let hive_vaddr: u64 = 0x0040_0000;
        let hive_paddr: u64 = 0x0040_0000;
        let base_block: u64 = 0x0041_0000;
        let base_block_paddr: u64 = 0x0041_0000;
        let storage_ptr: u64 = 0x0042_0000;

        let mut hive_page = vec![0u8; 0x1000];
        hive_page[0x10..0x18].copy_from_slice(&base_block.to_le_bytes());
        // Storage at 0x30 = non-zero storage_ptr
        hive_page[0x30..0x38].copy_from_slice(&storage_ptr.to_le_bytes());

        let mut bb_page = vec![0u8; 0x1000];
        bb_page[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(base_block, base_block_paddr, flags::WRITABLE)
            .write_phys(base_block_paddr, &bb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // flat_base = storage_ptr (not mapped) → read_cell_addr → 0 → empty
        let result = walk_sam_users(&reader, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }
}
