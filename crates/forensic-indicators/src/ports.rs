/// Well-known suspicious/attacker-favoured TCP/UDP ports.
pub const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit default
    50050, // Cobalt Strike teamserver
    31337, // eleet / Back Orifice
    1337,  // leet
    8888,  // common C2 / jupyter abuse
    9999,  // common C2
    4445,  // Metasploit variant
    1234,  // common test/C2 port
    6666,  // IRC / C2
    7777,  // common C2
    8080,  // HTTP proxy / C2 (beyond the HTTP norm)
    9001,  // Tor relay
    9030,  // Tor directory
    4899,  // Radmin
    5900,  // VNC
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    47001, // WinRM alt
];

/// Returns `true` if `port` appears in [`SUSPICIOUS_PORTS`].
pub fn is_suspicious_port(port: u16) -> bool {
    SUSPICIOUS_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Positive cases — ports that MUST be flagged
    #[test]
    fn detects_metasploit_default_4444() {
        assert!(is_suspicious_port(4444), "4444 (Metasploit default) should be suspicious");
    }

    #[test]
    fn detects_cobalt_strike_50050() {
        assert!(is_suspicious_port(50050), "50050 (Cobalt Strike teamserver) should be suspicious");
    }

    #[test]
    fn detects_eleet_31337() {
        assert!(is_suspicious_port(31337), "31337 (eleet) should be suspicious");
    }

    #[test]
    fn detects_tor_9001() {
        assert!(is_suspicious_port(9001), "9001 (Tor relay) should be suspicious");
    }

    #[test]
    fn detects_winrm_5985() {
        assert!(is_suspicious_port(5985), "5985 (WinRM) should be suspicious");
    }

    // Negative cases — common benign ports
    #[test]
    fn allows_port_80() {
        assert!(!is_suspicious_port(80), "port 80 (HTTP) should not be suspicious");
    }

    #[test]
    fn allows_port_443() {
        assert!(!is_suspicious_port(443), "port 443 (HTTPS) should not be suspicious");
    }

    // Edge / boundary cases
    #[test]
    fn port_zero_not_suspicious() {
        assert!(!is_suspicious_port(0), "port 0 should not be flagged");
    }

    #[test]
    fn port_65535_not_suspicious() {
        assert!(!is_suspicious_port(65535), "port 65535 (max) should not be flagged by default");
    }

    // Constant membership checks
    #[test]
    fn suspicious_ports_contains_4444() {
        assert!(SUSPICIOUS_PORTS.contains(&4444));
    }

    #[test]
    fn suspicious_ports_contains_9030() {
        assert!(SUSPICIOUS_PORTS.contains(&9030), "9030 (Tor dir) missing");
    }

    #[test]
    fn suspicious_ports_contains_radmin_4899() {
        assert!(SUSPICIOUS_PORTS.contains(&4899), "4899 (Radmin) missing");
    }
}
