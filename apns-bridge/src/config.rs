//! Config types parsed from the INI config file.

use std::path::{Path, PathBuf};

use configparser::ini::Ini;

/// Configuration for the `[bridge]` section.
pub struct BridgeConfig {
    pub config_file:       PathBuf,
    pub identity_path:     String,
    pub db_path:           String,
    /// Optional external Reticulum config directory. Kept for compatibility,
    /// but the preferred format is to place `[reticulum]` and `[interfaces]`
    /// directly in the main bridge config file just like rfed/rnsd.
    pub rns_config:        Option<String>,
    /// Legacy bridge-only transport keys. New configs should use native
    /// Reticulum `[[Interface]]` sections under `[interfaces]` instead.
    pub rns_tcp_host:      Option<String>,
    pub rns_tcp_port:      Option<u16>,
    pub rns_tcp_endpoints: Vec<(String, u16)>,
    pub has_reticulum_section: bool,
    pub has_interfaces_section: bool,
}

impl BridgeConfig {
    pub fn has_native_reticulum_config(&self) -> bool {
        self.has_reticulum_section && self.has_interfaces_section
    }

    pub fn has_legacy_tcp_config(&self) -> bool {
        self.rns_tcp_host.is_some() || self.rns_tcp_port.is_some() || !self.rns_tcp_endpoints.is_empty()
    }

    pub fn legacy_tcp_endpoints(&self) -> Vec<(String, u16)> {
        let mut endpoints = self.rns_tcp_endpoints.clone();
        if let (Some(host), Some(port)) = (&self.rns_tcp_host, self.rns_tcp_port) {
            if !endpoints.iter().any(|(h, p)| h == host && *p == port) {
                endpoints.push((host.clone(), port));
            }
        }
        endpoints
    }
}

/// Configuration for the `[apns]` section.
pub struct ApnsConfig {
    pub key_file:    String,
    pub key_id:      String,
    pub team_id:     String,
    pub bundle_id:   String,
    pub sandbox:     bool,
    pub push_type:   String,
    pub alert_title: String,
    pub alert_body:  String,
    pub token_ttl:   u64,
}

pub struct Config {
    pub bridge: BridgeConfig,
    pub apns:   ApnsConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file: {e}"))?;

        Self::parse(&text, path)
    }

    fn parse(text: &str, path: &Path) -> Result<Self, String> {
        let mut ini = Ini::new();
        ini.read(text.to_string())
            .map_err(|e| format!("cannot parse config file: {e}"))?;

        let has_reticulum_section = has_section_header(text, "reticulum");
        let has_interfaces_section = has_section_header(text, "interfaces");

        // ── [bridge] ──────────────────────────────────────────────────────────
        let get_b = |key: &str| ini.get("bridge", key);
        let identity_path = expand_home(
            get_b("identity_path").unwrap_or_else(|| "~/.rfed-apns/identity".to_string()),
        );
        let db_path = expand_home(
            get_b("db_path").unwrap_or_else(|| "~/.rfed-apns/tokens.db".to_string()),
        );
        let rns_config = get_b("rns_config").map(expand_home);
        let rns_tcp_host = get_b("rns_tcp_host");
        let rns_tcp_port = get_b("rns_tcp_port")
            .and_then(|v| v.parse::<u16>().ok());
        let rns_tcp_endpoints = get_b("rns_tcp_endpoints")
            .map(|v| parse_endpoints(&v))
            .unwrap_or_default();

        // ── [apns] ────────────────────────────────────────────────────────────
        let get_a = |key: &str| ini.get("apns", key);
        let key_file = get_a("key_file")
            .ok_or("apns.key_file is required")?;
        let key_id = get_a("key_id")
            .ok_or("apns.key_id is required")?;
        let team_id = get_a("team_id")
            .ok_or("apns.team_id is required")?;
        let bundle_id = get_a("bundle_id")
            .ok_or("apns.bundle_id is required")?;
        let sandbox = get_a("sandbox")
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        let push_type = get_a("push_type").unwrap_or_else(|| "alert".to_string());
        let alert_title = get_a("alert_title").unwrap_or_else(|| "New message".to_string());
        let alert_body  = get_a("alert_body").unwrap_or_else(|| "You have a new message waiting.".to_string());
        let token_ttl: u64 = get_a("token_ttl")
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);

        Ok(Config {
            bridge: BridgeConfig {
                config_file: path.to_path_buf(),
                identity_path,
                db_path,
                rns_config,
                rns_tcp_host,
                rns_tcp_port,
                rns_tcp_endpoints,
                has_reticulum_section,
                has_interfaces_section,
            },
            apns: ApnsConfig {
                key_file,
                key_id,
                team_id,
                bundle_id,
                sandbox,
                push_type,
                alert_title,
                alert_body,
                token_ttl,
            },
        })
    }
}

fn has_section_header(text: &str, section: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.len() == section.len() + 2
            && line.starts_with('[')
            && line.ends_with(']')
            && line[1..line.len() - 1].eq_ignore_ascii_case(section)
    })
}

fn expand_home(s: String) -> String {
    if s.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &s[1..]);
        }
    }
    s
}

/// Parse a comma-separated list of `host:port` endpoints. Whitespace
/// around entries is ignored. Entries that fail to parse are silently
/// skipped — we want the bridge to keep working with whatever endpoints
/// remain valid rather than refuse to start.
fn parse_endpoints(raw: &str) -> Vec<(String, u16)> {
    raw.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() { return None; }
            let (host, port) = part.rsplit_once(':')?;
            let port: u16 = port.trim().parse().ok()?;
            let host = host.trim();
            if host.is_empty() { return None; }
            Some((host.to_string(), port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Config, BridgeConfig, parse_endpoints};

    #[test]
    fn parses_comma_separated_endpoints() {
        let v = parse_endpoints("rns.beleth.net:4242, 192.0.2.1:4242 ,  example.org:9999");
        assert_eq!(v, vec![
            ("rns.beleth.net".to_string(), 4242),
            ("192.0.2.1".to_string(), 4242),
            ("example.org".to_string(), 9999),
        ]);
    }

    #[test]
    fn skips_malformed_entries() {
        let v = parse_endpoints("good.host:4242, bogus, :4242, host:notaport, host2:1");
        assert_eq!(v, vec![
            ("good.host".to_string(), 4242),
            ("host2".to_string(), 1),
        ]);
    }

    #[test]
    fn empty_string_yields_no_endpoints() {
        assert!(parse_endpoints("").is_empty());
        assert!(parse_endpoints("   ,  ,").is_empty());
    }

    #[test]
    fn detects_native_reticulum_sections_in_main_config() {
        let cfg = Config::parse(
            "[reticulum]\n  share_instance = no\n\n[interfaces]\n\n  [[Backbone]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = rns.example.org\n    target_port = 4242\n\n[bridge]\n  identity_path = ~/.rfed-apns/identity\n\n[apns]\n  key_file = /tmp/key.p8\n  key_id = ABC123\n  team_id = TEAM123\n  bundle_id = com.example.app\n",
            Path::new("/tmp/apns_bridge.conf"),
        )
        .unwrap();

        assert_eq!(cfg.bridge.config_file, PathBuf::from("/tmp/apns_bridge.conf"));
        assert!(cfg.bridge.has_native_reticulum_config());
        assert!(!cfg.bridge.has_legacy_tcp_config());
    }

    #[test]
    fn shipped_sample_uses_native_reticulum_format() {
        let cfg = Config::parse(
            include_str!("../sample.conf"),
            Path::new("sample.conf"),
        )
        .unwrap();

        assert!(cfg.bridge.has_native_reticulum_config());
        assert!(!cfg.bridge.has_legacy_tcp_config());
    }

    #[test]
    fn merges_legacy_single_endpoint_without_duplication() {
        let bridge = BridgeConfig {
            config_file: PathBuf::from("/tmp/apns_bridge.conf"),
            identity_path: String::new(),
            db_path: String::new(),
            rns_config: None,
            rns_tcp_host: Some("rns.example.org".to_string()),
            rns_tcp_port: Some(4242),
            rns_tcp_endpoints: vec![
                ("rns.example.org".to_string(), 4242),
                ("backup.example.org".to_string(), 4242),
            ],
            has_reticulum_section: false,
            has_interfaces_section: false,
        };

        assert_eq!(
            bridge.legacy_tcp_endpoints(),
            vec![
                ("rns.example.org".to_string(), 4242),
                ("backup.example.org".to_string(), 4242),
            ]
        );
    }
}
