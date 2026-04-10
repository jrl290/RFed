//! Config types parsed from the INI config file.

use std::path::Path;

use configparser::ini::Ini;

/// Configuration for the `[bridge]` section.
pub struct BridgeConfig {
    pub identity_path: String,
    pub db_path:       String,
    pub rns_config:    Option<String>,
    pub rns_tcp_host:  Option<String>,
    pub rns_tcp_port:  Option<u16>,
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
        let mut ini = Ini::new();
        ini.load(path.to_str().unwrap_or(""))
            .map_err(|e| format!("cannot read config file: {e}"))?;

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
                identity_path,
                db_path,
                rns_config,
                rns_tcp_host,
                rns_tcp_port,
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

fn expand_home(s: String) -> String {
    if s.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &s[1..]);
        }
    }
    s
}
