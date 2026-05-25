//! Config types parsed from the INI config file.

use std::path::{Path, PathBuf};

use configparser::ini::Ini;

pub struct BridgeConfig {
    pub config_file: PathBuf,
    pub identity_path: String,
    pub db_path: String,
    pub rns_config: Option<String>,
    pub rns_tcp_host: Option<String>,
    pub rns_tcp_port: Option<u16>,
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

pub struct FcmConfig {
    pub service_account_key: String,
    pub app_package_name: String,
    pub token_ttl: u64,
}

pub struct Config {
    pub bridge: BridgeConfig,
    pub fcm: FcmConfig,
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

        let get_b = |key: &str| ini.get("bridge", key);
        let identity_path = expand_home(
            get_b("identity_path").unwrap_or_else(|| "~/.rfed-fcm/identity".to_string()),
        );
        let db_path = expand_home(
            get_b("db_path").unwrap_or_else(|| "~/.rfed-fcm/tokens.db".to_string()),
        );
        let rns_config = get_b("rns_config").map(expand_home);
        let rns_tcp_host = get_b("rns_tcp_host");
        let rns_tcp_port = get_b("rns_tcp_port").and_then(|v| v.parse::<u16>().ok());
        let rns_tcp_endpoints = get_b("rns_tcp_endpoints")
            .map(|v| parse_endpoints(&v))
            .unwrap_or_default();

        let get_f = |key: &str| ini.get("fcm", key);
        let service_account_key = expand_home(
            get_f("service_account_key")
                .ok_or("fcm.service_account_key is required")?,
        );
        let app_package_name = get_f("app_package_name")
            .ok_or("fcm.app_package_name is required")?;
        let token_ttl = get_f("token_ttl")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000)
            .clamp(60, 3600);

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
            fcm: FcmConfig {
                service_account_key,
                app_package_name,
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

fn parse_endpoints(raw: &str) -> Vec<(String, u16)> {
    raw.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let (host, port) = part.rsplit_once(':')?;
            let port: u16 = port.trim().parse().ok()?;
            let host = host.trim();
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{parse_endpoints, BridgeConfig, Config};

    #[test]
    fn parses_comma_separated_endpoints() {
        let v = parse_endpoints("rns.beleth.net:4242, 192.0.2.1:4242 , example.org:9999");
        assert_eq!(
            v,
            vec![
                ("rns.beleth.net".to_string(), 4242),
                ("192.0.2.1".to_string(), 4242),
                ("example.org".to_string(), 9999),
            ]
        );
    }

    #[test]
    fn detects_native_reticulum_sections_in_main_config() {
        let cfg = Config::parse(
            "[reticulum]\n  share_instance = no\n\n[interfaces]\n\n  [[Backbone]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = rns.example.org\n    target_port = 4242\n\n[bridge]\n  identity_path = ~/.rfed-fcm/identity\n\n[fcm]\n  service_account_key = /tmp/service-account.json\n  app_package_name = com.example.app\n",
            Path::new("/tmp/fcm_bridge.conf"),
        )
        .unwrap();

        assert_eq!(cfg.bridge.config_file, PathBuf::from("/tmp/fcm_bridge.conf"));
        assert!(cfg.bridge.has_native_reticulum_config());
        assert!(!cfg.bridge.has_legacy_tcp_config());
        assert_eq!(cfg.fcm.app_package_name, "com.example.app");
    }

    #[test]
    fn shipped_sample_uses_native_reticulum_format() {
        let cfg = Config::parse(include_str!("../sample.conf"), Path::new("sample.conf")).unwrap();
        assert!(cfg.bridge.has_native_reticulum_config());
        assert!(!cfg.bridge.has_legacy_tcp_config());
        assert_eq!(cfg.fcm.app_package_name, "com.newendian.retichat");
    }

    #[test]
    fn merges_legacy_single_endpoint_without_duplication() {
        let bridge = BridgeConfig {
            config_file: PathBuf::from("/tmp/fcm_bridge.conf"),
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