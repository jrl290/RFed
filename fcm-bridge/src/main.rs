//! rfed FCM Push Bridge — Rust binary
//!
//! Connects the rfed notify system to Firebase Cloud Messaging.
//!
//! Usage:
//!   fcm_bridge [--config fcm_bridge.conf] [--debug]
//!
//! The config file uses Reticulum's native config layout:
//!   [reticulum]  Reticulum core settings
//!   [interfaces] Native `[[Interface]]` entries (TCPClientInterface, etc.)
//!   [bridge]     identity_path, db_path
//!   [fcm]        service_account_key, app_package_name, token_ttl
//!
//! Legacy bridge-only transport keys (`rns_config`, `rns_tcp_host`,
//! `rns_tcp_port`, `rns_tcp_endpoints`) are still accepted for compatibility,
//! but new configs should define interfaces under `[interfaces]` like rfed/rnsd.
//!
//! Compile for Linux x86_64 (shared hosting):
//!   cargo build --release -p fcm-bridge --target x86_64-unknown-linux-musl

mod bridge;
mod config;
mod db;
mod fcm;
mod jwt;

use std::path::Path;
use std::process;

use log::{error, info};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = default_config_path();
    let mut debug = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    config_path = args[i].clone();
                } else {
                    eprintln!("ERROR: --config requires a path argument");
                    process::exit(1);
                }
            }
            "--debug" | "-d" => debug = true,
            "--help" | "-h" => {
                println!("rfed FCM Push Bridge\n");
                println!("Usage: fcm_bridge [--config <file>] [--debug]");
                println!("       fcm_bridge --help\n");
                println!("  --config <file>  Path to config file (default: ./fcm_bridge.conf)");
                println!("  --debug          Enable debug-level logging");
                process::exit(0);
            }
            other => {
                eprintln!("ERROR: unknown argument: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    let log_level = if debug { "debug" } else { "info" };
    env_logger::Builder::new()
        .filter_level(log_level.parse().unwrap())
        .format_timestamp_secs()
        .init();

    let config_file = Path::new(&config_path);
    if !config_file.exists() {
        error!(
            "Config file not found: {}\nCreate fcm_bridge.conf with [reticulum], [interfaces], [bridge], and [fcm] sections.",
            config_path
        );
        process::exit(1);
    }

    let cfg = match config::Config::load(config_file) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config: {e}");
            process::exit(1);
        }
    };

    let db = match db::TokenDB::open(Path::new(&cfg.bridge.db_path)) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to open token database at {}: {e}", cfg.bridge.db_path);
            process::exit(1);
        }
    };

    let service_account_key = Path::new(&cfg.fcm.service_account_key);
    if !service_account_key.exists() {
        error!("FCM service account key not found: {}", cfg.fcm.service_account_key);
        process::exit(1);
    }

    let fcm = match fcm::FcmSender::new(&cfg.fcm, service_account_key) {
        Ok(sender) => sender,
        Err(e) => {
            error!("Failed to initialise FCM sender: {e}");
            process::exit(1);
        }
    };

    info!("Starting rfed FCM Push Bridge");
    info!("Config:   {config_path}");
    info!("Database: {}", cfg.bridge.db_path);
    info!(
        "FCM:      project={} package={}",
        fcm.project_id(),
        cfg.fcm.app_package_name
    );

    if let Err(e) = bridge::run(&cfg.bridge, db, fcm) {
        error!("Bridge error: {e}");
        process::exit(1);
    }
}

fn default_config_path() -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    let sibling = exe.with_file_name("fcm_bridge.conf");
    if sibling.exists() {
        return sibling.to_string_lossy().to_string();
    }
    "fcm_bridge.conf".to_string()
}