//! rfed APNs Push Bridge — Rust binary
//!
//! Connects the rfed notify system to Apple APNs.
//!
//! Usage:
//!   apns_bridge [--config apns_bridge.conf] [--debug]
//!
//! The config file is the same INI format as the Python version:
//!   [bridge]  identity_path, db_path, rns_config | rns_tcp_host/port
//!   [apns]    key_file, key_id, team_id, bundle_id, sandbox, push_type, ...
//!
//! Compile for Linux x86_64 (shared hosting):
//!   cargo build --release -p apns-bridge --target x86_64-unknown-linux-musl

mod apns;
mod bridge;
mod config;
mod db;
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
                println!("rfed APNs Push Bridge\n");
                println!("Usage: apns_bridge [--config <file>] [--debug]");
                println!("       apns_bridge --help\n");
                println!("  --config <file>  Path to INI config file (default: ./apns_bridge.conf)");
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

    // ── Logging ───────────────────────────────────────────────────────────────
    let log_level = if debug { "debug" } else { "info" };
    env_logger::Builder::new()
        .filter_level(log_level.parse().unwrap())
        .format_timestamp_secs()
        .init();

    // ── Config ────────────────────────────────────────────────────────────────
    let config_file = Path::new(&config_path);
    if !config_file.exists() {
        error!(
            "Config file not found: {}\nCopy apns_bridge.conf.example → apns_bridge.conf and fill in.",
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

    // ── Token database ────────────────────────────────────────────────────────
    let db = match db::TokenDB::open(Path::new(&cfg.bridge.db_path)) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to open token database at {}: {e}", cfg.bridge.db_path);
            process::exit(1);
        }
    };

    // ── APNs sender ───────────────────────────────────────────────────────────
    let key_file = Path::new(&cfg.apns.key_file);
    if !key_file.exists() {
        error!("APNs key file not found: {}", cfg.apns.key_file);
        process::exit(1);
    }
    let apns = match apns::ApnsSender::new(&cfg.apns, key_file) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to initialise APNs sender: {e}");
            process::exit(1);
        }
    };

    info!("Starting rfed APNs Push Bridge");
    info!("Config:   {config_path}");
    info!("Database: {}", cfg.bridge.db_path);
    info!("APNs:     bundle={} sandbox={}", cfg.apns.bundle_id, cfg.apns.sandbox);

    // ── Run ───────────────────────────────────────────────────────────────────
    if let Err(e) = bridge::run(&cfg.bridge, db, apns) {
        error!("Bridge error: {e}");
        process::exit(1);
    }
}

fn default_config_path() -> String {
    // Look for apns_bridge.conf next to the binary, then current directory
    let exe = std::env::current_exe().unwrap_or_default();
    let sibling = exe.with_file_name("apns_bridge.conf");
    if sibling.exists() {
        return sibling.to_string_lossy().to_string();
    }
    "apns_bridge.conf".to_string()
}
