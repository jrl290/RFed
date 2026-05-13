//! Quick standalone test: register a notify relay with rfed.
//!
//! 1. Boots Reticulum against the RPi rnsd at 192.168.2.107:4242.
//! 2. Waits for a path to rfed.notify (69e52bf1b9abf1e894ef1e492fd1a117).
//! 3. Creates a Link, identifies with a throwaway identity.
//! 4. Sends /rfed/notify/register with Retichat's hash as the relay dest.
//! 5. Prints the boolean response from rfed.
//!
//! Run with:
//!   cargo run --example notify_register --

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, MODE_AES256_CBC, register_runtime_link_handle};
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

const RFED_NOTIFY_HASH: &str = "69e52bf1b9abf1e894ef1e492fd1a117";
const RETICHAT_HASH: &str     = "31327c7aa74e5f374b12bac5c6b636ed";
const REGISTER_PATH: &str     = "/rfed/notify/register";

fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

fn main() {
    let config_dir = home_dir().join("tmp/rfed-notify-test/_rns");
    fs::create_dir_all(&config_dir).expect("create config dir");

    // Write a minimal RNS config pointing at the RPi rnsd.
    let config_path = config_dir.join("config");
    if !config_path.exists() {
        fs::write(
            &config_path,
            r#"[reticulum]
  enable_transport = false
  share_instance   = false
  shared_instance_port = 0
  instance_control_port = 0

[[RPi rnsd]]
  type = TCPClientInterface
  enabled = true
  target_host = 192.168.2.107
  target_port = 4242
"#,
        )
        .expect("write config");
    }

    eprintln!("[test] Initialising Reticulum (config={})...", config_dir.display());
    Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
        .expect("Reticulum init");

    let notify_hash = reticulum_rust::decode_hex(RFED_NOTIFY_HASH)
        .expect("decode rfed.notify hash");

    // Create (or load) a throwaway identity for this test.
    let id_path = config_dir.join("test_identity");
    let our_identity = if id_path.exists() {
        Identity::from_file(&id_path).expect("load identity")
    } else {
        let id = Identity::new(true);
        let _ = id.to_file(&id_path);
        id
    };
    let our_hash = our_identity
        .hash
        .as_ref()
        .map(|h| reticulum_rust::hexrep(h, false))
        .unwrap_or_default();
    eprintln!("[test] Our identity hash: {}", our_hash);

    // Wait for path to rfed.notify.
    eprintln!("[test] Requesting path to rfed.notify ({RFED_NOTIFY_HASH})...");
    for attempt in 1..=30 {
        if Transport::has_path(&notify_hash) {
            eprintln!("[test] Path found after {attempt} attempts");
            break;
        }
        Transport::request_path(&notify_hash, None, None, None, None);
        thread::sleep(Duration::from_secs(2));
        if attempt == 30 {
            eprintln!("[test] FAIL: could not find path after 60 s");
            std::process::exit(1);
        }
    }

    // Recall rfed's identity (must have heard its announce).
    let rfed_identity = match Identity::recall(&notify_hash) {
        Some(id) => id,
        None => {
            eprintln!("[test] FAIL: rfed.notify identity not in known-destinations table");
            std::process::exit(1);
        }
    };
    eprintln!("[test] rfed.notify identity recalled OK");

    // Build outbound destination → link.
    let dest = Destination::new_outbound(
        Some(rfed_identity),
        DestinationType::Single,
        "rfed".to_string(),
        vec!["notify".to_string()],
    )
    .expect("create destination");

    let link = Link::new_outbound(dest, MODE_AES256_CBC).expect("create link");
    let link_handle = LinkHandle::spawn(link);

    let done = Arc::new(AtomicBool::new(false));

    // Set up the link_established callback.
    {
        let identity_for_cb = our_identity.clone();
        let done_est = Arc::clone(&done);
        let lh_est = link_handle.clone();

        link_handle.set_link_established_callback(Some(Arc::new(move |_la| {
            eprintln!("[test] Link established!");

            // Identify ourselves so the remote side has our identity.
            match lh_est.identify(&identity_for_cb) {
                Ok(()) => eprintln!("[test] identify sent OK"),
                Err(e) => eprintln!("[test] identify error: {e}"),
            }

            // Give rfed time to process the identify proof before sending request.
            std::thread::sleep(std::time::Duration::from_secs(3));

            // Encode the relay hash as a msgpack string (what rfed expects).
            let payload = rmp_serde::to_vec(RETICHAT_HASH).unwrap_or_default();

            let done_ok = Arc::clone(&done_est);
            let done_fail = Arc::clone(&done_est);

            let response_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |receipt: RequestReceipt| {
                    eprintln!("[test] RESPONSE received!");
                    if let Some(ref data) = receipt.response {
                        eprintln!("[test] Raw response ({} bytes): {:?}", data.len(), data);
                        // rfed returns msgpack bool; transport may wrap in bin.
                        // Try direct bool first, then unwrap bin layer.
                        let result = rmp_serde::from_slice::<bool>(data)
                            .or_else(|_| {
                                // bin8(1, [byte]) → unwrap the inner byte
                                if data.len() == 3 && data[0] == 0xC4 && data[1] == 1 {
                                    rmp_serde::from_slice::<bool>(&data[2..])
                                } else {
                                    Err(rmp_serde::decode::Error::Syntax("not bool".into()))
                                }
                            });
                        match result {
                            Ok(true) => eprintln!("[test] SUCCESS: rfed accepted registration"),
                            Ok(false) => eprintln!("[test] REJECTED: rfed returned false (caller identity not recognized, or policy denied)"),
                            Err(e) => eprintln!(
                                "[test] Response decode error: {e}  raw={:?}",
                                data
                            ),
                        }
                    } else {
                        eprintln!("[test] Response had no data");
                    }
                    done_ok.store(true, Ordering::Relaxed);
                });

            let failed_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |_receipt: RequestReceipt| {
                    eprintln!("[test] FAILED: request timed out or was rejected");
                    done_fail.store(true, Ordering::Relaxed);
                });

            // Send the request on the link.
            match lh_est.request(
                REGISTER_PATH.to_string(),
                payload,
                Some(response_cb),
                Some(failed_cb),
                None,
            ) {
                Ok(_) => eprintln!("[test] Request sent to {REGISTER_PATH}"),
                Err(e) => {
                    eprintln!("[test] Request send error: {e}");
                    done_est.store(true, Ordering::Relaxed);
                }
            }
        })));

        // Set up link_closed callback.
        let done_closed = Arc::clone(&done);
        link_handle.set_link_closed_callback(Some(Arc::new(move |_| {
            eprintln!("[test] Link closed");
            done_closed.store(true, Ordering::Relaxed);
        })));

        // Initiate the link handshake.
        if let Err(e) = link_handle.initiate() {
            eprintln!("[test] FAIL: link initiate error: {e}");
            std::process::exit(1);
        }
    }
    register_runtime_link_handle(link_handle.clone());
    eprintln!("[test] Link handshake initiated, waiting for establishment...");

    // Wait for completion (up to 60 s).
    for _ in 0..60 {
        if done.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !done.load(Ordering::Relaxed) {
        eprintln!("[test] TIMEOUT: no response after 60 s");
    }

    // Teardown.
    link_handle.teardown();
    thread::sleep(Duration::from_millis(500));
    eprintln!("[test] Done.");
}