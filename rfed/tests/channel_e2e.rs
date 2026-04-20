//! channel_e2e — End-to-end channel send/receive test.
//!
//! 1. Connects to a running rfed's local TCP server.
//! 2. Receiver identity subscribes to a channel and announces its delivery dest.
//! 3. Sender identity encrypts and sends a channel message.
//! 4. Verifies the receiver decrypts the message correctly.
//!
//! Usage:
//!   rfed_channel_e2e --rfed-port <port> [--channel-name <name>]
//!                    [--message <text>] [--timeout <secs>]
//!
//! Exit 0 = PASS, exit 1 = FAIL.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, MODE_AES256_CBC, register_runtime_link_handle};
use reticulum_rust::packet::{Packet, DATA, NONE, FLAG_UNSET, HEADER_1};
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::{AnnounceHandler, Transport, BROADCAST};

use sha2::{Digest, Sha256};
use reticulum_rust::lxstamper::LXStamper;
use reticulum_rust::identity::full_hash;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Channel crypto ────────────────────────────────────────────────────────────

/// Build the deterministic RNS Identity for a named channel.
/// seed = sha256(name); private_key_bundle = seed || seed
fn make_channel_identity(name: &str) -> Identity {
    let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();
    let mut prv = [0u8; 64];
    prv[..32].copy_from_slice(&seed);
    prv[32..].copy_from_slice(&seed);
    Identity::from_bytes(&prv).expect("channel identity from seed")
}

// ── Wire format helpers ───────────────────────────────────────────────────────

/// Encode as msgpack bin8: 0xc4 | len | bytes
fn mp_bin8(out: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() <= 255, "mp_bin8: data too long");
    out.push(0xc4);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// Subscribe payload: msgpack fixarray-3 [bin(ch_hash), bin(pubkey), bin(sig)]
/// sig = Ed25519(channel_hash) with subscriber's signing key.
fn build_subscribe_payload(identity: &Identity, channel_hash: &[u8]) -> Vec<u8> {
    let pubkey = identity.get_public_key().expect("get_public_key");
    let sig    = identity.sign(channel_hash);
    let mut p  = Vec::new();
    p.push(0x93); // fixarray-3
    mp_bin8(&mut p, channel_hash);
    mp_bin8(&mut p, &pubkey);
    mp_bin8(&mut p, &sig);
    p
}

/// Inner plaintext sent by the sender (matches iOS dispatchDecryptedInner format):
/// sender_hash(16) | ts_ms_be(8) | pubkey(64) | sig(64) | content_utf8
/// sig = Ed25519(sender_hash || ts_ms_be || content)
fn build_inner_plaintext(sender: &Identity, content: &str) -> Vec<u8> {
    let sender_hash = sender.hash.as_ref().expect("sender hash");
    let mut sender_hash_16 = sender_hash.clone();
    sender_hash_16.resize(16, 0);

    let ts_bytes = now_ms().to_be_bytes();
    let content_bytes = content.as_bytes();
    let pubkey = sender.get_public_key().expect("sender pubkey");

    // Signable matches iOS: sender_hash(16) || ts(8) || content
    let mut signable = Vec::new();
    signable.extend_from_slice(&sender_hash_16);
    signable.extend_from_slice(&ts_bytes);
    signable.extend_from_slice(content_bytes);
    let sig = sender.sign(&signable);

    let mut inner = Vec::new();
    inner.extend_from_slice(&sender_hash_16);
    inner.extend_from_slice(&ts_bytes);
    inner.extend_from_slice(&pubkey);
    inner.extend_from_slice(&sig);
    inner.extend_from_slice(content_bytes);
    inner
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    let rfed_port: u16 = arg_value(&args, "--rfed-port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4246);
    let rfed_channel_hash_hex = arg_value(&args, "--rfed-channel-hash");
    let channel_name = arg_value(&args, "--channel-name")
        .unwrap_or_else(|| "public.test.channel".to_string());
    let message = arg_value(&args, "--message")
        .unwrap_or_else(|| "hello from rfed_channel_e2e".to_string());
    let timeout_secs: u64 = arg_value(&args, "--timeout")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    // None = no stamp (rfed stamp_cost absent); Some(0) = stamp present but any stamp accepted;
    // Some(n>0) = compute real PoW stamp.
    let stamp_cost: Option<u32> = arg_value(&args, "--stamp-cost")
        .and_then(|s| s.parse().ok());

    eprintln!("[e2e] rfed port:    {rfed_port}");
    eprintln!("[e2e] channel:      {channel_name}");
    eprintln!("[e2e] message:      {message}");
    eprintln!("[e2e] timeout:      {timeout_secs}s");

    // ── RNS config ─────────────────────────────────────────────────────────
    let base = PathBuf::from("/tmp/rfed_channel_e2e");
    let rns_dir = base.join("_rns");
    fs::create_dir_all(&rns_dir).expect("create rns dir");
    fs::write(
        rns_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = false\n  share_instance = false\n\n\
             [interfaces]\n\
             \n  [[rfed-local]]\n    type = TCPClientInterface\n    enabled = true\n    \
             target_host = 127.0.0.1\n    target_port = {rfed_port}\n"
        ),
    )
    .expect("write rns config");

    eprintln!("[e2e] Initialising Reticulum → 127.0.0.1:{rfed_port}");
    Reticulum::init(Some(rns_dir), None, None, None, false, None).expect("RNS init");
    eprintln!("[e2e] RNS ready — waiting 2s for TCP interface to connect...");
    thread::sleep(Duration::from_secs(2));

    // ── Identities (fresh each run — delete /tmp/rfed_channel_e2e to reset) ─
    let recv_id_path = base.join("recv_identity");
    let receiver = if recv_id_path.exists() {
        Identity::from_file(&recv_id_path).expect("load receiver identity")
    } else {
        let id = Identity::new(true);
        let _ = id.to_file(&recv_id_path);
        id
    };

    let send_id_path = base.join("send_identity");
    let sender = if send_id_path.exists() {
        Identity::from_file(&send_id_path).expect("load sender identity")
    } else {
        let id = Identity::new(true);
        let _ = id.to_file(&send_id_path);
        id
    };

    eprintln!("[e2e] Receiver: {}", hex(receiver.hash.as_ref().expect("recv hash")));
    eprintln!("[e2e] Sender:   {}", hex(sender.hash.as_ref().expect("send hash")));

    // ── Channel identity & hash ─────────────────────────────────────────────
    let ch_id    = make_channel_identity(&channel_name);
    let ch_hash  = ch_id.hash.clone().expect("channel hash");
    eprintln!("[e2e] Channel:  {}", hex(&ch_hash));

    // ── Crypto self-test ────────────────────────────────────────────────────
    {
        let test_plain = b"channel-e2e-selftest";
        let mut enc = make_channel_identity(&channel_name);
        match enc.encrypt(test_plain) {
            Ok(ct) => {
                let mut dec = make_channel_identity(&channel_name);
                match dec.decrypt(&ct) {
                    Ok(got) if got == test_plain => eprintln!("[e2e] channel crypto self-test: OK"),
                    Ok(got) => {
                        eprintln!("[e2e] FAIL: self-test content mismatch: {:?}", got);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("[e2e] FAIL: self-test decrypt failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("[e2e] FAIL: self-test encrypt failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── Receiver delivery destination ───────────────────────────────────────
    let recv_content: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let recv_done = Arc::new(AtomicBool::new(false));

    let recv_content_w = Arc::clone(&recv_content);
    let recv_done_w    = Arc::clone(&recv_done);
    let ch_name_cb     = channel_name.clone();
    // Capture sender hash for filtering (only accept our own test message).
    let expected_sender_hash: Vec<u8> = {
        let mut h = sender.hash.as_ref().expect("sender hash").clone();
        h.resize(16, 0);
        h
    };

    let mut delivery_dest = Destination::new_inbound(
        Some(receiver.clone()),
        DestinationType::Single,
        "rfed".to_string(),
        vec!["delivery".to_string()],
    )
    .expect("create delivery dest");

    delivery_dest.set_packet_callback(Some(Arc::new(
        move |data: &[u8], _pkt: &reticulum_rust::packet::Packet| {
            eprintln!("[recv] delivery packet: {} bytes  first16={}", data.len(),
                hex(&data[..data.len().min(16)]));
            // Payload from rfed fanout: channel_hash(16) | inner_blob_ciphertext
            if data.len() <= 16 {
                eprintln!("[recv] too short, ignoring");
                return;
            }
            let inner_ct = &data[16..];
            let mut ch = make_channel_identity(&ch_name_cb);
            match ch.decrypt(inner_ct) {
                Ok(plain) => {
                    // inner plaintext: sender_hash(16) | ts(8) | pubkey(64) | sig(64) | content
                    let header = 16 + 8 + 64 + 64;
                    if plain.len() <= header {
                        eprintln!("[recv] decrypted but too short ({} bytes)", plain.len());
                        return;
                    }
                    let msg_sender_hash = &plain[..16];
                    // Only accept messages from our own test sender.
                    if msg_sender_hash != expected_sender_hash.as_slice() {
                        eprintln!("[recv] decrypted OK but sender={} (not ours), skipping",
                            hex(msg_sender_hash));
                        return;
                    }
                    let text = String::from_utf8_lossy(&plain[header..]).into_owned();
                    eprintln!("[recv] decrypted from our sender: '{text}'");
                    *recv_content_w.lock().unwrap() = Some(text);
                    recv_done_w.store(true, Ordering::Relaxed);
                }
                Err(e) => eprintln!("[recv] decrypt FAILED (foreign msg?): {e}"),
            }
        },
    )));

    Transport::register_destination(delivery_dest.clone());
    delivery_dest
        .announce(None, false, None, None, true)
        .expect("announce delivery");
    eprintln!("[recv] delivery announced: {}", hex(&delivery_dest.hash));

    // ── Discover rfed.channel ───────────────────────────────────────────────
    // If the shell script gave us rfed's channel hash, request the path to
    // it immediately — rfed will send a path response containing its identity,
    // which fires our AnnounceHandler (receive_path_responses=true).
    if let Some(ref hash_hex) = rfed_channel_hash_hex {
        if let Ok(hash_bytes) = hex_to_bytes(hash_hex) {
            eprintln!("[e2e] requesting path to rfed.channel {hash_hex}...");
            Transport::request_path(&hash_bytes, None, None, None, None);
        }
    }
    // Store the rfed.channel destination hash so we can build a Destination later.
    let rfed_ch_hash: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let ch_ready = Arc::new(AtomicBool::new(false));

    for aspect in &["rfed.channel", "rfed.node"] {
        let hash_mu  = Arc::clone(&rfed_ch_hash);
        let ready    = Arc::clone(&ch_ready);
        let aspect_s = aspect.to_string();
        Transport::register_announce_handler(AnnounceHandler {
            aspect_filter:        Some(aspect_s.clone()),
            receive_path_responses: true,
            callback: Arc::new(move |dest_hash, _identity, _app_data, _ann_hash, _is_path| {
                if ready.load(Ordering::Relaxed) { return; }
                // Both rfed.channel and rfed.node share the same identity;
                // store the *channel* hash (derived from identity) regardless
                // of which aspect we heard.  We'll use Identity::recall later.
                *hash_mu.lock().unwrap() = Some(dest_hash.to_vec());
                ready.store(true, Ordering::Relaxed);
                eprintln!("[e2e] rfed destination heard via {aspect_s}");
            }),
        });
    }

    eprintln!("[e2e] Waiting for rfed announce (up to {}s)...", timeout_secs / 2);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs / 2);
    while !ch_ready.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
    }
    if !ch_ready.load(Ordering::Relaxed) {
        eprintln!("[e2e] FAIL: rfed did not announce within timeout");
        std::process::exit(1);
    }

    // Build outbound channel destination from rfed's recalled identity.
    let heard_hash = rfed_ch_hash.lock().unwrap().clone().expect("rfed dest hash");
    let rfed_identity = Identity::recall(&heard_hash)
        .expect("rfed identity not in known-destinations table");

    let channel_dest = Destination::new_outbound(
        Some(rfed_identity.clone()),
        DestinationType::Single,
        "rfed".to_string(),
        vec!["channel".to_string()],
    )
    .expect("build rfed.channel dest");
    eprintln!("[e2e] rfed.channel: {}", hex(&channel_dest.hash));

    // ── Subscribe ───────────────────────────────────────────────────────────
    let sub_ok   = Arc::new(AtomicBool::new(false));
    let sub_done = Arc::new(AtomicBool::new(false));

    // These arcs are captured by the link_established callback.
    let sub_ok_outer   = Arc::clone(&sub_ok);
    let sub_done_outer = Arc::clone(&sub_done);

    let ch_hash_sub = ch_hash.clone();
    let receiver_sub = receiver.clone();

    let link = Link::new_outbound(channel_dest, MODE_AES256_CBC).expect("create link");
    let link_handle = LinkHandle::spawn(link);

    {
        let lh = link_handle.clone();

        link_handle.set_link_established_callback(Some(Arc::new(move |_la| {
            eprintln!("[e2e] link established");

            if let Err(e) = lh.identify(&receiver_sub) {
                eprintln!("[e2e] identify error: {e}");
            } else {
                eprintln!("[e2e] identify sent");
            }
            // Brief pause for rfed to process IDENTIFY before request.
            thread::sleep(Duration::from_millis(300));

            let payload = build_subscribe_payload(&receiver_sub, &ch_hash_sub);

            let ok_a   = Arc::clone(&sub_ok_outer);
            let done_a = Arc::clone(&sub_done_outer);
            let done_b = Arc::clone(&sub_done_outer);

            let resp_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |receipt: RequestReceipt| {
                    // Response: [true, stamp_cost_or_nil]  (or legacy 0xc3)
                    let accepted = receipt.response.as_deref().map(|d| {
                        if d.first() == Some(&0xc3) { return true; }
                        if let Ok(v) = rmpv::decode::read_value(&mut std::io::Cursor::new(d)) {
                            if let rmpv::Value::Array(arr) = v {
                                return arr.first().and_then(|x| x.as_bool()).unwrap_or(false);
                            }
                        }
                        rmp_serde::from_slice::<bool>(d).unwrap_or(false)
                    }).unwrap_or(false);
                    eprintln!("[e2e] subscribe response: {}", if accepted { "OK" } else { "REJECTED" });
                    ok_a.store(accepted, Ordering::Relaxed);
                    done_a.store(true, Ordering::Relaxed);
                });

            let fail_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |_| {
                    eprintln!("[e2e] subscribe request failed/timed out");
                    done_b.store(true, Ordering::Relaxed);
                });

            if let Err(e) = lh.request(
                "/rfed/subscribe".to_string(),
                payload,
                Some(resp_cb),
                Some(fail_cb),
                None,
            ) {
                eprintln!("[e2e] request error: {e}");
                sub_done_outer.store(true, Ordering::Relaxed);
            }
        })));

        let sub_done_closed = Arc::clone(&sub_done);
        link_handle.set_link_closed_callback(Some(Arc::new(move |_| {
            eprintln!("[e2e] link closed");
            sub_done_closed.store(true, Ordering::Relaxed);
        })));

        if let Err(e) = link_handle.initiate() {
            eprintln!("[e2e] FAIL: link initiate: {e}");
            std::process::exit(1);
        }
    }
    register_runtime_link_handle(link_handle);

    let deadline = Instant::now() + Duration::from_secs(30);
    while !sub_done.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }

    if !sub_ok.load(Ordering::Relaxed) {
        eprintln!("[e2e] FAIL: subscribe did not succeed (done={}, ok={})",
            sub_done.load(Ordering::Relaxed), sub_ok.load(Ordering::Relaxed));
        std::process::exit(1);
    }
    eprintln!("[e2e] Subscribed OK — waiting 1s for rfed to register subscription...");
    thread::sleep(Duration::from_secs(1));

    // ── Send channel message ─────────────────────────────────────────────────
    // Rebuild the channel dest (link may have closed, but identity is still known).
    let send_channel_dest = Destination::new_outbound(
        Some(rfed_identity),
        DestinationType::Single,
        "rfed".to_string(),
        vec!["channel".to_string()],
    )
    .expect("rebuild rfed.channel dest for send");

    let inner_pt   = build_inner_plaintext(&sender, &message);
    let ciphertext = ch_id.encrypt(&inner_pt).expect("channel encrypt");
    eprintln!("[send] inner_pt_len={} ciphertext_len={}", inner_pt.len(), ciphertext.len());

    // Packet payload:
    //   stamp_cost=None  → channel_hash(16) | ciphertext   (no stamp; rfed doesn't strip)
    //   stamp_cost=Some(0) → channel_hash(16) | ciphertext | stamp(32 zeros)  (trivial stamp)
    //   stamp_cost=Some(n) → channel_hash(16) | ciphertext | stamp(32 PoW)    (real stamp)
    let mut payload = ch_hash.clone();
    payload.extend_from_slice(&ciphertext);
    if let Some(cost) = stamp_cost {
        let material = &payload; // ch_hash || ciphertext
        let transient_id = full_hash(material);
        let stamp = if cost == 0 {
            vec![0u8; LXStamper::STAMP_SIZE]
        } else {
            let (s, _) = LXStamper::generate_stamp(&transient_id, cost, 16);
            s
        };
        eprintln!("[send] appending stamp (cost={cost})");
        payload.extend_from_slice(&stamp);
    }
    eprintln!("[send] payload_len={}", payload.len());

    let mut pkt = Packet::new(
        Some(send_channel_dest),
        payload,
        DATA, NONE, BROADCAST, HEADER_1,
        None, None, false, FLAG_UNSET,
    );

    match pkt.send() {
        Ok(Some(_)) => eprintln!("[send] packet sent OK"),
        Ok(None)    => eprintln!("[send] packet sent (no receipt)"),
        Err(e)      => {
            eprintln!("[send] FAIL: packet send error: {e}");
            std::process::exit(1);
        }
    }

    // ── Wait for delivery ────────────────────────────────────────────────────
    eprintln!("[e2e] Waiting for delivery (up to {timeout_secs}s)...");
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while !recv_done.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }

    if !recv_done.load(Ordering::Relaxed) {
        eprintln!("[e2e] FAIL: message not received within {timeout_secs}s");
        std::process::exit(1);
    }

    let got = recv_content.lock().unwrap().clone().unwrap_or_default();
    if got != message {
        eprintln!("[e2e] FAIL: content mismatch\n  expected: '{message}'\n  got:      '{got}'");
        std::process::exit(1);
    }

    eprintln!("[e2e] ✓ PASS: '{got}'");
}
