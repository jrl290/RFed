//! Reticulum-native notify wake-up dispatch.
//!
//! Sends a msgpack-encoded wake packet to a notify relay node identified by
//! a 32-char lowercase hex destination hash stored in `NotifyRegistration`.
//!
//! The relay is a Reticulum node operated by the app developer and is
//! responsible for forwarding the wake-up to the device via FCM, APNs, SMS,
//! or any other out-of-band channel.  rfed never makes an outbound IP
//! connection — the entire notify path stays within the Reticulum mesh.
//!
//! # Wake packet payload
//! A msgpack-encoded Map sent to the relay containing:
//!   - `receiver`: Binary(16) — subscriber destination hash (always present)
//!   - `sender`:   Binary(16) — publisher destination hash (when available)
//!   - `channel`:  Binary(16) — channel hash (rfed.channel only, omitted for LXMF)
//!
//! No message content is included.
//!
//! # Retry & fallback
//! If no path to the relay exists, a path request is issued and dispatch is
//! retried once after a short delay.  If the retry also fails, the notify is
//! dropped — the subscriber will receive their messages via the normal
//! deferred-queue flush (triggered by their next announce) or via LXMF
//! propagation pull on their client, whichever comes first.

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::transport::{self, Transport};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use super::NotifyRegistration;

/// Send a msgpack wake packet to the registered notify relay.
///
/// Spawns a background thread and returns immediately.  If the first
/// attempt fails (no path / no cached identity), a single retry is
/// scheduled after `RETRY_DELAY`.  If the retry also fails the notify is
/// silently dropped — delivery proceeds via the deferred queue / LXMF
/// propagation pull path.
pub fn dispatch(
    reg: &NotifyRegistration,
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) {
    let dest_hex = reg.relay_hash.clone();
    let sub_hash = reg.subscriber_hash.clone();
    let sender_hash = sender.map(|s| s.to_vec());
    let channel_hash = channel.map(|c| c.to_vec());

    std::thread::spawn(move || {
        if try_send(&dest_hex, &sub_hash, sender_hash.as_deref(), channel_hash.as_deref()) {
            return;
        }
        // First attempt failed — wait for path convergence and retry once.
        std::thread::sleep(RETRY_DELAY);
        if !try_send(&dest_hex, &sub_hash, sender_hash.as_deref(), channel_hash.as_deref()) {
            log(
                &format!(
                    "[notify/rns] relay {dest_hex} unreachable after retry; \
                     delivery will proceed via deferred queue / LXMF pull",
                ),
                LOG_DEBUG,
                false,
                false,
            );
        }
    });
}

/// Retry delay between the first and second dispatch attempt.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(8);

/// Try to send a single wake packet.  Returns `true` on success.
fn try_send(
    dest_hex: &str,
    sub_hash: &[u8],
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> bool {
    // Decode the 32-char hex hash into 16 bytes.
    let dest_hash: Vec<u8> = match (0..dest_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&dest_hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(b) if b.len() == 16 => b,
        _ => {
            log(
                &format!(
                    "[notify/rns] invalid dest hash for {}",
                    hexrep(sub_hash, false),
                ),
                LOG_WARNING,
                false,
                false,
            );
            return false;
        }
    };

    // If no path is known, request one and bail.
    if !Transport::has_path(&dest_hash) {
        Transport::request_path(&dest_hash, None, None, None, None);
        log(
            &format!(
                "[notify/rns] no path to {dest_hex}, path request issued",
            ),
            LOG_DEBUG,
            false,
            false,
        );
        return false;
    }

    // Recall the identity for the destination (needed to build a
    // Single-type outbound destination and encrypt the packet).
    let identity = match Identity::recall(&dest_hash) {
        Some(id) => id,
        None => {
            Transport::request_path(&dest_hash, None, None, None, None);
            log(
                &format!(
                    "[notify/rns] identity not cached for {dest_hex}, path request issued",
                ),
                LOG_DEBUG,
                false,
                false,
            );
            return false;
        }
    };

    let dest = match Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        "rns".to_string(),
        vec!["notify".to_string()],
    ) {
        Ok(d) => d,
        Err(e) => {
            log(
                &format!("[notify/rns] dest build error for {dest_hex}: {e}"),
                LOG_WARNING,
                false,
                false,
            );
            return false;
        }
    };

    let mut entries = vec![
        (
            rmpv::Value::String("receiver".into()),
            rmpv::Value::Binary(sub_hash.to_vec()),
        ),
    ];
    if let Some(s) = sender {
        entries.push((
            rmpv::Value::String("sender".into()),
            rmpv::Value::Binary(s.to_vec()),
        ));
    }
    if let Some(c) = channel {
        entries.push((
            rmpv::Value::String("channel".into()),
            rmpv::Value::Binary(c.to_vec()),
        ));
    }
    let mut payload = Vec::new();
    let _ = rmpv::encode::write_value(&mut payload, &rmpv::Value::Map(entries));
    let mut pkt = Packet::new(
        Some(dest),
        payload,
        packet::DATA,
        packet::NONE,
        transport::BROADCAST,
        packet::HEADER_1,
        None,
        None,
        false,
        packet::FLAG_UNSET,
    );

    match pkt.send() {
        Ok(_) => {
            log(
                &format!(
                    "[notify/rns] wake sent to {dest_hex} for {}",
                    hexrep(sub_hash, false),
                ),
                LOG_NOTICE,
                false,
                false,
            );
            true
        }
        Err(e) => {
            log(
                &format!(
                    "[notify/rns] send failed for {dest_hex}: {e}",
                ),
                LOG_WARNING,
                false,
                false,
            );
            false
        }
    }
}

