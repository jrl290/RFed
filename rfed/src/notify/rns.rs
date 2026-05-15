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
//! The relay destination is `rfed.notify` (`app_name="rfed"`, `aspects=["notify"]`).
//!
//! # Retry & fallback
//! Notify uses direct RNS packet send to `rfed.notify` so relay nodes that
//! only register a destination packet callback (no link handlers) still
//! receive wake packets.
//! A single delayed retry is scheduled if the first send cannot complete.

use std::sync::Arc;

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
    let dest_hash = match decode_relay_hash(&reg.relay_hash, &reg.subscriber_hash) {
        Some(hash) => hash,
        None => return,
    };
    let dest_hex = reg.relay_hash.clone();
    let sub_hash = reg.subscriber_hash.clone();
    let payload = encode_wake_payload(&sub_hash, sender, channel);

    log(
        format!(
            "[notify/rns] dispatch queued for relay={} subscriber={}",
            &dest_hex,
            hexrep(&sub_hash, false),
        ),
        LOG_DEBUG,
        false,
        false,
    );

    send_with_app_links(dest_hash, dest_hex, sub_hash, payload, 0);
}

/// Retry delay between the first and second dispatch attempt.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(8);

fn decode_relay_hash(
    dest_hex: &str,
    sub_hash: &[u8],
) -> Option<Vec<u8>> {
    // Decode the 32-char hex hash into 16 bytes.
    match (0..dest_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&dest_hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(b) if b.len() == 16 => Some(b),
        _ => {
            log(
                format!(
                    "[notify/rns] invalid dest hash for {}",
                    hexrep(sub_hash, false),
                ),
                LOG_WARNING,
                false,
                false,
            );
            None
        }
    }
}

fn send_with_app_links(
    dest_hash: Vec<u8>,
    dest_hex: String,
    sub_hash: Vec<u8>,
    payload: Vec<u8>,
    attempt: usize,
) {
    log(
        format!(
            "[notify/rns] wake attempt={} relay={} subscriber={}",
            attempt + 1,
            dest_hex,
            hexrep(&sub_hash, false),
        ),
        LOG_DEBUG,
        false,
        false,
    );

    // If no path is known yet, request one and retry once.
    if !Transport::has_path(&dest_hash) {
        Transport::request_path(&dest_hash, None, None, None, None);
        retry_or_drop(
            dest_hash,
            dest_hex,
            sub_hash,
            payload,
            attempt,
            "no path to relay",
        );
        return;
    }

    // Destination identity is required to build an encrypted SINGLE outbound
    // destination. If unavailable, request path/announce and retry once.
    let identity = match Identity::recall(&dest_hash) {
        Some(id) => id,
        None => {
            Transport::request_path(&dest_hash, None, None, None, None);
            retry_or_drop(
                dest_hash,
                dest_hex,
                sub_hash,
                payload,
                attempt,
                "identity not cached for relay",
            );
            return;
        }
    };

    let dest = match Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        "rfed".to_string(),
        vec!["notify".to_string()],
    ) {
        Ok(d) => d,
        Err(e) => {
            retry_or_drop(
                dest_hash,
                dest_hex,
                sub_hash,
                payload,
                attempt,
                &format!("destination build failed: {e}"),
            );
            return;
        }
    };

    let mut pkt = Packet::new(
        Some(dest),
        payload.clone(),
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
                format!(
                    "[notify/rns] wake sent to {} for {}",
                    dest_hex,
                    hexrep(&sub_hash, false),
                ),
                LOG_NOTICE,
                false,
                false,
            );
        }
        Err(e) => {
            retry_or_drop(
                dest_hash,
                dest_hex,
                sub_hash,
                payload,
                attempt,
                &format!("send failed: {e}"),
            );
        }
    }
}

fn retry_or_drop(
    dest_hash: Vec<u8>,
    dest_hex: String,
    sub_hash: Vec<u8>,
    payload: Vec<u8>,
    attempt: usize,
    reason: &str,
) {
    if attempt == 0 {
        log(
            format!(
                "[notify/rns] first attempt failed for relay={} ({reason}), scheduling retry in {}s",
                dest_hex,
                RETRY_DELAY.as_secs(),
            ),
            LOG_NOTICE,
            false,
            false,
        );

        std::thread::spawn(move || {
            std::thread::sleep(RETRY_DELAY);
            send_with_app_links(
                dest_hash,
                dest_hex,
                sub_hash,
                payload,
                1,
            );
        });
    } else {
        log(
            format!(
                "[notify/rns] relay {dest_hex} unreachable after retry ({reason}); \
                 delivery will proceed via deferred queue / LXMF pull",
            ),
            LOG_DEBUG,
            false,
            false,
        );
    }
}

fn encode_wake_payload(
    sub_hash: &[u8],
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> Vec<u8> {
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
    payload
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rmpv::decode::read_value;
    use rmpv::Value;

    use super::encode_wake_payload;

    fn map_entry<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
        map.iter()
            .find(|(candidate, _)| candidate.as_str() == Some(key))
            .map(|(_, value)| value)
    }

    #[test]
    fn wake_payload_uses_binary_hash_fields() {
        let receiver = [0x11u8; 16];
        let sender = [0x22u8; 16];
        let channel = [0x33u8; 16];

        let payload = encode_wake_payload(&receiver, Some(&sender), Some(&channel));
        let value = read_value(&mut Cursor::new(payload)).expect("decode wake payload");
        let map = match value {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };

        assert_eq!(map_entry(&map, "receiver"), Some(&Value::Binary(receiver.to_vec())));
        assert_eq!(map_entry(&map, "sender"), Some(&Value::Binary(sender.to_vec())));
        assert_eq!(map_entry(&map, "channel"), Some(&Value::Binary(channel.to_vec())));
    }

    #[test]
    fn wake_payload_omits_optional_fields_when_absent() {
        let receiver = [0x44u8; 16];

        let payload = encode_wake_payload(&receiver, None, None);
        let value = read_value(&mut Cursor::new(payload)).expect("decode wake payload");
        let map = match value {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };

        assert_eq!(map.len(), 1);
        assert_eq!(map_entry(&map, "receiver"), Some(&Value::Binary(receiver.to_vec())));
        assert_eq!(map_entry(&map, "sender"), None);
        assert_eq!(map_entry(&map, "channel"), None);
    }
}

