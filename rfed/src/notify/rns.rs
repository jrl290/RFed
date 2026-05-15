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
//! Notify uses AppLinks for the actual send path so the relay wake rides the
//! same short-lived, proof-backed link machinery as other app-driven traffic.
//! A single delayed retry is still scheduled if the first send exhausts the
//! AppLinks tier chain without a delivery proof.

use std::sync::Arc;

use app_links::AppLinks;
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
    AppLinks::open(&dest_hash, "rfed", &["notify"]);

    log(
        format!(
            "[notify/rns] app-link wake attempt={} relay={} subscriber={}",
            attempt + 1,
            dest_hex,
            hexrep(&sub_hash, false),
        ),
        LOG_DEBUG,
        false,
        false,
    );

    let delivered_dest_hex = dest_hex.clone();
    let delivered_sub_hash = sub_hash.clone();
    let on_delivered: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
        log(
            format!(
                "[notify/rns] wake delivered to {} for {}",
                delivered_dest_hex,
                hexrep(&delivered_sub_hash, false),
            ),
            LOG_NOTICE,
            false,
            false,
        );
    });

    let on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(|| {});

    let on_failed: Arc<dyn Fn() + Send + Sync + 'static> = if attempt == 0 {
        let retry_dest_hash = dest_hash.clone();
        let retry_dest_hex = dest_hex.clone();
        let retry_sub_hash = sub_hash.clone();
        let retry_payload = payload.clone();
        Arc::new(move || {
            log(
                format!(
                    "[notify/rns] first attempt failed for relay={}, scheduling retry in {}s",
                    retry_dest_hex,
                    RETRY_DELAY.as_secs(),
                ),
                LOG_NOTICE,
                false,
                false,
            );
            let retry_dest_hash = retry_dest_hash.clone();
            let retry_dest_hex = retry_dest_hex.clone();
            let retry_sub_hash = retry_sub_hash.clone();
            let retry_payload = retry_payload.clone();
            std::thread::spawn(move || {
                std::thread::sleep(RETRY_DELAY);
                send_with_app_links(
                    retry_dest_hash,
                    retry_dest_hex,
                    retry_sub_hash,
                    retry_payload,
                    1,
                );
            });
        })
    } else {
        let failed_dest_hex = dest_hex.clone();
        Arc::new(move || {
            log(
                format!(
                    "[notify/rns] relay {failed_dest_hex} unreachable after retry; \
                     delivery will proceed via deferred queue / LXMF pull",
                ),
                LOG_DEBUG,
                false,
                false,
            );
        })
    };

    AppLinks::send(
        &dest_hash,
        payload,
        on_delivered,
        on_propagation_needed,
        on_failed,
    );
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

