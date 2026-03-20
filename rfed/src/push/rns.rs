//! Reticulum-native push wake-up dispatch.
//!
//! Sends a msgpack-encoded wake packet to a push relay node identified by
//! a 32-char lowercase hex destination hash stored in `PushRegistration`.
//!
//! The relay is a Reticulum node operated by the app developer and is
//! responsible for forwarding the wake-up to the device via FCM, APNs, SMS,
//! or any other out-of-band channel.  rfed never makes an outbound IP
//! connection — the entire push path stays within the Reticulum mesh.
//!
//! # Wake packet payload
//! A msgpack-encoded `Vec<u8>` containing the 16-byte subscriber destination
//! hash is sent to the relay.  The relay uses this hash to look up the
//! platform device token in its own table and fires the platform push.
//! No message content, channel metadata, or sender identity is included.
//!
//! If no path to the relay exists yet, a path request is issued and the
//! wake-up is dropped for this cycle; the next push attempt will succeed
//! once routing has converged.

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::transport::{self, Transport};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use super::PushRegistration;

/// Send a msgpack wake packet to the registered push relay.
///
/// Spawns a background thread and returns immediately.
pub fn dispatch(reg: &PushRegistration) {
    let dest_hex = reg.relay_hash.clone();
    let sub_hash = reg.subscriber_hash.clone();

    std::thread::spawn(move || {
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
                        "[push/rns] invalid dest hash in endpoint for {}",
                        hexrep(&sub_hash, false),
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                return;
            }
        };

        // If no path is known, request one and bail — the next push attempt
        // will succeed once routing has converged.
        if !Transport::has_path(&dest_hash) {
            Transport::request_path(&dest_hash, None, None, None, None);
            log(
                &format!(
                    "[push/rns] no path to {dest_hex}, path request issued",
                ),
                LOG_DEBUG,
                false,
                false,
            );
            return;
        }

        // Recall the identity for the destination (needed to build a
        // Single-type outbound destination and encrypt the packet).
        let identity = match Identity::recall(&dest_hash) {
            Some(id) => id,
            None => {
                // Identity not in cache yet; path request will trigger an
                // announce that populates it on the next cycle.
                Transport::request_path(&dest_hash, None, None, None, None);
                log(
                    &format!(
                        "[push/rns] identity not cached for {dest_hex}, retrying next push",
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                return;
            }
        };

        let dest = match Destination::new_outbound(
            Some(identity),
            DestinationType::Single,
            "rns".to_string(),
            vec!["push".to_string()],
        ) {
            Ok(d) => d,
            Err(e) => {
                log(
                    &format!("[push/rns] dest build error for {dest_hex}: {e}"),
                    LOG_WARNING,
                    false,
                    false,
                );
                return;
            }
        };

        let payload = rmp_serde::to_vec(&sub_hash).unwrap_or_default();
        let mut pkt = Packet::new(
            Some(dest),
            payload,             // msgpack-encoded subscriber destination hash
            packet::DATA,
            packet::NONE,        // context: no special meaning
            transport::BROADCAST,
            packet::HEADER_1,
            None,                // transport_id
            None,                // attached_interface
            false,               // no delivery receipt needed
            packet::FLAG_UNSET,
        );

        match pkt.send() {
            Ok(_) => log(
                &format!(
                    "[push/rns] wake sent to {dest_hex} for {}",
                    hexrep(&sub_hash, false),
                ),
                LOG_NOTICE,
                false,
                false,
            ),
            Err(e) => log(
                &format!(
                    "[push/rns] send failed for {dest_hex}: {e}",
                ),
                LOG_WARNING,
                false,
                false,
            ),
        }
    });
}

