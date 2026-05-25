//! Channel fanout — deliver an inner blob to every subscriber.
//!
//! Protocol (double-envelope):
//!
//!   Inner blob  — encrypted TO channel pubkey, signed BY sender.
//!                 Created once by the sender; the node never modifies it.
//!
//!   Outer envelope — standard Reticulum transport packet addressed TO
//!                    each subscriber's rfed.delivery destination.
//!                    Encrypted + signed by the Reticulum stack using the
//!                    node's identity.  Never stored; created here at
//!                    fanout time.
//!
//! The node's only job is:
//!   1. Look up subscribers for the destination channel.
//!   2. Prefer any active `rfed.channel.stream` links for that subscriber.
//!   3. Fall back to the legacy `rfed.delivery` packet path when no stream
//!      session is active (compatibility during migration).
//!   4. Fire registered delivery hooks (notify adapters).


use std::sync::{Arc, Mutex};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, DATA, NONE, HEADER_1, FLAG_UNSET};
use reticulum_rust::transport::Transport;
use reticulum_rust::{log, hexrep, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::notify::HookRegistry;
use crate::stream_registry::ChannelStreamRegistry;
use crate::subscription::SubscriptionTable;

/// rfed app name used to compute destination hashes.
pub const APP_NAME: &str = "rfed";

/// Fanout an inner blob to all subscribers of `channel_dest_hash`.
///
/// Returns the dest hashes of subscribers whose identity was not yet known
/// to the local Reticulum node (i.e. `Identity::recall` returned `None`).
/// The caller is responsible for enqueuing those in the deferred delivery
/// queue and firing notify hooks for them.
pub fn fanout_blob(
    inner_blob: &[u8],
    channel_dest_hash: &[u8],
    subscription_table: &SubscriptionTable,
    hook_registry: &HookRegistry,
    channel_streams: Option<&Arc<Mutex<ChannelStreamRegistry>>>,
) -> Vec<Vec<u8>> {
    let subscribers = subscription_table.get_subscribers_with_owner(channel_dest_hash);

    if subscribers.is_empty() {
        log(
            format!(
                "[fanout] no subscribers for channel {}",
                hexrep(channel_dest_hash, false)
            ),
            LOG_DEBUG,
            false,
            false,
        );
        return Vec::new();
    }

    log(
        format!(
            "[fanout] delivering blob ({} bytes) to {} subscriber(s) on channel {}",
            inner_blob.len(),
            subscribers.len(),
            hexrep(channel_dest_hash, false),
        ),
        LOG_DEBUG,
        false,
        false,
    );

    let mut missed: Vec<Vec<u8>> = Vec::new();

    for (sub_hash, owner_hash) in &subscribers {
        // Backup subscriptions: suppress delivery while the owner node is reachable.
        // If the owner's path has decayed, fall through and deliver normally.
        if let Some(owner) = owner_hash {
            if Identity::recall(owner).is_some() {
                log(
                    format!(
                        "[fanout] backup sub {} suppressed — owner reachable",
                        hexrep(sub_hash, false)
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                continue;
            }
            log(
                format!(
                    "[fanout] backup sub {} — owner offline, delivering",
                    hexrep(sub_hash, false)
                ),
                LOG_DEBUG,
                false,
                false,
            );
        }

        let mut payload = channel_dest_hash.to_vec();
        payload.extend_from_slice(inner_blob);

        if let Some(streams) = channel_streams {
            if let Ok(mut registry) = streams.lock() {
                let result = registry.dispatch(sub_hash, channel_dest_hash, &payload);
                if result.delivered() {
                    log(
                        format!(
                            "[fanout] streamed channel {} to subscriber {} on {} live link(s)",
                            hexrep(channel_dest_hash, false),
                            hexrep(sub_hash, false),
                            result.sent,
                        ),
                        LOG_DEBUG,
                        false,
                        false,
                    );
                    hook_registry.on_deliver(sub_hash, inner_blob);
                    continue;
                }
                if result.had_sessions() {
                    log(
                        format!(
                            "[fanout] stream delivery failed for subscriber {} on channel {} — falling back to legacy delivery",
                            hexrep(sub_hash, false),
                            hexrep(channel_dest_hash, false),
                        ),
                        LOG_WARNING,
                        false,
                        false,
                    );
                }
            }
        }

        // subscriber_hash is the identity hash stored by subscribe_cb.
        // Use recall_from_identity_hash (not recall by destination hash).
        let maybe_identity = Identity::recall_from_identity_hash(sub_hash);

        let identity = match maybe_identity {
            Some(id) => id,
            None => {
                log(
                    format!(
                        "[fanout] subscriber {} unknown — will defer",
                        hexrep(sub_hash, false)
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                missed.push(sub_hash.clone());
                continue;
            }
        };

        // Construct an outbound destination to the subscriber's rfed.delivery
        // endpoint.  Reticulum handles X25519 encryption + node signing.
        match Destination::new_outbound(
            Some(identity),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["delivery".to_string()],
        ) {
            Ok(dest) => {
                // Only attempt live delivery if a network path is known.
                // Without a path, Transport::outbound falls back to broadcast
                // (sending to all interfaces), which falsely returns sent=true
                // even though the subscriber is unreachable.
                if !Transport::has_path(&dest.hash) {
                    log(
                        format!(
                            "[fanout] no path to subscriber {} delivery — will defer",
                            hexrep(sub_hash, false)
                        ),
                        LOG_DEBUG,
                        false,
                        false,
                    );
                    missed.push(sub_hash.clone());
                    continue;
                }

                // Delivery packet payload: channel_id_hash(16) | inner_blob.
                // This remains as a compatibility fallback while clients migrate
                // to rfed.channel.stream.

                let mut packet = Packet::new(
                    Some(dest),
                    payload,
                    DATA,
                    NONE,
                    reticulum_rust::transport::BROADCAST,
                    HEADER_1,
                    None,
                    None,
                    false,
                    FLAG_UNSET,
                );
                match packet.send() {
                    Err(e) => {
                        log(
                            format!("[fanout] send to {} failed: {e} — will defer", hexrep(sub_hash, false)),
                            LOG_WARNING,
                            false,
                            false,
                        );
                        missed.push(sub_hash.clone());
                    }
                    Ok(None) => {
                        // Transport::outbound returned false (e.g. subscriber's TCP
                        // session is gone but the path entry still exists).  Treat as
                        // delivery failure and defer the blob.
                        log(
                            format!("[fanout] no interface for {} — will defer", hexrep(sub_hash, false)),
                            LOG_WARNING,
                            false,
                            false,
                        );
                        missed.push(sub_hash.clone());
                    }
                    Ok(Some(_)) => {
                        log(
                            format!(
                                "[FANOUT] SENT channel={} sub={} payload_bytes={}",
                                hexrep(channel_dest_hash, false),
                                hexrep(sub_hash, false),
                                inner_blob.len() + channel_dest_hash.len(),
                            ),
                            reticulum_rust::LOG_NOTICE,
                            false,
                            false,
                        );
                    }
                }
                // Also fire delivery hooks (notify adapters etc.)
                hook_registry.on_deliver(sub_hash, inner_blob);
            }
            Err(e) => {
                log(
                    format!(
                        "[fanout] failed to build destination for {}: {e}",
                        hexrep(sub_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
            }
        }
    }

    missed
}
