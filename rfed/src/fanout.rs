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


use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, DATA, NONE, HEADER_1, FLAG_UNSET};
use reticulum_rust::transport::Transport;
use reticulum_rust::{log, hexrep, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::deferred_queue::DeferredQueue;
use crate::notify::{dispatch_notify, HookRegistry, NotifyRegistry};
use crate::stream_registry::ChannelStreamRegistry;

/// rfed app name used to compute destination hashes.
pub const APP_NAME: &str = "rfed";

/// A channel fan-out that has been fully detached from the `FedNode` mutex.
///
/// # Why this type exists
///
/// A fan-out performs unbounded network work per subscriber: stream dispatch,
/// `Identity::recall`, path lookup, and packet dispatch. On this transport a
/// single subscriber's link establishment measures 7–16 seconds. Any lock held
/// across the loop is therefore held for minutes, and every request callback
/// that needs the same lock stalls behind it.
///
/// That is not hypothetical. The distro side of it was diagnosed in production
/// on 2026-08-09 (see `distro::distro_fanout`): `/rfed/distro/register`
/// callbacks blocked forever on `distro_table.lock()`, never logged
/// `[REQ] callback completed`, and the browser client hung. The fix there
/// snapshotted one table. The channel side kept the original shape — the
/// callers held the **`FedNode` mutex itself**, plus `subscription_table` and
/// `hook_registry`, across `fanout_blob` — so the same wedge reappeared on
/// 2026-08-17 from the other direction: `/rfed/subscribe` returned no response
/// within 26s and the `rfed.distro.register` link never proved, because
/// `subscribe_cb` and every other handler were waiting on `sub_node.lock()`.
///
/// So the contract is enforced by the type instead of by a comment. A
/// `FanoutPlan` owns its subscriber snapshot and holds `Arc`s rather than
/// borrows, which means it stays valid after the guard is dropped — and
/// `FanoutPlan::run` needs no guard at all.
///
/// NEVER REMOVE the owned snapshot in favour of borrowing from the `FedNode`
/// guard. Build the plan under the lock, let the guard drop, then `run`.
pub struct FanoutPlan {
    /// `(subscriber_hash, owner_node_hash)` snapshot taken under
    /// `subscription_table`, which is released before any delivery.
    pub subscribers: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// Per-subscriber deferred-queue limit, resolved from `NodeConfig` under
    /// the guard so the config need not be reachable during the fan-out.
    pub deferred_limits: HashMap<Vec<u8>, usize>,
    pub hook_registry: Arc<Mutex<HookRegistry>>,
    pub notify_registry: Arc<Mutex<NotifyRegistry>>,
    pub deferred_queue: Arc<Mutex<DeferredQueue>>,
    pub channel_streams: Arc<Mutex<ChannelStreamRegistry>>,
}

impl FanoutPlan {
    /// Deliver `inner_blob` to every subscriber in the plan, then defer and
    /// wake whoever could not be reached.
    ///
    /// Callers must not hold the `FedNode` mutex here — see the type's docs.
    pub fn run(&self, channel_dest_hash: &[u8], inner_blob: &[u8]) {
        let missed = {
            let hooks = match self.hook_registry.lock() {
                Ok(h) => h,
                Err(_) => {
                    log("[fanout] hook registry poisoned — skipping fanout",
                        LOG_WARNING, false, false);
                    return;
                }
            };
            fanout_blob(
                inner_blob,
                channel_dest_hash,
                &self.subscribers,
                &hooks,
                Some(&self.channel_streams),
            )
        };

        if missed.is_empty() {
            return;
        }

        if let Ok(mut deferred) = self.deferred_queue.lock() {
            for sub_hash in &missed {
                let limit = self.deferred_limits.get(sub_hash).copied().unwrap_or(0);
                deferred.enqueue(
                    sub_hash.clone(),
                    channel_dest_hash.to_vec(),
                    inner_blob.to_vec(),
                    limit,
                );
            }
        }

        // Fire notify wake-ups for deferred subscribers.
        if let Ok(notify) = self.notify_registry.lock() {
            for sub_hash in &missed {
                for reg in notify.get_for_channel(sub_hash, Some(channel_dest_hash)) {
                    dispatch_notify(reg, None, Some(channel_dest_hash));
                }
            }
        }
    }
}

/// Fanout an inner blob to the given subscribers of `channel_dest_hash`.
///
/// Returns the dest hashes of subscribers whose identity was not yet known
/// to the local Reticulum node (i.e. `Identity::recall` returned `None`).
/// The caller is responsible for enqueuing those in the deferred delivery
/// queue and firing notify hooks for them — `FanoutPlan::run` does both.
///
/// NEVER REMOVE the `subscribers` snapshot parameter in favour of a
/// `&SubscriptionTable`. Taking the table forced every caller to hold
/// `subscription_table` — and in practice the whole `FedNode` mutex — across
/// the delivery loop, which wedged `/rfed/subscribe` in production on
/// 2026-08-17. See `FanoutPlan`.
pub fn fanout_blob(
    inner_blob: &[u8],
    channel_dest_hash: &[u8],
    subscribers: &[(Vec<u8>, Option<Vec<u8>>)],
    hook_registry: &HookRegistry,
    channel_streams: Option<&Arc<Mutex<ChannelStreamRegistry>>>,
) -> Vec<Vec<u8>> {
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

    for (sub_hash, owner_hash) in subscribers {
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
