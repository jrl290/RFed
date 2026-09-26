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
//!   2. Prefer any bound `rfed.link` session for that subscriber
//!      (RFed-spec/Link.md) — a `/delivery` request back down the link the
//!      client already has open.
//!   3. Then any active `rfed.channel.stream` link for that subscriber.
//!   4. Fall back to the legacy `rfed.delivery` packet path when no session
//!      is active (compatibility during migration), with a delivery receipt.
//!   5. Queue for `/channel/pull` and push every subscriber no route
//!      confirmed: no response, no proof, or no route at all
//!      (`crate::handoff::defer_then_wake`).
//!
//! Tiers 2 and 3 are mutually exclusive per subscriber: a client that has
//! migrated to `rfed.link` must not also receive the legacy copy.


use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, DATA, NONE, HEADER_1, FLAG_UNSET};
use reticulum_rust::{log, hexrep, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::deferred_queue::DeferredQueue;
use crate::handoff::{await_packet_proof, OnUnconfirmed, PacketProof, Unconfirmed, DELIVERY_PACKET_PROOF};
use crate::link_session::LinkSessionRegistry;
use crate::notify::rns::{LiveStack, RelayStack};
use crate::notify::{HookRegistry, NotifyRegistry};
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
    /// `rfed.link` sessions — tier 1, ahead of `channel_streams`.
    pub link_sessions: Arc<Mutex<LinkSessionRegistry>>,
}

impl FanoutPlan {
    /// Deliver `inner_blob` to every subscriber in the plan; every subscriber
    /// the delivery is not confirmed for is queued for `/channel/pull` and
    /// pushed ([`crate::handoff::defer_then_wake`]).
    ///
    /// Callers must not hold the `FedNode` mutex here — see the type's docs.
    pub fn run(&self, channel_dest_hash: &[u8], inner_blob: &[u8]) {
        let limits = self.deferred_limits.clone();
        let on_unconfirmed = crate::handoff::defer_then_wake(
            Arc::new(LiveStack),
            Arc::clone(&self.deferred_queue),
            Arc::clone(&self.notify_registry),
            Arc::new(move |sub_hash: &[u8]| limits.get(sub_hash).copied().unwrap_or(0)),
            channel_dest_hash,
            inner_blob,
            Some(channel_dest_hash),
        );
        let hooks = match self.hook_registry.lock() {
            Ok(h) => h,
            Err(_) => {
                log("[fanout] hook registry poisoned — skipping fanout",
                    LOG_WARNING, false, false);
                return;
            }
        };
        fanout_blob(
            &LiveStack,
            inner_blob,
            channel_dest_hash,
            &self.subscribers,
            &hooks,
            Some(&self.channel_streams),
            Some(&self.link_sessions),
            on_unconfirmed,
            DELIVERY_PACKET_PROOF,
        );
    }
}

/// Fanout an inner blob to the given subscribers of `channel_dest_hash`, and
/// hand every subscriber it cannot confirm to `on_unconfirmed`. Returns how
/// many were handed off here and now; the proof-driven routes hand off later.
///
/// A delivery is confirmed by its proof (RFed SPEC §7): the rfed.link
/// response, the stream link's proof, or, when `packet_proof` is `Required`,
/// the `rfed.delivery` packet's proof (the apps prove it since 2026-09-26;
/// until most run such an app the packet is `Observed`: sent once, its proof
/// only logged). `on_unconfirmed` fires for a subscriber whose key or path is
/// unknown, whose packet no interface took, and, later, for an unanswered or
/// unproven push on the link or stream, or an unproven packet when proofs
/// are required. Until
/// 2026-09-26 the packet counted as delivered once it left, a subscriber whose
/// app had died lost it, and an unanswered or unproven live push was queued
/// but not pushed.
///
/// NEVER REMOVE the `subscribers` snapshot parameter in favour of a
/// `&SubscriptionTable`. Taking the table forced every caller to hold
/// `subscription_table` — and in practice the whole `FedNode` mutex — across
/// the delivery loop, which wedged `/rfed/subscribe` in production on
/// 2026-08-17. See `FanoutPlan`.
#[allow(clippy::too_many_arguments)]
pub fn fanout_blob(
    stack: &dyn RelayStack,
    inner_blob: &[u8],
    channel_dest_hash: &[u8],
    subscribers: &[(Vec<u8>, Option<Vec<u8>>)],
    hook_registry: &HookRegistry,
    channel_streams: Option<&Arc<Mutex<ChannelStreamRegistry>>>,
    link_sessions: Option<&Arc<Mutex<LinkSessionRegistry>>>,
    on_unconfirmed: OnUnconfirmed,
    packet_proof: PacketProof,
) -> usize {
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
        return 0;
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

    let mut handed_off = 0usize;

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

        // A channel subscriber is queued and pushed under its subscriber
        // hash (the identity hash subscribe_cb stored).
        let subscriber = Unconfirmed { queue_key: sub_hash.clone(), wake_key: sub_hash.clone() };
        let hand_off_later = || -> Arc<dyn Fn() + Send + Sync> {
            let hook = Arc::clone(&on_unconfirmed);
            let subscriber = subscriber.clone();
            Arc::new(move || hook(subscriber.clone()))
        };

        let mut payload = channel_dest_hash.to_vec();
        payload.extend_from_slice(inner_blob);

        // ── Tier 1: rfed.link session (RFed-spec/Link.md) ────────────
        let link_result = link_sessions.and_then(|sessions| {
            let mut registry = sessions.lock().ok()?;
            if !registry.has_channel_session(sub_hash, channel_dest_hash) {
                return None;
            }
            // The client answers this push; if it never does, the blob is
            // handed off — a route change, not a retry (DESIGN_PRINCIPLES §3).
            Some(registry.dispatch_channel(sub_hash, channel_dest_hash, &payload, Some(hand_off_later())))
        });

        if let Some(result) = link_result {
            if result.delivered() {
                log(
                    format!(
                        "[fanout] rfed.link pushed channel {} to subscriber {} on {} link(s)",
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
            log(
                format!(
                    "[fanout] rfed.link push failed for subscriber {} on channel {} — falling through",
                    hexrep(sub_hash, false),
                    hexrep(channel_dest_hash, false),
                ),
                LOG_WARNING,
                false,
                false,
            );
        }

        // ── Tier 2: rfed.channel.stream (proof-driven) ───────────────
        if let Some(streams) = channel_streams {
            if let Ok(mut registry) = streams.lock() {
                let result = registry.dispatch(sub_hash, channel_dest_hash, &payload, Some(hand_off_later()));
                if result.delivered() {
                    log(
                        format!(
                            "[fanout] streamed channel {} to subscriber {} on {} live link(s), awaiting its proof",
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
                            "[fanout] stream delivery failed for subscriber {} on channel {} — falling back to the rfed.delivery packet",
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

        // ── Tier 3: the rfed.delivery packet, with a delivery receipt ─
        // subscriber_hash is the identity hash stored by subscribe_cb.
        let Some(identity) = Identity::recall_from_identity_hash(sub_hash) else {
            log(
                format!("[fanout] subscriber {} unknown — queueing and pushing", hexrep(sub_hash, false)),
                LOG_DEBUG,
                false,
                false,
            );
            handed_off += 1;
            on_unconfirmed(subscriber);
            continue;
        };
        let dest = match Destination::new_outbound(
            Some(identity),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["delivery".to_string()],
        ) {
            Ok(dest) => dest,
            Err(e) => {
                log(
                    format!("[fanout] failed to build destination for {}: {e} — queueing and pushing", hexrep(sub_hash, false)),
                    LOG_WARNING,
                    false,
                    false,
                );
                handed_off += 1;
                on_unconfirmed(subscriber);
                continue;
            }
        };
        // Without a path, Transport::outbound falls back to broadcast, which
        // reports sent=true although the subscriber is unreachable.
        if !stack.has_path(&dest.hash) {
            log(
                format!("[fanout] no path to subscriber {} delivery — queueing and pushing", hexrep(sub_hash, false)),
                LOG_DEBUG,
                false,
                false,
            );
            handed_off += 1;
            on_unconfirmed(subscriber);
            continue;
        }

        let dest_hash_for_request = dest.hash.clone();
        let mut packet = Packet::new(
            Some(dest),
            payload,
            DATA,
            NONE,
            reticulum_rust::transport::BROADCAST,
            HEADER_1,
            None,
            None,
            true,
            FLAG_UNSET,
        );
        match stack.send_with_receipt(&mut packet) {
            Ok(Some(receipt)) => {
                // Required: delivered on the subscriber's proof, handed off on
                // the RNS receipt timeout, as the stream tier. Observed: sent
                // once, the proof only logged.
                await_packet_proof(
                    &receipt,
                    format!("channel {} packet to subscriber {}", hexrep(channel_dest_hash, false), hexrep(sub_hash, false)),
                    packet_proof,
                    hand_off_later(),
                );
                log(
                    format!(
                        "[FANOUT] SENT channel={} sub={} payload_bytes={}",
                        hexrep(channel_dest_hash, false),
                        hexrep(sub_hash, false),
                        inner_blob.len() + channel_dest_hash.len(),
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                hook_registry.on_deliver(sub_hash, inner_blob);
            }
            Ok(None) => {
                // The path exists but no interface took the packet (e.g. the
                // subscriber's TCP session is gone but the path entry stays).
                log(
                    format!("[fanout] no interface for {} — requesting a path, queueing and pushing", hexrep(sub_hash, false)),
                    LOG_WARNING,
                    false,
                    false,
                );
                stack.request_path(&dest_hash_for_request);
                handed_off += 1;
                on_unconfirmed(subscriber);
            }
            Err(e) => {
                log(
                    format!("[fanout] send to {} failed: {e} — queueing and pushing", hexrep(sub_hash, false)),
                    LOG_WARNING,
                    false,
                    false,
                );
                handed_off += 1;
                on_unconfirmed(subscriber);
            }
        }
    }

    handed_off
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;
    use crate::notify::rns::fake::FakeStack;

    /// A subscriber whose key rfed knows, and the hash of its rfed.delivery.
    fn known_subscriber() -> (Identity, Vec<u8>, Vec<u8>) {
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("pubkey");
        let sub_hash = identity.hash.clone().expect("identity hash");
        let delivery = Destination::hash(identity.hash.as_deref(), APP_NAME, &["delivery"]);
        let _ = Identity::remember_destination(&delivery, &pubkey, None);
        (identity, sub_hash, delivery)
    }

    fn recording() -> (OnUnconfirmed, mpsc::Receiver<Unconfirmed>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let hook: OnUnconfirmed = Arc::new(move |who| {
            let _ = tx.lock().unwrap().send(who);
        });
        (hook, rx)
    }

    fn fan_out_with(stack: &FakeStack, sub_hash: &[u8], hook: OnUnconfirmed, proof: PacketProof) -> usize {
        fanout_blob(
            stack,
            &[0xAB; 40],
            &[0xC1; 16],
            &[(sub_hash.to_vec(), None)],
            &HookRegistry::new(),
            None,
            None,
            hook,
            proof,
        )
    }

    fn fan_out(stack: &FakeStack, sub_hash: &[u8], hook: OnUnconfirmed) -> usize {
        fan_out_with(stack, sub_hash, hook, PacketProof::Required)
    }

    fn the_subscriber(sub_hash: &[u8]) -> Unconfirmed {
        Unconfirmed { queue_key: sub_hash.to_vec(), wake_key: sub_hash.to_vec() }
    }

    /// With the proof required: until 2026-09-26 the packet counted as
    /// delivered once it left, and a subscriber whose app had died, its path
    /// still held, lost the message. It waits for the proof, and on the RNS
    /// receipt timeout the subscriber is queued and pushed.
    #[test]
    fn a_channel_packet_nobody_proves_is_queued_and_pushed() {
        let (_, sub_hash, delivery) = known_subscriber();
        let stack = FakeStack::new(&delivery, None);
        let (hook, handed_off) = recording();

        assert_eq!(fan_out(&stack, &sub_hash, hook), 0, "nothing handed off before the receipt concludes");
        let mut receipt = stack.receipts.lock().unwrap()[0].clone();
        assert!(handed_off.try_recv().is_err());

        receipt.set_timeout(0.0);
        receipt.check_timeout();
        let who = handed_off.recv_timeout(Duration::from_secs(5)).expect("handed off on the receipt timeout");
        assert_eq!(who, the_subscriber(&sub_hash));
    }

    /// While the proof is observed (until the apps that prove are on most
    /// devices): an unproven packet is sent once, not queued, so the announce
    /// flush never sends it again, and nobody is pushed for it.
    #[test]
    fn while_the_proof_is_observed_an_unproven_packet_is_sent_once() {
        let (_, sub_hash, delivery) = known_subscriber();
        let stack = FakeStack::new(&delivery, None);
        let (hook, handed_off) = recording();

        assert_eq!(fan_out_with(&stack, &sub_hash, hook, PacketProof::Observed), 0);
        assert_eq!(stack.packets.lock().unwrap().len(), 1, "sent once");
        let mut receipt = stack.receipts.lock().unwrap()[0].clone();
        receipt.set_timeout(0.0);
        receipt.check_timeout();
        assert!(handed_off.recv_timeout(Duration::from_millis(300)).is_err(), "not queued, not pushed");
    }

    #[test]
    fn a_proved_channel_packet_is_delivered() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let stack = FakeStack::new(&delivery, None);
        let (hook, handed_off) = recording();

        fan_out(&stack, &sub_hash, hook);
        let mut receipt = stack.receipts.lock().unwrap()[0].clone();
        let mut proof = receipt.hash.clone();
        proof.extend_from_slice(&identity.sign(&receipt.hash));
        assert!(receipt.validate_proof(&proof), "the subscriber's proof validates");

        assert!(handed_off.recv_timeout(Duration::from_millis(300)).is_err(), "a proved packet is not handed off");
    }

    #[test]
    fn an_unknown_subscriber_is_queued_and_pushed_at_once() {
        let stranger = Identity::new(true).hash.expect("hash");
        let stack = FakeStack::new(&[0; 16], None);
        let (hook, handed_off) = recording();
        assert_eq!(fan_out(&stack, &stranger, hook), 1);
        assert_eq!(handed_off.try_recv().expect("handed off"), the_subscriber(&stranger));
        assert!(stack.packets.lock().unwrap().is_empty());
    }

    #[test]
    fn a_packet_no_interface_takes_is_queued_and_pushed_and_its_path_requested() {
        let (_, sub_hash, delivery) = known_subscriber();
        let stack = FakeStack::new(&delivery, None).without_interface();
        let (hook, handed_off) = recording();
        assert_eq!(fan_out(&stack, &sub_hash, hook), 1);
        assert_eq!(handed_off.try_recv().expect("handed off"), the_subscriber(&sub_hash));
        assert_eq!(stack.path_requests.lock().unwrap().as_slice(), &[delivery]);
    }
}
