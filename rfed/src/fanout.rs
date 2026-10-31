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
//!
//! [`flush_queued`] is the other way a queued blob reaches a subscriber: the
//! `rfed.delivery` announce flush, over tier 1 or a packet as above.


use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, DATA, NONE, HEADER_1, FLAG_UNSET};
use reticulum_rust::{log, hexrep, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::deferred_queue::DeferredQueue;
use crate::handoff::{await_packet_proof, wake_for_queued, OnUnconfirmed, PacketProof, Unconfirmed, DELIVERY_PACKET_PROOF};
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
    /// The subscribers whose subscription to the channel expired as the plan
    /// was made (crate::subscription::SubscriptionTable::expire_stale): not
    /// in `subscribers`, and what they have queued on the channel is dropped.
    pub expired: Vec<Vec<u8>>,
}

impl FanoutPlan {
    /// Deliver `inner_blob` to every subscriber in the plan; every subscriber
    /// the delivery is not confirmed for is queued for `/channel/pull` and
    /// pushed ([`crate::handoff::defer_then_wake`]).
    ///
    /// Callers must not hold the `FedNode` mutex here — see the type's docs.
    pub fn run(&self, channel_dest_hash: &[u8], inner_blob: &[u8]) {
        self.drop_expired(channel_dest_hash);
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

    /// Drop what each subscription that expired had queued on the channel,
    /// and say so: nobody is left to pull it, and it only crowds the queue
    /// (RFed SPEC §6 "Renewal and expiry").
    fn drop_expired(&self, channel_dest_hash: &[u8]) {
        for subscriber in &self.expired {
            let dropped = self
                .deferred_queue
                .lock()
                .map(|mut queue| queue.drain_channel_batch(subscriber, channel_dest_hash, usize::MAX).len())
                .unwrap_or(0);
            log(
                format!(
                    "[channel] {}'s subscription to {} expired: not renewed in {} days; {} queued blob(s) dropped",
                    hexrep(subscriber, false),
                    hexrep(channel_dest_hash, false),
                    (crate::subscription::LOCAL_SUBSCRIPTION_LIFETIME_SECS / 86_400.0) as u64,
                    dropped,
                ),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }
}

/// What one announce flush did with the entries it sent copies of.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Pushed down the subscriber's bound `rfed.link`; its answer confirms.
    pub by_link: usize,
    /// Sent as `rfed.delivery` packets with a receipt; the proof confirms.
    pub by_packet: usize,
    /// Above the packet MDU, with no `rfed.link` bound for its channel.
    pub oversized: usize,
    /// Not transmitted: no interface took the packet, or no destination.
    pub not_sent: usize,
}

/// The `rfed.delivery` announce flush (RFed SPEC §7 "Delivery Triggers"):
/// send `subscriber`, whose announce for `delivery_hash` was just heard,
/// what it has queued under the routing hashes `wanted` admits. The entries
/// stay queued, and pullable, while they are sent
/// ([`DeferredQueue::flush_copies`]): a route's confirmation deletes one,
/// and one no route confirms waits for the pull, the subscriber pushed to
/// collect it ([`wake_for_queued`]). One not sent at all waits without a
/// push: the subscriber has just announced.
///
/// Each goes down the subscriber's bound `rfed.link` when it has bound the
/// channel, as tier 1 of the live fan-out, confirmed by its answer; else as
/// an `rfed.delivery` packet with a receipt, confirmed by its proof under
/// [`DELIVERY_PACKET_PROOF`].
///
/// Until 2026-10-30 the flush drained the entries, sent packets only, and
/// queued them again on each receipt timeout. The web client never proves
/// those packets and pulls 2 s after its announce, so its pull found its
/// backlog away for the ~30 s the receipts ran, at every announce; on
/// 2026-10-30 the re-queue met a full queue and eight #public.general posts
/// were lost.
#[allow(clippy::too_many_arguments)]
pub fn flush_queued(
    stack: Arc<dyn RelayStack + Send + Sync>,
    deferred_queue: &Arc<Mutex<DeferredQueue>>,
    notify_registry: &Arc<Mutex<NotifyRegistry>>,
    link_sessions: &Mutex<LinkSessionRegistry>,
    hook_registry: &Mutex<HookRegistry>,
    identity: &Identity,
    subscriber: &[u8],
    delivery_hash: &[u8],
    wanted: impl Fn(&[u8]) -> bool,
) -> Flushed {
    let mut flushed = Flushed::default();
    let copies = match deferred_queue.lock() {
        Ok(mut queue) => queue.flush_copies(subscriber, wanted),
        Err(_) => return flushed,
    };
    if copies.is_empty() {
        return flushed;
    }
    log(
        format!(
            "[deferred] subscriber {} (delivery {}) back online — flushing {} blob(s), each kept queued until confirmed",
            hexrep(subscriber, false),
            hexrep(delivery_hash, false),
            copies.len(),
        ),
        LOG_NOTICE,
        false,
        false,
    );

    let dest = match Destination::new_outbound(
        Some(identity.clone()),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec!["delivery".to_string()],
    ) {
        Ok(dest) => Some(dest),
        Err(e) => {
            log(
                format!("[deferred] no delivery destination for {}: {e}", hexrep(subscriber, false)),
                LOG_WARNING,
                false,
                false,
            );
            None
        }
    };
    // Queued under the identity hash the pull takes by; woken under the key
    // its registration is stored under.
    let recipient = Unconfirmed { queue_key: subscriber.to_vec(), wake_key: crate::notify::notify_key(subscriber) };
    let hooks = hook_registry.lock().ok();
    let mut unsent: Vec<u64> = Vec::new();
    for entry in &copies {
        let ticket = entry.ticket();
        let confirmed: Arc<dyn Fn() + Send + Sync> = {
            let queue = Arc::clone(deferred_queue);
            let subscriber = subscriber.to_vec();
            Arc::new(move || {
                if let Ok(mut queue) = queue.lock() {
                    queue.confirm(&subscriber, ticket);
                }
            })
        };
        let unconfirmed: Arc<dyn Fn() + Send + Sync> = {
            let (stack, queue, notify) = (Arc::clone(&stack), Arc::clone(deferred_queue), Arc::clone(notify_registry));
            let (recipient, channel, blob) = (recipient.clone(), entry.channel_hash.clone(), entry.blob.clone());
            Arc::new(move || {
                let waiting = queue.lock().map(|mut queue| queue.release(&recipient.queue_key, ticket)).unwrap_or(false);
                if waiting {
                    wake_for_queued(&*stack, &notify, &recipient, &channel, &blob, Some(&channel));
                }
            })
        };
        let mut payload = entry.channel_hash.clone();
        payload.extend_from_slice(&entry.blob);

        // Tier 1 first, as the live fan-out: the link the client keeps open
        // and answers on. Until 2026-10-30 the flush sent packets only.
        let linked = link_sessions.lock().ok().and_then(|mut registry| {
            registry.has_channel_session(subscriber, &entry.channel_hash).then(|| {
                registry.dispatch_channel(
                    subscriber,
                    &entry.channel_hash,
                    &payload,
                    Some(Arc::clone(&unconfirmed)),
                    Some(Arc::clone(&confirmed)),
                )
            })
        });
        if linked.is_some_and(|result| result.delivered()) {
            flushed.by_link += 1;
            if let Some(ref hooks) = hooks {
                hooks.on_deliver(subscriber, &entry.blob);
            }
            continue;
        }

        // A blob above the packet MDU can never leave as a single DATA
        // packet: Packet::send fails with "exceeds MTU" every time. Until
        // 2026-09-23 that failure re-enqueued the blob and every announce
        // tried the same impossible send again. It waits for the pull.
        if !crate::destinations::fits_in_delivery_packet(payload.len()) {
            flushed.oversized += 1;
            unsent.push(ticket);
            continue;
        }
        let Some(dest) = dest.as_ref() else {
            flushed.not_sent += 1;
            unsent.push(ticket);
            continue;
        };
        let mut packet = Packet::new(
            Some(dest.clone()),
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
                await_packet_proof(
                    &receipt,
                    format!("deferred flush of {} to {}", hexrep(&entry.channel_hash, false), hexrep(subscriber, false)),
                    DELIVERY_PACKET_PROOF,
                    Some(confirmed),
                    unconfirmed,
                );
                flushed.by_packet += 1;
                if let Some(ref hooks) = hooks {
                    hooks.on_deliver(subscriber, &entry.blob);
                }
            }
            // No usable interface right now: it waits for the pull or the
            // next announce.
            Ok(None) => {
                log(
                    format!("[deferred] send to {} not transmitted (no usable interface) — left queued", hexrep(subscriber, false)),
                    LOG_NOTICE,
                    false,
                    false,
                );
                flushed.not_sent += 1;
                unsent.push(ticket);
            }
            Err(e) => {
                log(
                    format!("[deferred] send to {} failed: {e} — left queued", hexrep(subscriber, false)),
                    LOG_WARNING,
                    false,
                    false,
                );
                flushed.not_sent += 1;
                unsent.push(ticket);
            }
        }
    }
    if !unsent.is_empty() {
        if let Ok(mut queue) = deferred_queue.lock() {
            for ticket in &unsent {
                queue.release(subscriber, *ticket);
            }
        }
    }
    if flushed.oversized > 0 {
        log(
            format!(
                "[deferred] {} blob(s) for {} exceed the {}-byte packet MDU and no rfed.link is bound for their channel — left queued for /channel/pull",
                flushed.oversized,
                hexrep(subscriber, false),
                reticulum_rust::packet::ENCRYPTED_MDU,
            ),
            LOG_NOTICE,
            false,
            false,
        );
    }
    flushed
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

        // A channel subscriber is queued under its subscriber hash (the
        // identity hash subscribe_cb stored, which the pull drains by) and
        // woken under its lxmf.delivery hash, the key its notify
        // registration and push token are under (crate::notify::notify_key).
        // Until 2026-09-26 it was woken under the identity hash, which no
        // bridge had a token for.
        let subscriber = Unconfirmed { queue_key: sub_hash.clone(), wake_key: crate::notify::notify_key(sub_hash) };
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
            Some(registry.dispatch_channel(sub_hash, channel_dest_hash, &payload, Some(hand_off_later()), None))
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
                    None,
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

    /// Queued under its identity hash, woken under its lxmf.delivery hash
    /// (crate::notify::notify_key), where its push token is.
    fn the_subscriber(sub_hash: &[u8]) -> Unconfirmed {
        Unconfirmed { queue_key: sub_hash.to_vec(), wake_key: crate::notify::notify_key(sub_hash) }
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

    // ── The announce flush (flush_queued, 2026-10-30) ─────────────────────

    use reticulum_rust::packet::PacketReceipt;

    const CHANNEL: [u8; 16] = [0xC1; 16];

    struct Flush {
        dir: std::path::PathBuf,
        queue: Arc<Mutex<DeferredQueue>>,
        notify: Arc<Mutex<NotifyRegistry>>,
        links: Mutex<LinkSessionRegistry>,
        hooks: Mutex<HookRegistry>,
    }

    impl Flush {
        fn new(tag: &str) -> Flush {
            let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("rfed_flush_{tag}_{unique}"));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Flush {
                queue: Arc::new(Mutex::new(DeferredQueue::load(dir.join("deferred.rmp")))),
                notify: Arc::new(Mutex::new(NotifyRegistry::load(dir.join("notify.rmp")))),
                links: Mutex::new(LinkSessionRegistry::default()),
                hooks: Mutex::new(HookRegistry::new()),
                dir,
            }
        }

        fn queue_blob(&self, sub_hash: &[u8], blob: &[u8]) {
            self.queue.lock().unwrap().enqueue(sub_hash.to_vec(), CHANNEL.to_vec(), blob.to_vec(), 256);
        }

        fn run(&self, stack: &Arc<FakeStack>, identity: &Identity, sub_hash: &[u8], delivery: &[u8]) -> Flushed {
            flush_queued(
                Arc::clone(stack) as Arc<dyn RelayStack + Send + Sync>,
                &self.queue,
                &self.notify,
                &self.links,
                &self.hooks,
                identity,
                sub_hash,
                delivery,
                |_| true,
            )
        }

        fn queued(&self, sub_hash: &[u8]) -> usize {
            self.queue.lock().unwrap().count_matching(sub_hash, &CHANNEL)
        }
    }

    impl Drop for Flush {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Wait for a hook's thread to act.
    fn eventually(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn prove(receipt: &mut PacketReceipt, identity: &Identity) {
        let mut proof = receipt.hash.clone();
        proof.extend_from_slice(&identity.sign(&receipt.hash));
        assert!(receipt.validate_proof(&proof), "the subscriber's proof validates");
    }

    /// The `[handoff]` line of a flushed blob nothing confirmed, from any
    /// thread: the receipt's timeout runs it on one of its own.
    fn handoff_lines(mark: &crate::test_log::Mark, sub_hash: &[u8]) -> Vec<String> {
        mark.any_thread_containing(&format!(
            "[handoff] {} unconfirmed for",
            hexrep(&crate::notify::notify_key(sub_hash), false)
        ))
    }

    /// The web client never proves the flush's packets and pulls 2 s after
    /// its announce. The flushed blobs stay queued meanwhile, so that pull
    /// gets them; a proof deletes its blob, and one never proved stays for
    /// the pull, its subscriber woken. Until 2026-10-30 the flush drained
    /// them, and the pull found nothing until the receipts timed out.
    #[test]
    fn the_flush_keeps_its_blobs_queued_until_a_proof() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let stack = Arc::new(FakeStack::new(&delivery, None));
        let flush = Flush::new("keeps");
        flush.queue_blob(&sub_hash, b"one");
        flush.queue_blob(&sub_hash, b"two");

        assert_eq!(flush.run(&stack, &identity, &sub_hash, &delivery), Flushed { by_packet: 2, ..Default::default() });
        assert_eq!(flush.queued(&sub_hash), 2, "both still queued while their receipts run");
        let (page, pulled) = flush.queue.lock().unwrap().take_page(&sub_hash, |_| true, 25, usize::MAX, |_| 1);
        assert_eq!(pulled.len(), 2, "a pull meanwhile gets them");
        flush.queue.lock().unwrap().settle_page(page, false);

        let mut receipts = stack.receipts.lock().unwrap().clone();
        prove(&mut receipts[0], &identity);
        eventually("the proved blob is deleted", || flush.queued(&sub_hash) == 1);

        let mark = crate::test_log::mark();
        receipts[1].set_timeout(0.0);
        receipts[1].check_timeout();
        eventually("the subscriber is woken for the unproven one", || !handoff_lines(&mark, &sub_hash).is_empty());
        let lines = handoff_lines(&mark, &sub_hash);
        assert!(lines[0].contains(": queued for pull, woken via 0 of 0"), "{}", lines[0]);
        assert_eq!(
            flush.run(&stack, &identity, &sub_hash, &delivery),
            Flushed { by_packet: 1, ..Default::default() },
            "out of flight, so the next announce sends it again"
        );
        let left = flush.queue.lock().unwrap().drain(&sub_hash);
        assert_eq!(left.iter().map(|e| e.blob.clone()).collect::<Vec<_>>(), vec![b"two".to_vec()], "it waits for the pull");
    }

    /// A proof that lands after the receipt timed out still deletes the
    /// blob: the device has it, so its next pull need not bring it again.
    #[test]
    fn a_late_proof_still_deletes_the_blob() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let stack = Arc::new(FakeStack::new(&delivery, None));
        let flush = Flush::new("late");
        flush.queue_blob(&sub_hash, b"one");
        flush.run(&stack, &identity, &sub_hash, &delivery);

        let mark = crate::test_log::mark();
        let mut receipt = stack.receipts.lock().unwrap()[0].clone();
        receipt.set_timeout(0.0);
        receipt.check_timeout();
        eventually("handed off on the timeout", || !handoff_lines(&mark, &sub_hash).is_empty());
        assert_eq!(flush.queued(&sub_hash), 1);
        prove(&mut receipt, &identity);
        eventually("deleted on the late proof", || flush.queued(&sub_hash) == 0);
    }

    /// An announce while the flush waits for its receipts sends nothing again.
    #[test]
    fn an_announce_during_a_flush_sends_nothing_twice() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let stack = Arc::new(FakeStack::new(&delivery, None));
        let flush = Flush::new("twice");
        flush.queue_blob(&sub_hash, b"one");
        assert_eq!(flush.run(&stack, &identity, &sub_hash, &delivery).by_packet, 1);
        assert_eq!(flush.run(&stack, &identity, &sub_hash, &delivery), Flushed::default(), "still in flight");
        assert_eq!(stack.packets.lock().unwrap().len(), 1);
    }

    /// A packet no interface took is not in flight: it waits, queued, and
    /// the next announce sends it. Nobody is pushed: the subscriber has just
    /// announced.
    #[test]
    fn a_blob_not_transmitted_waits_for_the_next_announce() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let flush = Flush::new("unsent");
        flush.queue_blob(&sub_hash, b"one");
        let mark = crate::test_log::mark();
        let dead = Arc::new(FakeStack::new(&delivery, None).without_interface());
        assert_eq!(flush.run(&dead, &identity, &sub_hash, &delivery), Flushed { not_sent: 1, ..Default::default() });
        assert_eq!(flush.queued(&sub_hash), 1);
        assert!(handoff_lines(&mark, &sub_hash).is_empty(), "nobody woken");
        let live = Arc::new(FakeStack::new(&delivery, None));
        assert_eq!(flush.run(&live, &identity, &sub_hash, &delivery).by_packet, 1, "released, so sent next time");
    }

    /// A blob above the packet MDU, with no rfed.link bound for its channel,
    /// is not tried as a packet: it waits for the pull.
    #[test]
    fn an_oversized_blob_without_a_link_waits_for_the_pull() {
        let (identity, sub_hash, delivery) = known_subscriber();
        let stack = Arc::new(FakeStack::new(&delivery, None));
        let flush = Flush::new("oversized");
        flush.queue_blob(&sub_hash, &vec![0x42; reticulum_rust::packet::ENCRYPTED_MDU]);
        assert_eq!(flush.run(&stack, &identity, &sub_hash, &delivery), Flushed { oversized: 1, ..Default::default() });
        assert!(stack.packets.lock().unwrap().is_empty());
        assert_eq!(flush.queued(&sub_hash), 1);
        assert_eq!(flush.run(&stack, &identity, &sub_hash, &delivery).oversized, 1, "not left in flight");
    }

    /// A subscription that expired as the plan was made: what it had queued
    /// on the channel is dropped, and the line says so; its entries for
    /// other channels stay.
    #[test]
    fn a_plan_drops_what_an_expired_subscription_had_queued() {
        let flush = Flush::new("expired");
        let gone = vec![0x0A; 16];
        let elsewhere = vec![0xC2; 16];
        flush.queue_blob(&gone, b"post");
        flush.queue.lock().unwrap().enqueue(gone.clone(), elsewhere.clone(), b"another channel's".to_vec(), 256);
        let plan = FanoutPlan {
            subscribers: Vec::new(),
            deferred_limits: HashMap::new(),
            hook_registry: Arc::new(Mutex::new(HookRegistry::new())),
            notify_registry: Arc::clone(&flush.notify),
            deferred_queue: Arc::clone(&flush.queue),
            channel_streams: Arc::new(Mutex::new(ChannelStreamRegistry::default())),
            link_sessions: Arc::new(Mutex::new(LinkSessionRegistry::default())),
            expired: vec![gone.clone()],
        };

        let mark = crate::test_log::mark();
        plan.run(&CHANNEL, b"a new post");
        assert_eq!(flush.queued(&gone), 0);
        assert_eq!(flush.queue.lock().unwrap().count_matching(&gone, &elsewhere), 1);
        let lines = mark.containing("subscription to");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].ends_with(&format!(
            "[channel] {}'s subscription to {} expired: not renewed in 30 days; 1 queued blob(s) dropped",
            hexrep(&gone, false),
            hexrep(&CHANNEL, false),
        )), "{}", lines[0]);
    }
}
