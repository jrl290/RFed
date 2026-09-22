//! `rfed.link` — the single bidirectional RFed endpoint.
//!
//! See `RFed-spec/Link.md`. This module owns two things:
//!
//!   1. [`paths`] — the complete request-path table for `rfed.link`, in both
//!      directions. One place answers "what does rfed.link expose?".
//!   2. [`LinkSessionRegistry`] — the links a client has bound for push, and
//!      the node → client dispatch over them.
//!
//! # Why a request and not a DATA packet
//!
//! The legacy stream destinations push with `link.send_packet`, which is
//! fire-and-forget: the node learns nothing about whether the subscriber got
//! the blob. On `rfed.link` a push is a REQUEST, so the client's RESPONSE is
//! the delivery proof — a deterministic protocol event rather than an elapsed
//! time (DESIGN_PRINCIPLES §1). When the request fails, the blob goes to the
//! deferred queue via the caller's `on_failed` hook and the client collects it
//! with `/channel/pull`. That is a change of delivery tier, not a retry (§3).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use reticulum_rust::link::{LinkHandle, RequestReceipt};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::stream_registry::StreamDispatchResult;

/// Every `rfed.link` request path.
///
/// The rule (RFed-spec/Link.md): the path is the destination's aspect chain
/// with `.` replaced by `/`, plus the operation verb when the aspect chain does
/// not already name it. `rfed.channel.pull` → `/channel/pull`.
///
/// NEVER rename one of these in place. A path is hashed into the wire request
/// (`truncated_hash(path)`), so a rename is a silent 404 for every deployed
/// client — the exact failure `CHECK_THESE_THINGS_FIRST.md` exists to prevent.
pub mod paths {
    // ── client → node ────────────────────────────────────────────────
    /// `rfed.node` `/rfed/offer`
    pub const NODE_OFFER: &str = "/node/offer";
    /// `rfed.node` `/rfed/get`
    pub const NODE_GET: &str = "/node/get";
    /// `rfed.node` `/rfed/backup/push`
    pub const NODE_BACKUP_PUSH: &str = "/node/backup/push";
    /// `rfed.node` `/rfed/capabilities`
    pub const NODE_CAPABILITIES: &str = "/node/capabilities";

    /// `rfed.channel.subscribe` `/rfed/subscribe`
    pub const CHANNEL_SUBSCRIBE: &str = "/channel/subscribe";
    /// `rfed.channel.unsubscribe` `/rfed/unsubscribe`
    pub const CHANNEL_UNSUBSCRIBE: &str = "/channel/unsubscribe";
    /// `rfed.channel.publish` DATA packet — as a request it also answers.
    pub const CHANNEL_PUBLISH: &str = "/channel/publish";
    /// `rfed.channel.pull` `/rfed/pull`
    pub const CHANNEL_PULL: &str = "/channel/pull";
    /// `rfed.channel.stream` `/rfed/channel/stream/open`
    pub const CHANNEL_STREAM_OPEN: &str = "/channel/stream/open";

    /// `rfed.propagation.stream` `/rfed/propagation/stream/open`
    pub const PROPAGATION_STREAM_OPEN: &str = "/propagation/stream/open";

    /// `rfed.notify.register` `/rfed/notify/register`
    pub const NOTIFY_REGISTER: &str = "/notify/register";
    /// `rfed.notify.unregister` `/rfed/notify/unregister`
    pub const NOTIFY_UNREGISTER: &str = "/notify/unregister";
    /// `rfed.notify` `/rfed/notify/clear`
    pub const NOTIFY_CLEAR: &str = "/notify/clear";

    /// `rfed.distro.register` `/rfed/distro/register`
    pub const DISTRO_REGISTER: &str = "/distro/register";
    /// `rfed.distro.register` `/rfed/distro/announce`
    pub const DISTRO_ANNOUNCE: &str = "/distro/announce";
    /// `rfed.distro.register` `/rfed/pull`
    pub const DISTRO_PULL: &str = "/distro/pull";
    /// `rfed.distro.unregister` `/rfed/distro/unregister`
    pub const DISTRO_UNREGISTER: &str = "/distro/unregister";
    /// `rfed.distro.list` `/rfed/distro/list`
    pub const DISTRO_LIST: &str = "/distro/list";

    // ── node → client ────────────────────────────────────────────────
    /// Channel fan-out push. Payload `channel_hash(16) | inner_blob(*)` —
    /// byte-identical to what `rfed.delivery` receives today.
    pub const DELIVERY: &str = "/delivery";
    /// LXMF propagation push. Payload is the packed LXMF message; its own
    /// leading 16 bytes are the recipient's `lxmf.delivery` hash.
    pub const LXMF_DELIVERY: &str = "/lxmf/delivery";
    /// Push-bridge wake packet. Payload is the Notify.md wake map.
    pub const NOTIFY: &str = "/notify";
}

/// One client's `rfed.link` link and what it has asked to be pushed.
///
/// A single link can carry both bindings: `/channel/stream/open` sets the
/// channel filter, `/propagation/stream/open` sets the LXMF delivery hash, and
/// both pushes then flow over the same link.
#[derive(Clone)]
struct LinkSession {
    link: LinkHandle,
    /// Subscriber identity hash — set by `/channel/stream/open`.
    subscriber_hash: Option<Vec<u8>>,
    /// Channel filter set — replaced wholesale on every stream open.
    channel_hashes: Vec<Vec<u8>>,
    /// `lxmf.delivery` hash — set by `/propagation/stream/open`.
    delivery_hash: Option<Vec<u8>>,
}

/// Does a session bound to `(subscriber, channels)` want this channel push?
///
/// Pulled out of the registry so it can be tested without a live link. The
/// cases that matter and cannot be read off the call site: a session with no
/// subscriber bound (`/propagation/stream/open` only) is not a channel
/// recipient, and an empty filter set means the client cleared its filters —
/// which must stop pushes, not pass everything.
fn wants_channel(
    bound_subscriber: Option<&[u8]>,
    bound_channels: &[Vec<u8>],
    subscriber_hash: &[u8],
    channel_hash: &[u8],
) -> bool {
    bound_subscriber == Some(subscriber_hash)
        && bound_channels
            .iter()
            .any(|configured| configured.as_slice() == channel_hash)
}

impl LinkSession {
    fn new(link: LinkHandle) -> Self {
        LinkSession {
            link,
            subscriber_hash: None,
            channel_hashes: Vec::new(),
            delivery_hash: None,
        }
    }
}

/// Every live `rfed.link` link that has bound itself for push, keyed by link id.
/// Remove every session other than `keep` for which `predicate` holds, and
/// return their ids. Generic over the session type so the rule can be tested
/// without a live `LinkHandle`.
pub(crate) fn evict_others<S, F>(sessions: &mut HashMap<Vec<u8>, S>, keep: &[u8], predicate: F) -> Vec<Vec<u8>>
where
    F: Fn(&S) -> bool,
{
    let mut evicted: Vec<Vec<u8>> = sessions
        .iter()
        .filter(|(link_id, session)| link_id.as_slice() != keep && predicate(session))
        .map(|(link_id, _)| link_id.clone())
        .collect();
    evicted.sort();
    for link_id in &evicted {
        sessions.remove(link_id.as_slice());
    }
    evicted
}

#[derive(Default)]
pub struct LinkSessionRegistry {
    sessions: HashMap<Vec<u8>, LinkSession>,
}

impl LinkSessionRegistry {
    /// Bind (or rebind) this link's channel filter set.
    ///
    /// Repeat calls are reconfiguration, not an error — the filter set is
    /// replaced, matching `rfed.channel.stream` semantics.
    ///
    /// Link.md "Binding the link for push": a subscriber holds ONE rfed.link
    /// link, so binding a subscriber hash on a new link replaces any earlier
    /// link bound for it; the replaced link ids are returned for the log.
    /// Before 2026-09-22 every link a device had ever bound stayed bound
    /// until RNS timed it out (~12 min for a browser page closed without
    /// LINKCLOSE), and each push went to all of them, waiting a request
    /// timeout on every dead one before the deferred queue took over.
    pub fn configure_channels(
        &mut self,
        link: LinkHandle,
        subscriber_hash: Vec<u8>,
        channel_hashes: Vec<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let link_id = link.link_id();
        let replaced = evict_others(&mut self.sessions, &link_id, |session| {
            session.subscriber_hash.as_deref() == Some(subscriber_hash.as_slice())
        });
        let entry = self
            .sessions
            .entry(link_id)
            .or_insert_with(|| LinkSession::new(link));
        entry.subscriber_hash = Some(subscriber_hash);
        entry.channel_hashes = channel_hashes;
        replaced
    }

    /// Bind (or rebind) this link's LXMF delivery hash. Same replacement
    /// rule as `configure_channels`; returns the replaced link ids.
    pub fn configure_delivery(&mut self, link: LinkHandle, delivery_hash: Vec<u8>) -> Vec<Vec<u8>> {
        let link_id = link.link_id();
        let replaced = evict_others(&mut self.sessions, &link_id, |session| {
            session.delivery_hash.as_deref() == Some(delivery_hash.as_slice())
        });
        let entry = self
            .sessions
            .entry(link_id)
            .or_insert_with(|| LinkSession::new(link));
        entry.delivery_hash = Some(delivery_hash);
        replaced
    }

    /// Drop a session. Called from the link-closed callback.
    pub fn remove(&mut self, link_id: &[u8]) -> bool {
        self.sessions.remove(link_id).is_some()
    }

    /// Whether this subscriber has any link bound for this channel.
    ///
    /// Cheap enough to ask before building a push: `dispatch_channel`'s
    /// `on_failed` hook has to own a copy of the blob, and a fan-out to
    /// hundreds of subscribers should not copy it for the ones that have no
    /// session at all.
    pub fn has_channel_session(&self, subscriber_hash: &[u8], channel_hash: &[u8]) -> bool {
        self.sessions.values().any(|session| {
            wants_channel(
                session.subscriber_hash.as_deref(),
                &session.channel_hashes,
                subscriber_hash,
                channel_hash,
            )
        })
    }

    /// Push a channel blob to every link this subscriber has bound for that
    /// channel. `payload` is `channel_hash(16) | inner_blob`.
    pub fn dispatch_channel(
        &mut self,
        subscriber_hash: &[u8],
        channel_hash: &[u8],
        payload: &[u8],
        on_failed: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> StreamDispatchResult {
        let matches = self.matching(|session| {
            wants_channel(
                session.subscriber_hash.as_deref(),
                &session.channel_hashes,
                subscriber_hash,
                channel_hash,
            )
        });
        self.dispatch(matches, paths::DELIVERY, payload, on_failed)
    }

    /// Push a packed LXMF message to every link bound to `delivery_hash`.
    pub fn dispatch_lxmf(
        &mut self,
        delivery_hash: &[u8],
        payload: &[u8],
        on_failed: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> StreamDispatchResult {
        let matches =
            self.matching(|session| session.delivery_hash.as_deref() == Some(delivery_hash));
        self.dispatch(matches, paths::LXMF_DELIVERY, payload, on_failed)
    }

    fn matching<F>(&self, predicate: F) -> Vec<(Vec<u8>, LinkHandle)>
    where
        F: Fn(&LinkSession) -> bool,
    {
        self.sessions
            .iter()
            .filter(|(_, session)| predicate(session))
            .map(|(link_id, session)| (link_id.clone(), session.link.clone()))
            .collect()
    }

    fn dispatch(
        &mut self,
        matches: Vec<(Vec<u8>, LinkHandle)>,
        path: &str,
        payload: &[u8],
        on_failed: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> StreamDispatchResult {
        let mut result = StreamDispatchResult {
            matched: matches.len(),
            sent: 0,
        };
        let mut stale_links = Vec::new();

        // One subscriber may have more than one link bound. `on_failed` defers
        // the blob, and deferring it once per unanswered link would queue the
        // same message several times — including when a sibling link did
        // deliver it. First failure wins; the rest are no-ops.
        let deferred_once = Arc::new(AtomicBool::new(false));
        let gated_failure = on_failed.map(|hook| {
            let gate = Arc::clone(&deferred_once);
            let gated: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if !gate.swap(true, Ordering::SeqCst) {
                    hook();
                }
            });
            gated
        });

        for (link_id, link) in matches {
            if !link.is_alive() {
                stale_links.push(link_id);
                continue;
            }
            if push_request(&link, path, payload, gated_failure.clone()) {
                result.sent += 1;
            } else {
                stale_links.push(link_id);
            }
        }

        // A link that could not carry the request is gone as far as this node
        // is concerned; drop it so the caller falls through to the next
        // delivery tier instead of matching a corpse on the next fan-out.
        for link_id in stale_links {
            self.sessions.remove(link_id.as_slice());
        }

        result
    }
}

/// Send one node → client request and wire up the acknowledgement callbacks.
///
/// Returns `false` when the request could not be dispatched at all (link gone,
/// payload not encodable), which is the caller's signal to try the next tier.
/// A dispatched-but-unanswered request is reported through `on_failed`, not
/// through this return value — by then the fan-out has moved on.
fn push_request(
    link: &LinkHandle,
    path: &str,
    payload: &[u8],
    on_failed: Option<Arc<dyn Fn() + Send + Sync>>,
) -> bool {
    // `LinkHandle::request` re-decodes `data` and embeds it inline in the
    // request array, so the payload has to arrive here already msgpack-encoded.
    // A bare `Vec<u8>` would be read back as garbage.
    let mut data = Vec::new();
    if rmpv::encode::write_value(&mut data, &rmpv::Value::Binary(payload.to_vec())).is_err() {
        log(
            format!("[rfed.link] {path}: could not encode {} byte payload", payload.len()),
            LOG_WARNING,
            false,
            false,
        );
        return false;
    }

    let link_hex = hexrep(&link.link_id(), false);
    let ack_path = path.to_string();
    let ack_link = link_hex.clone();
    let response_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |receipt| {
        let acked = receipt
            .response
            .as_deref()
            .map(|bytes| rmp_serde::from_slice::<bool>(bytes).unwrap_or(false))
            .unwrap_or(false);
        if acked {
            log(
                format!("[rfed.link] {ack_path} acknowledged by {ack_link}"),
                LOG_DEBUG,
                false,
                false,
            );
        } else {
            // The client answered and said no. Never silent — a refused push
            // that looks identical to a delivered one is how a whole class of
            // "message never arrived" reports become undiagnosable.
            log(
                format!("[rfed.link] {ack_path} REFUSED by {ack_link}"),
                LOG_WARNING,
                false,
                false,
            );
        }
    });

    let fail_path = path.to_string();
    let fail_link = link_hex.clone();
    let failed_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |_| {
        log(
            format!("[rfed.link] {fail_path} unanswered by {fail_link} — deferring"),
            LOG_WARNING,
            false,
            false,
        );
        if let Some(hook) = on_failed.as_ref() {
            hook();
        }
    });

    match link.request(
        path.to_string(),
        data,
        Some(response_cb),
        Some(failed_cb),
        None,
    ) {
        Ok(_) => {
            log(
                format!(
                    "[rfed.link] {path} pushed {} bytes to {link_hex}",
                    payload.len()
                ),
                LOG_NOTICE,
                false,
                false,
            );
            true
        }
        Err(_) => {
            log(
                format!("[rfed.link] {path} link {link_hex} gone — falling through"),
                LOG_WARNING,
                false,
                false,
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{paths, wants_channel};

    const SUB: &[u8] = b"subscriber-hash!";
    const OTHER_SUB: &[u8] = b"someone-else!!!!";
    const CHAN: &[u8] = b"channel-hash-16b";
    const OTHER_CHAN: &[u8] = b"other-channel!!!";

    fn filters(hashes: &[&[u8]]) -> Vec<Vec<u8>> {
        hashes.iter().map(|h| h.to_vec()).collect()
    }

    #[test]
    fn bound_subscriber_and_channel_is_a_match() {
        assert!(wants_channel(Some(SUB), &filters(&[CHAN]), SUB, CHAN));
    }

    #[test]
    fn another_subscribers_session_never_matches() {
        assert!(!wants_channel(Some(OTHER_SUB), &filters(&[CHAN]), SUB, CHAN));
    }

    #[test]
    fn a_channel_outside_the_filter_set_does_not_match() {
        assert!(!wants_channel(Some(SUB), &filters(&[OTHER_CHAN]), SUB, CHAN));
    }

    /// A link that only opened `/propagation/stream/open` has no subscriber
    /// bound. It must not receive channel pushes.
    #[test]
    fn a_session_with_no_subscriber_bound_does_not_match() {
        assert!(!wants_channel(None, &filters(&[CHAN]), SUB, CHAN));
    }

    /// RFed-spec/Link.md: an empty filter array clears the live filters. The
    /// link stays open with no channel fanout — "empty" must never be read as
    /// "everything".
    #[test]
    fn a_new_link_bound_for_the_same_subscriber_replaces_the_old_one() {
        // Link.md "Binding the link for push": one link per subscriber.
        let mut sessions: std::collections::HashMap<Vec<u8>, Option<Vec<u8>>> = Default::default();
        sessions.insert(vec![1; 16], Some(b"device-A".to_vec()));
        sessions.insert(vec![2; 16], Some(b"device-A".to_vec()));
        sessions.insert(vec![3; 16], Some(b"device-B".to_vec()));
        sessions.insert(vec![4; 16], None);
        let replaced = super::evict_others(&mut sessions, &[9; 16], |bound| bound.as_deref() == Some(b"device-A".as_slice()));
        assert_eq!(replaced, vec![vec![1; 16], vec![2; 16]], "both of device A's earlier links are replaced");
        assert!(sessions.contains_key(&vec![3; 16]), "device B's link is untouched");
        assert!(sessions.contains_key(&vec![4; 16]), "an unbound session is untouched");
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn rebinding_the_same_link_replaces_nothing() {
        let mut sessions: std::collections::HashMap<Vec<u8>, Option<Vec<u8>>> = Default::default();
        sessions.insert(vec![1; 16], Some(b"device-A".to_vec()));
        let replaced = super::evict_others(&mut sessions, &[1; 16], |bound| bound.as_deref() == Some(b"device-A".as_slice()));
        assert!(replaced.is_empty(), "a repeat open on the same link is reconfiguration, not replacement");
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn an_empty_filter_set_stops_pushes() {
        assert!(!wants_channel(Some(SUB), &[], SUB, CHAN));
    }

    /// The `.`→`/` rule from RFed-spec/Link.md, asserted mechanically.
    ///
    /// Every entry is `(legacy aspect chain, rfed.link path)`. If a path is
    /// ever edited to something that is not its aspect chain, this fails —
    /// which is cheaper than discovering it from a client that gets no
    /// response and cannot say why.
    #[test]
    fn every_path_is_its_aspect_chain() {
        let table: &[(&str, &str)] = &[
            ("node.offer", paths::NODE_OFFER),
            ("node.get", paths::NODE_GET),
            ("node.backup.push", paths::NODE_BACKUP_PUSH),
            ("node.capabilities", paths::NODE_CAPABILITIES),
            ("channel.subscribe", paths::CHANNEL_SUBSCRIBE),
            ("channel.unsubscribe", paths::CHANNEL_UNSUBSCRIBE),
            ("channel.publish", paths::CHANNEL_PUBLISH),
            ("channel.pull", paths::CHANNEL_PULL),
            ("channel.stream.open", paths::CHANNEL_STREAM_OPEN),
            ("propagation.stream.open", paths::PROPAGATION_STREAM_OPEN),
            ("notify.register", paths::NOTIFY_REGISTER),
            ("notify.unregister", paths::NOTIFY_UNREGISTER),
            ("notify.clear", paths::NOTIFY_CLEAR),
            ("distro.register", paths::DISTRO_REGISTER),
            ("distro.announce", paths::DISTRO_ANNOUNCE),
            ("distro.pull", paths::DISTRO_PULL),
            ("distro.unregister", paths::DISTRO_UNREGISTER),
            ("distro.list", paths::DISTRO_LIST),
            ("delivery", paths::DELIVERY),
            ("lxmf.delivery", paths::LXMF_DELIVERY),
            ("notify", paths::NOTIFY),
        ];

        for (dotted, path) in table {
            assert_eq!(
                format!("/{}", dotted.replace('.', "/")),
                *path,
                "rfed.link path for {dotted} must be its aspect chain",
            );
        }
    }

    /// Two paths hashing to the same request handler key would make one of them
    /// unreachable, and the loser would be whichever registered second.
    #[test]
    fn paths_are_pairwise_distinct() {
        let all = [
            paths::NODE_OFFER,
            paths::NODE_GET,
            paths::NODE_BACKUP_PUSH,
            paths::NODE_CAPABILITIES,
            paths::CHANNEL_SUBSCRIBE,
            paths::CHANNEL_UNSUBSCRIBE,
            paths::CHANNEL_PUBLISH,
            paths::CHANNEL_PULL,
            paths::CHANNEL_STREAM_OPEN,
            paths::PROPAGATION_STREAM_OPEN,
            paths::NOTIFY_REGISTER,
            paths::NOTIFY_UNREGISTER,
            paths::NOTIFY_CLEAR,
            paths::DISTRO_REGISTER,
            paths::DISTRO_ANNOUNCE,
            paths::DISTRO_PULL,
            paths::DISTRO_UNREGISTER,
            paths::DISTRO_LIST,
            paths::DELIVERY,
            paths::LXMF_DELIVERY,
            paths::NOTIFY,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "duplicate rfed.link path");
            }
        }
    }

    /// `/delivery` and `/lxmf/delivery` both carry a leading 16-byte hash with
    /// different meanings. If they ever collapsed to one path the client would
    /// have to guess, which RFed-spec/Link.md forbids.
    #[test]
    fn push_paths_discriminate_payload_type() {
        assert_ne!(paths::DELIVERY, paths::LXMF_DELIVERY);
        assert!(paths::LXMF_DELIVERY.starts_with("/lxmf/"));
    }
}
