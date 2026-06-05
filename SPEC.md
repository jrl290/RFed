# rfed — Reticulum Federation Node

> **Version 0.1.0** · Protocol version 1
>
> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models (Claude / GitHub Copilot). Architecture
> decisions, implementation, code review, and this specification were produced
> through an iterative human–AI collaboration. All code has been reviewed and
> tested by the human author.

## Overview

**rfed** is a store-and-forward federation node for the
[Reticulum](https://reticulum.network) network. It provides named **channel**
messaging with offline delivery, cross-node synchronisation, notify
wake-ups, and subscriber backup failover — all running over Reticulum's
encrypted transport layer.

Nodes form a loosely-coupled mesh: each node independently accepts blobs,
fans them out to local subscribers, and synchronises with peers. There is no
central coordinator. Any node can join or leave the federation at any time.

### Design Principles

- **Dumb store, smart clients** — the node never interprets blob content.
  Channels exist by virtue of blobs stored against their hash.
- **Sender anonymity** — Reticulum Single destinations carry no sender identity
  in the wire header. LXMF optionally embeds sender inside the encrypted
  envelope.
- **Zero server-side channel registration** — any party that knows a channel
  name can independently derive its hash and publish/subscribe.
- **Encrypted at every hop** — all data packets use `DestinationType::Single`
  (asymmetric encryption). No plaintext broadcasts.

---

### TL-DR Summary
- Channel participants get the plaintext address which translates into the public and private keys
- Sender creates an LXMF packet addressed to and encrypted for the channel. Now it includes the prelude for ID verification
- Sender wraps that packet in a Reticulum packet addressed to his RFed node
- RFed node unwraps the packet and rewraps it in a Reticulum packet addressed to each subscriber
- The subscriber unwraps the packet and gets the LXMF packet addressed to the channel
- The subscriber uses the Channel credentials to decrypt the message. He has the prelude and signing from the sender to verify the identity of the sender

---

## CANONICAL WIRE FORMAT — ULTIMATE AUTHORITY

> **THIS SECTION IS THE ONE TRUE SOURCE OF TRUTH FOR THE CHANNEL
> MESSAGE FORMAT. If any other section, comment, or document
> disagrees with this one, this section wins and the other one is a
> bug. Update this section *first*, then propagate.**

### The four nested envelopes (sender → subscriber)

A channel message is a propagation-style LXMF message wrapped in two
Reticulum hops (sender → RFed node, RFed node → each subscriber). All
encryption is asymmetric (`DestinationType::Single`); RFed is dumb and
never decrypts the payload.

```
Layer 4 (innermost — application):
    plaintext = [ "RTID"(4) | sender_identity_pub(64) | LXMF_tail ]
    where
        sender_identity_pub = Identity::get_public_key()           (32 X25519 enc || 32 Ed25519 sign)
        LXMF_tail           = source_hash(16) | signature(64) | msgpack_payload
        source_hash         = the sender's lxmf.delivery DESTINATION hash
                            = truncated_hash( name_hash("lxmf.delivery") || identity_hash )
                              — NOT truncated_hash(sender_identity_pub).

Layer 3 (LXMF EC envelope, addressed to the CHANNEL identity):
    inner_blob = EC_encrypt( channel_identity.X25519_pub , plaintext )
               = ephemeral_pub(32) | ciphertext | hmac
    Channel identity is derived deterministically from the channel name —
    see §1. Channel Hash Derivation. All subscribers + the sender hold
    the channel private key.

Layer 2 (RFed wire payload, what the sender PUTs to /rfed/send):
    rfed_payload = [ channel_hash(16) | inner_blob | stamp(32) ]
    channel_hash = the channel's identity hash (16 B), used by RFed
                   purely as a routing label; subscribers proved knowledge
                   of it via signed /rfed/subscribe.
    stamp        = LXMF PoW stamp over
                   sha256( channel_hash(16) || inner_blob ), with
                   STAMP_EXPAND_ROUNDS = 16 (see PoW STAMP CONTRACT below).

Layer 1 (Reticulum transport — first hop):
    Reticulum DATA packet, DestinationType::Single, addressed to
    rfed.send (the RFed node's send endpoint). RFed decrypts the outer
    Reticulum envelope with its node identity, validates the stamp,
    strips it, and stores `inner_blob` keyed by channel_hash.

Layer 1' (Reticulum transport — fanout hop, one per subscriber):
    For every subscriber S of channel_hash, RFed sends a Reticulum
    DATA packet, DestinationType::Single, addressed to S's
    rfed.delivery endpoint, with payload:
        [ channel_hash(16) | inner_blob ]
    (No stamp on the fanout hop — stamp was already validated at ingest.)
```

### Subscriber decode (exact inverse)

1. Reticulum decrypts the outer packet with the subscriber's node
   identity → exposes `[ channel_hash(16) | inner_blob ]`.
2. Look up `channel_hash` in the subscriber's local channel table to
   find the matching channel name and re-derive the channel identity
   (private key + public key) per §1.
3. EC-decrypt `inner_blob` with the **channel** private key → recover
   the Layer-4 plaintext.
4. Verify magic `"RTID"` and split off the 64-byte
   `sender_identity_pub`. **Do NOT compare
   `truncated_hash(sender_identity_pub)` against `source_hash` — those
   are different hashes.** `source_hash` is the lxmf.delivery
   destination hash; the bare identity hash is just one of its inputs.
5. Call `Identity::remember_destination(source_hash, sender_identity_pub, None)`
   to populate Reticulum's known-destinations cache.
6. Prepend the channel's `lxmf.delivery` destination hash to the
   LXMF tail and feed to
   `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`.
7. LXMF Ed25519 signature validation runs against the just-cached
   `sender_identity_pub`. **This is the integrity check** — a forged
   `sender_identity_pub` produces `SIGNATURE_INVALID`. Cache poisoning
   by an unauthorised party is impossible because reaching step 3
   already required the channel EC private key.

### Why the prelude exists

Without it, `LXMessage::unpack(PROPAGATED)` rejects the message as
`SOURCE_UNKNOWN` whenever the sender's `lxmf.delivery` announce hasn't
recently traversed the receiver — the same announce-timing flakiness
that plagues regular LXMF ("have to be online at the right moment").
The prelude embeds the sender pubkey inside the EC envelope, so
signature validation works on the very first message a receiver ever
sees, period.

### Invariants you may NOT break

- **Magic** is the four ASCII bytes `"RTID"`. Not `"RTI "`, not
  little-endian, not length-prefixed.
- **`sender_identity_pub` is 64 bytes** in `Identity::get_public_key()`
  layout. `Identity::from_public_key` is its inverse.
- **`source_hash` is the destination hash, not the identity hash.**
  Repeat: `truncated_hash(name_hash || identity_hash)`, not
  `truncated_hash(public_key)`.
- **The prelude is mandatory.** No legacy fallback path. Receivers
  MUST refuse blobs without `"RTID"`.
- **RFed never inspects the prelude** — it lives inside the EC
  envelope. RFed only sees `[ channel_hash | inner_blob | stamp ]`.
- **`STAMP_EXPAND_ROUNDS = 16`** on every implementation, forever.
  Bumping it silently invalidates every cached `stamp_cost` and
  every in-flight stamp.
- **`stamp_cost` is owned exclusively by `/rfed/subscribe`'s
  `[true, cost_or_nil]` reply.** `Some(0)` means disabled, identical
  to `None`. Re-subscribe per session and on every SEND rejection.

### Bytes-on-the-wire reference (typical)

```
sizeof channel_hash      = 16
sizeof prelude magic     =  4   ("RTID")
sizeof sender_id_pub     = 64
sizeof source_hash       = 16
sizeof signature         = 64
sizeof stamp             = 32
→ inner_blob = ECC overhead(~48) + 4 + 64 + 16 + 64 + msgpack_payload
→ rfed_payload = 16 + inner_blob + 32
```

A "hello" message of ~7 bytes UTF-8 produces `inner_blob ≈ 256`,
`rfed_payload ≈ 304` — confirmed in retichat.log April 25 2026.

---

## Table of Contents

1. [Channel Hash Derivation](#1-channel-hash-derivation)
2. [RNS Destinations & Request Paths](#2-rns-destinations--request-paths)
3. [Wire Formats](#3-wire-formats)
4. [Sync Protocol](#4-sync-protocol)
5. [Blob Storage](#5-blob-storage)
6. [Subscription Table](#6-subscription-table)
7. [Deferred Delivery](#7-deferred-delivery)
8. [Fanout & Double Envelope](#8-fanout--double-envelope)
9. [Notify System](#9-notify-system)
10. [LXMF Propagation Relationship](#10-lxmf-propagation-relationship)
11. [Backup Failover](#11-backup-failover)
12. [Announce Format](#12-announce-format)
13. [Configuration](#13-configuration)
14. [CLI Reference](#14-cli-reference)
15. [Test Suite](#15-test-suite)
16. [Dependencies](#16-dependencies)

---

## 1. Channel Hash Derivation

Channels are identified by a deterministic 16-byte hash derived from a
plain-text channel name. Any party that knows the name can independently
compute the same hash — no server-side registration is needed.

### Algorithm

```
seed          = SHA-256(channel_name)                        → 32 bytes
x25519_pub    = X25519_public_key_from(seed)                 → 32 bytes
ed25519_pub   = Ed25519_public_key_from(seed)                → 32 bytes
bundle        = x25519_pub ‖ ed25519_pub                     → 64 bytes
channel_hash  = SHA-256(bundle)[0..16]                       → 16 bytes
```

This mirrors Reticulum's own `Identity` hash derivation: the hash is
computed over the 64-byte public key bundle, then truncated to the first
16 bytes (`TRUNCATED_HASHLENGTH / 8`).

### Rust Implementation

```rust
use sha2::{Digest, Sha256};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519Public};
use ed25519_dalek::{SecretKey as Ed25519Secret, PublicKey as Ed25519Public};

fn channel_hash(name: &str) -> Vec<u8> {
    let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();

    let x_secret = X25519Secret::from(seed);
    let x_public = X25519Public::from(&x_secret);

    let e_secret = Ed25519Secret::from_bytes(&seed).unwrap();
    let e_public = Ed25519Public::from(&e_secret);

    let mut bundle = Vec::with_capacity(64);
    bundle.extend_from_slice(x_public.as_bytes());
    bundle.extend_from_slice(e_public.as_bytes());

    Sha256::digest(&bundle)[..16].to_vec()
}
```

### Python Implementation

```python
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def compute_channel_hash(name: str) -> bytes:
    seed = hashlib.sha256(name.encode("utf-8")).digest()      # 32 bytes

    x_priv = X25519PrivateKey.from_private_bytes(seed)
    x_pub  = x_priv.public_key().public_bytes_raw()           # 32 bytes

    e_priv = Ed25519PrivateKey.from_private_bytes(seed)
    e_pub  = e_priv.public_key().public_bytes_raw()            # 32 bytes

    bundle = x_pub + e_pub                                     # 64 bytes
    return hashlib.sha256(bundle).digest()[:16]
```

### Naming Convention

| Pattern | Visibility | Example |
|---------|-----------|---------|
| `public.<segments>` | Discoverable by name | `public.news.tech` |
| `<hash>.<segments>` | Private; hash acts as access control | `a1b2c3d4e5f6....<segments>` |

Segments are dot-separated, mirroring Reticulum's aspect notation:

```python
channel_path("public", "news", "tech")           # → "public.news.tech"
channel_path("a1b2c3d4e5f6", "team", "ops")      # → "a1b2c3d4e5f6.team.ops"
```

For **public** channels the first segment is the literal string `"public"`.
Anyone who learns the name can subscribe and decrypt.

For **private** channels, the first segment should be a cryptographically
random hex string (32+ characters generated by a CSPRNG). Since possession
of the channel name equals possession of the decryption key, the random
prefix makes it computationally infeasible to guess the name. Distribute
the full channel name out-of-band to intended members only.

---

## 2. RNS Destinations & Request Paths

rfed exposes four logical Reticulum service groups under the `rfed` app
namespace. Modern clients should discover and use the split announced
destinations `rfed.channel.subscribe`, `rfed.channel.unsubscribe`,
`rfed.channel.publish`, `rfed.channel.pull`, `rfed.notify.register`, and
`rfed.notify.unregister`. The legacy combined `rfed.channel`, `rfed.delivery`,
and `rfed.notify` surfaces remain wired for compatibility while clients
migrate.

In official Reticulum terminology, these are two separate notations:

- **Destinations** are named by app and aspects, commonly rendered in dot
  notation such as `rfed.channel.subscribe`.
- **Request handlers** on an established link use a separate request-path
  string. RFed follows the slash-prefixed convention used in upstream
  Reticulum examples and built-in handlers, such as `/random/text`, `/status`,
  `/list`, and therefore `/rfed/subscribe`.

| Destination | Aspects | Purpose |
|-------------|---------|---------|
| `rfed.node` | `["node"]` | Peer sync, announces, backup push |
| `rfed.channel` | `["channel"]` | Channel publish / subscribe / pull service family |
| `rfed.delivery` | `["delivery"]` | Live subscriber delivery plus legacy aggregate pull |
| `rfed.notify` | `["notify"]` | Notify relay registration service family |

All destinations use `DestinationType::Single` (asymmetric encryption,
multi-hop routed).

### Request Paths

**rfed.node** (peer-to-peer):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/offer` | Peer | `msgpack [message_id, ...]` | `msgpack [(channel_hash, message_id), ...]` |
| `/rfed/get` | Peer | `msgpack [message_id, ...]` | Binary blob stream (see §3) |
| `/rfed/backup/push` | Owner node | `msgpack [(sub_hash, ch_hash), ...]` | `msgpack bool` |
| `/rfed/capabilities` | Any | *(ignored)* | `msgpack Map` (see §17) |

**rfed.channel.*** (modern split service destinations):
| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.channel.subscribe` | `/rfed/subscribe` | Subscriber | `msgpack [bin(16) channel_hash, bin(64) subscriber_pubkey, bin(64) sig(channel_hash)]` | `msgpack [bool ok, uint stamp_cost \| nil]` |
| `rfed.channel.unsubscribe` | `/rfed/unsubscribe` | Subscriber | `msgpack [bin(16) channel_hash, bin(64) subscriber_pubkey, bin(64) sig(channel_hash)]` | `msgpack bool` |
| `rfed.channel.publish` | *(fire-and-forget SEND)* | Publisher | `channel_hash(16) \| inner_blob \| stamp` | *(none)* |
| `rfed.channel.pull` | `/rfed/pull` | Subscriber | `bin(16) channel_hash` or `msgpack bin(16)` | `msgpack [ [[bin(16) channel_hash, bin blob], …], bool more_pending ]` |

**rfed.delivery** (live fanout destination + legacy aggregate pull):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/pull` | Subscriber | *(empty — caller authenticated by link identity)* | `msgpack [ [[bin(16) channel_hash, bin blob], …], bool more_pending ]` |

**PULL paging** (user-initiated; mirrors chat-history "Load earlier
messages"): each call drains at most one page (`deferred_pull_batch_limit`
or `DEFAULT_PULL_PAGE_SIZE = 25`) and returns `more_pending = true` when
additional entries remain for the caller. The client offers another
page-load action while `more_pending` is true and stops once it is false.
Drain is destructive on the server side — once a page has been returned
those blobs are gone from this node and will only re-arrive via fanout
from another session or sync from the origin.

**rfed.notify** (subscriber → node):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/notify/register` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/unregister` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/clear` | Subscriber | *(empty)* | `msgpack bool` |

---

## 3. Wire Formats

### SEND Packet (fire-and-forget)

```
┌──────────────────┬──────────────────────┬──────────────┐
│ channel_hash(16) │     inner_blob       │   stamp      │
└──────────────────┴──────────────────────┴──────────────┘
```

- **channel_hash**: 16-byte channel **identity hash** of the target
  channel — the routing label RFed uses (subscribers signed it during
  `/rfed/subscribe`).
- **inner_blob**: **The EC-encrypted authentication payload from
  `lxmf_rust::LXMessage::pack(PROPAGATED)` — byte-identical to what an
  LXMF propagation node carries:**

  ```
  inner_blob = EC_encrypted( source-identity prelude || source_hash(16) || signature(64) || msgpack_payload )
  ```

  Immutable — RFed treats it OPAQUELY and never decrypts, parses or
  modifies it.

  **SOURCE-IDENTITY PRELUDE (Retichat extension, application-layer,
  RFed-agnostic, MANDATORY):** The EC plaintext starts with the 4-byte
  ASCII magic `"RTID"` followed by 64 bytes of sender identity public
  key (the format produced by Reticulum-rust's
  `Identity::get_public_key()` — 32 X25519 enc pub || 32 Ed25519 sign
  pub), then the LXMF tail. Receivers MUST call
  `Identity::remember_destination(source_hash, identity_pub, None)`
  with `source_hash` taken verbatim from the LXMF tail, then invoke
  `LXMessage::unpack_from_bytes`. **Do NOT pre-check
  `truncated_hash(identity_pub) == source_hash`** — `source_hash` is
  the lxmf.delivery DESTINATION hash, not the bare identity hash, so
  that equality never holds and would reject every legitimate
  message. The integrity guarantee is provided by LXMF's own Ed25519
  signature validation (forged `identity_pub` → `SIGNATURE_INVALID`),
  and cache poisoning is impossible because reaching this code path
  required the channel EC private key (i.e. authorised subscriber).
  RFed never sees the prelude (it's inside the EC envelope). See the
  **CANONICAL WIRE FORMAT** section at the top of this file for the
  full layered diagram and decode procedure — that section is
  authoritative.

  **Why this exists:** Channel pub/sub means the sender and receivers
  may have no prior history — the sender's `lxmf.delivery` identity is
  not in the receiver's known-destinations cache, so
  `LXMessage::unpack_from_bytes(PROPAGATED)` would emit
  `unverified_reason = SOURCE_UNKNOWN` for every message until/unless
  the sender's announce coincidentally arrived. The prelude removes
  the announce-timing dependency entirely: signature validates on the
  very first message a receiver sees, period.

  The channel identity (which holds both the X25519 encryption key and
  the Ed25519 verification baseline) is derived deterministically from
  the channel name as
  `seed = sha256(name); private_key_bundle = seed || seed`. Any subscriber
  holding the channel name can re-derive the channel identity, EC-decrypt
  the inner_blob, and reconstruct the canonical LXMF block by prepending
  the `lxmf.delivery` destination_hash for the channel identity (= the
  hash a receiver sees if they treat the channel identity as an LXMF
  delivery destination), then feed the result to
  `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`, which validates
  the Ed25519 signature against the cached source identity.
- **stamp**: Proof-of-work stamp appended by the sender. Validated and
  stripped on ingest; only the clean inner_blob (= LXMF lxmf_data tail) is
  stored and synced.

  **PoW STAMP CONTRACT (must hold across rfed + retichat-ffi + iOS forever):**
  * Material that the stamp is bound to:
    `material = channel_id_hash(16) || inner_blob`
    (i.e. `data[..data.len() - LXStamper::STAMP_SIZE]` as the SEND
    handler sees it).
  * `transient_id = identity::full_hash(material)`
  * `workblock    = LXStamper::stamp_workblock(transient_id, 16)`
    — `STAMP_EXPAND_ROUNDS` MUST stay 16 on both sides.  Bumping it
    silently invalidates every previously-cached client `stamp_cost`
    and every in-flight stamp.  Don't.
  * Required PoW value: `LXStamper::stamp_value(workblock, stamp) >= cost`
    where `cost = stamp_cost - stamp_flexibility` (clamped at 0).
  * `stamp_cost` is advertised by `/rfed/subscribe`'s response
    `[true, stamp_cost_or_nil]`. There is no other authoritative source;
    rfed announces do not currently carry it.
  * `Some(0)` in node config == disabled (same as `None`). Both subscribe
    response and SEND validation MUST honor this.
  * Clients MUST refresh their cached `stamp_cost` by re-issuing
    `/rfed/subscribe` at least once per app session AND on every SEND
    rejection, to recover from operator-side cost changes.

  See `RFed-rust/rfed/src/config.rs` (TierPolicy section, *HISTORICAL
  FAILURE MODES*), `Retichat-ios/rust/retichat-ffi/src/lib.rs`
  (`retichat_compute_channel_stamp`), and
  `Retichat-ios/Retichat/Services/RfedChannelClient.swift`
  (`refreshStampCost`, `trySend`).

### MESSAGE_GET Response (blob stream)

```
┌──────────────────┬──────────────────┬────────────┬──────────────┐
│ channel_hash(16) │ message_id(16)   │ length(4BE)│ blob(length) │
├──────────────────┼──────────────────┼────────────┼──────────────┤
│ channel_hash     │ message_id       │ length     │ blob         │
│       ...        │       ...        │    ...     │    ...       │
└──────────────────┴──────────────────┴────────────┴──────────────┘
```

Each record in the response:
- **channel_hash**: 16 bytes (padded/truncated)
- **message_id**: 16 bytes (padded/truncated)
- **length**: 4 bytes, big-endian `u32`
- **blob**: `length` bytes of raw inner blob (no stamp)

Records repeat until the response is complete or a transfer/sync limit is
reached.

### Notify Wake Packet

Sent as a msgpack Map:

```
{
  "receiver": bin(16),    // subscriber destination hash (always present)
  "sender":   bin(16),    // optional — present when known (e.g. LXMF)
  "channel":  bin(16),    // optional — present for rfed.channel fanout
}
```

Only destination hashes are included. No message content ever leaves the
node via the notify path.

---

## 4. Sync Protocol

Federation nodes exchange blobs through a three-step manifest-based sync
protocol:

### Step 1: OFFER

The initiating node (A) opens a Reticulum `Link` to the target node (B)
and sends an OFFER request containing the message IDs it already holds:

```
A → B: /rfed/offer  payload = msgpack [msg_id₁, msg_id₂, ...]
B → A: response     payload = msgpack [(ch_hash₁, msg_id₁), (ch_hash₂, msg_id₂), ...]
```

B returns its **entire** store manifest (channel hash + message ID pairs).

### Step 2: Gap Computation

A filters B's manifest to only IDs for channels A has local subscribers
for, minus IDs A already holds. This produces the "gap" — blobs A needs.

### Step 3: MESSAGE_GET

A requests the gap from B:

```
A → B: /rfed/get  payload = msgpack [wanted_id₁, wanted_id₂, ...]
B → A: response   payload = binary blob stream (see §3)
```

The response is subject to two limits:
- **transfer_limit_bytes**: caps a single session (per-peer)
- **sync_limit_bytes**: rolling 1-hour aggregate across all peers

### Step 4: Ingest & Fanout

A parses the blob stream, stores each blob, and immediately fans out to
local subscribers (see §8). Deferred queuing occurs for offline subscribers.

### Timing

| Constant | Value | Description |
|----------|-------|-------------|
| `SYNC_BACKOFF_MIN` | 10 s | Minimum interval between sync attempts |
| `SYNC_BACKOFF_MAX` | 3600 s | Maximum backoff (1 hour) |
| Stale peer cutoff | 7200 s | Peers not heard from in 2× max backoff are pruned |

Backoff doubles on failure and resets on success or announce heard.
Static peers are never pruned.

---

## 5. Blob Storage

Blobs are stored on the filesystem under `<config_dir>/blobs/`:

```
blobs/
  <channel_hash_hex>/
    <message_id_hex>      ← raw inner blob, no envelope
```

### Metadata

Each blob has an in-memory metadata entry rebuilt from disk on startup:

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | `[u8; 16]` | Random 16-byte ID assigned at ingest |
| `destination_hash` | `[u8; 16]` | Channel hash |
| `received` | `f64` | Unix timestamp |
| `size` | `usize` | Byte length of blob |

### Eviction

| Policy | Value | Trigger |
|--------|-------|---------|
| TTL | 30 days | Hourly check |
| Capacity | `storage_limit_bytes` (default 2 GB) | On new blob ingest |

When capacity is exceeded, the oldest blobs by `received` timestamp are
evicted first.

---

## 6. Subscription Table

Subscriptions map subscribers to channels and are persisted to disk as
msgpack (`subscriptions.rmp`).

### Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `[u8; 16]` | Subscriber's identity hash |
| `channel_hash` | `[u8; 16]` | Channel hash |
| `added` | `f64` | Unix timestamp |
| `owner_node_hash` | `Option<[u8; 16]>` | Non-None = backup subscription |
| `last_refreshed` | `f64` | Backup TTL tracking |

### Primary vs. Backup Subscriptions

- **Primary** (`owner_node_hash = None`): Created via `/rfed/subscribe`.
  Fanout always delivers.
- **Backup** (`owner_node_hash = Some(hash)`): Created via
  `/rfed/backup/push`. Delivery is **suppressed** while the owner node is
  online. When the owner's Reticulum path decays, the backup node activates
  delivery (failover).

Stale backup entries (not refreshed within `2 × owner_offline_secs`) are
automatically pruned.

---

## 7. Deferred Delivery

When a subscriber is offline during fanout, blobs are queued in the
deferred delivery queue and persisted to disk (`deferred_delivery.rmp`).

### Limits

| Scope | Default | Configurable |
|-------|---------|-------------|
| Per subscriber (default tier) | 256 blobs | `policy.default.deferred_queue_limit` |
| Per subscriber (VIP tier) | 2048 blobs | `policy.vip.deferred_queue_limit` |
| Global | 4096 entries | Hard cap |

When a per-subscriber limit is exceeded, the oldest entry is evicted.
When the global limit is reached, new entries are silently dropped.

### Delivery Triggers

1. **Subscriber comes online** — delivery destination announces; node
   drains deferred queue and sends each blob.
2. **PULL request** — subscriber explicitly requests pending blobs via
   `/rfed/pull`; queue is drained and returned as a msgpack array.
3. **Periodic eviction** — entries older than 7 days are pruned hourly.

---

## 8. Fanout & Double Envelope

### Fanout Process

When a blob is ingested (via SEND or sync), `fanout_blob()` iterates over
all subscribers for the channel:

1. Skip backup subscriptions where the owner is still online.
2. Look up the subscriber's identity and current path.
3. Build an outbound Reticulum packet to the subscriber's `rfed.delivery`
   destination, containing the inner blob as payload.
4. Send the packet.
5. If the subscriber is unreachable, add to the "missed" list for deferred
   queuing.

### Double Envelope

```
┌─── Outer Envelope (rfed → subscriber) ───────────────────────────┐
│  Reticulum HEADER_1 packet                                       │
│  Destination: subscriber's rfed.delivery (Single, encrypted)     │
│  Payload: [ inner_blob ]                                         │
│                                                                  │
│  ┌─── Inner Blob (sender → channel) ─────────────────────────┐  │
│  │  Encrypted to channel X25519 pubkey                        │  │
│  │  Signed by sender                                          │  │
│  │  Content: application-defined (opaque to rfed)             │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

The node **never modifies** the inner blob. It is stored, synced, and
delivered verbatim.

---

## 9. Notify System

The notify system sends lightweight wake-up signals to relay nodes when a
blob arrives for an offline subscriber.  These wake packets carry no message
content and can be used for mobile push notifications (APNs, FCM,
UnifiedPush) or any other out-of-band alerting mechanism, without the rfed
node holding platform credentials.

### 9.1 Registration

Subscribers register notify relay hashes via `/rfed/notify/register`.
The relay hash is the **32-character lowercase hex** representation of the
relay's 16-byte RNS destination hash.

```python
# Register a relay node for wake-ups
relay_hash = "aabbccdd11223344aabbccdd11223344"  # exactly 32 hex chars
# → /rfed/notify/register  payload = msgpack string("aabbccdd...")
# ← response: msgpack bool (true = accepted)
```

**Validation:** The hash must be exactly 32 ASCII hex digits (`[0-9a-f]`).
Any other value is rejected.

**Persistence:** Registrations are stored on disk in
`~/.rfed/notify_registrations.rmp` and survive node restarts.

#### NotifyRegistration Record

Each registration is stored as:

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `bin(16)` | Subscriber's RNS identity hash (derived from caller's public key) |
| `relay_hash` | `string(32)` | Hex-encoded relay destination hash |
| `registered` | `f64` | Unix timestamp of registration (for expiry/refresh) |

A subscriber may register multiple relays.  Each relay receives wake
packets independently.

### 9.2 Relay Destination Addressing

The rfed node addresses the relay as a **Reticulum Single destination**
using the following namespace:

| Component | Value |
|-----------|-------|
| App name | `"rfed"` |
| Aspects | `["notify"]` |
| Destination type | `Single` (asymmetric encryption, multi-hop routed) |
| Identity | Recalled from Reticulum transport by the 16-byte relay hash |

The full RNS destination name is `rfed.notify`.  The relay must announce
this destination so that Reticulum transport can route packets to it.

### 9.3 Wake Packet Wire Format

The wake packet payload is a **msgpack Map** with string keys and binary
values.  It contains only destination hashes — never message content.

| Key | Type | Present | Description |
|-----|------|---------|-------------|
| `"receiver"` | `bin(16)` | **Always** | Subscriber's RNS destination hash |
| `"sender"` | `bin(16)` | Optional | Sender's RNS destination hash (LXMF path only) |
| `"channel"` | `bin(16)` | Optional | Channel hash (rfed.channel fanout path only) |

The map contains **at most 3 entries**.  Clients must tolerate unknown keys
in future versions.

**Encoding:** `rmpv::Value::Map` (msgpack fixmap or map16).

#### Example: Channel Fanout Wake

When a blob arrives on `rfed.channel.publish` for a subscribed channel:

```
msgpack Map {
  "receiver" → bin(16)   ← subscriber destination hash
  "channel"  → bin(16)   ← channel hash the blob was published to
}
```

`"sender"` is absent because fire-and-forget SEND packets carry no sender
identity.

#### Example: LXMF Propagation Notification Wake

When an LXMF message arrives for a notify-registered destination:

```
msgpack Map {
  "receiver" → bin(16)   ← recipient destination hash
  "sender"   → bin(16)   ← sender destination hash (from LXMF payload)
}
```

`"channel"` is absent because LXMF messages are not channel-scoped.

### 9.4 Dispatch Flow

1. Blob arrives for a subscriber who has registered notify relays.
2. For each registered relay, rfed spawns an async task that:
   a. Decodes the 32-char hex relay hash to 16 bytes.
   b. Recalls the relay's identity from Reticulum transport.
   c. Builds an outbound `rfed.notify` Single destination.
   d. Sends the msgpack wake packet as a Reticulum packet.
3. On send failure, **one retry** is attempted after **8 seconds**.
4. If the retry also fails, the wake is silently dropped.  The subscriber
   will still receive the message via deferred queue pull or live fanout
   on their next connection.

### 9.5 Relay Implementation Guide (e.g. Retichat iOS)

A relay is a service that:

1. **Announces** a Reticulum identity on the `rfed.notify` destination
   (`app_name="rfed"`, `aspects=["notify"]`, `DestinationType::Single`).
2. **Receives** incoming Reticulum packets on that destination.
3. **Decodes** the msgpack Map payload (see §9.3).
4. **Maps** the `"receiver"` hash to a platform-specific device token
   (APNs, FCM, etc.) using a relay-side database.
5. **Sends** a platform push notification to the device.

```
┌─────────┐   SEND blob    ┌──────────┐  wake packet   ┌───────────┐  APNs/FCM  ┌──────────┐
│ Publisher│───────────────→│ rfed node│───────────────→│   Relay   │───────────→│  Device  │
└─────────┘                 └──────────┘                └───────────┘            └──────────┘
                                 │                           │
                         stores blob,                 maps receiver
                         checks subs,                 hash → device
                         dispatches wake              token, sends
                                                      platform push
```

**The rfed node never holds APNs/FCM credentials.**  The relay operator
manages all platform integrations independently.

#### Relay-Side Requirements

| Responsibility | Owner | Notes |
|---------------|-------|-------|
| `subscriber_hash → device_token` mapping | Relay | Relay must maintain this; rfed does not provide it |
| APNs/FCM/UnifiedPush credentials | Relay | Stored on relay infrastructure, never shared with rfed |
| Rate limiting outbound pushes | Relay | rfed imposes no backpressure on the relay |
| Delivery confirmation | N/A | No ack path from relay back to rfed (fire-and-forget) |

### 9.6 Privacy

- The relay sees only which `subscriber_hash` should be woken, and
  optionally which `sender` or `channel` triggered the wake.
- The relay **never** sees message content, channel names, or any
  encrypted payload.
- The rfed node **never** sees device tokens, APNs certificates, or any
  platform credentials.

---

## 10. LXMF Propagation Relationship

RFed is intentionally LXMF-adjacent, but the relationship has three separate
layers that are easy to conflate if they are not spelled out explicitly:

1. **Channel payload format**: the recommended RFed inner blob is an LXMF
   `PROPAGATED` message, with the required source-identity prelude, encrypted
   to the channel identity.
2. **Federation mechanics**: RFed reuses LXMF-style OFFER/GET manifest sync and
   LXMF stamp-validation machinery.
3. **Optional full propagation service**: rfed can also announce a standard
  `lxmf.propagation` destination and act as a full LXMF propagation node.

### What RFed reuses from LXMF propagation

- propagated LXMF blob semantics for sender authentication inside the encrypted
  inner payload
- manifest-based OFFER / GET sync between store-and-forward peers
- proof-of-work stamp validation rules and announce metadata conventions
- the core idea that a node can store opaque ciphertext keyed by a hash without
  being able to decrypt the content it forwards

### What RFed changes

- the stored key is a **channel hash**, not a recipient delivery hash
- delivery is **fanout to subscribers**, not one mailbox per recipient
- peer sync is filtered to channels with local subscriber interest
- subscribers prove channel membership by signing subscribe requests rather
  than by owning a delivery mailbox on the propagation node

### Optional full `lxmf.propagation` service

When `[node].lxmf_propagation = yes`, rfed announces an `lxmf.propagation`
destination and runs the standard LXMF propagation service in parallel with
its channel federation surfaces. This is full propagation support, not a
notify-only shim.

### Behaviour

1. Client sends an LXMF propagated message to rfed's propagation destination.
2. rfed validates the propagation-node stamp against the configured
  cost/flexibility.
3. rfed stores the LXMF message on disk, indexes it, and queues it for
  eligible propagation peers.
4. Recipients retrieve stored messages with the standard LXMF `GET` path, and
  peers exchange OFFER / GET sync with LXMF-rust `lxmd` instances and other
  rfed nodes.
5. If the recipient has notify relays registered, rfed also dispatches wake
  packets with `receiver` and optional `sender` hashes.

`lxmf_propagation_autopeer` controls announce-based discovery, while
`[peering].propagation_peers` pins static propagation peers.

### Announce Metadata

The LXMF propagation destination announces with app_data:

```
[
  false,                            // protocol version marker
  unix_timestamp,                   // announce time
  true,                             // is active propagation node
  transfer_limit_mb,                // per-transfer limit
  sync_limit_mb,                    // per-sync-period limit
  [stamp_cost, flexibility, cost],  // PoW parameters
  {0x01: node_name}                 // metadata map
]
```

---

## 11. Backup Failover

rfed implements chain-of-custody backup delivery for subscriber resilience.

### Architecture

```
              ┌─────────────┐
              │   Primary    │   ── owns subscriptions
              │   rfed node  │
              └──────┬───────┘
                     │  /rfed/backup/push (subscription pairs)
                     ▼
              ┌─────────────┐
              │   Backup     │   ── holds backup subscriptions
              │   rfed node  │   ── suppresses delivery while primary online
              └──────────────┘
                     │
                     ▼  primary path decays → activate delivery
              ┌─────────────┐
              │  Subscriber  │   ── receives blobs from backup
              └─────────────┘
```

### Configuration

```ini
[peering]
primary_node       = aabbccdd...    # first-choice backup target
secondary_nodes    = 11223344...    # ordered fallback list
owner_offline_secs = 90             # silence before failover activates
```

### Failover Sequence

1. Primary periodically pushes `(subscriber_hash, channel_hash)` pairs to
   its designated backup node via `/rfed/backup/push`.
2. Backup stores these as backup subscriptions (`owner_node_hash = primary`).
3. Backup monitors the primary's announce freshness.
4. When primary has been silent for `owner_offline_secs`, backup activates
   delivery for adopted subscribers.
5. Backup re-pushes adopted entries to **its own** backup (chain of custody).
6. Entries not refreshed within `2 × owner_offline_secs` are pruned.

### Backup Selection

The active backup is selected in priority order:

1. `primary_node` (if alive and reachable)
2. First alive node in `secondary_nodes`
3. Auto-selected from alive federation peers

Only **one** node receives pushes at a time.

---

## 12. Announce Format

### rfed.node Announce

Encoded as a msgpack array in the announce `app_data`:

```
[
  bin(display_name),        // UTF-8 node name
  uint(stamp_cost) | nil,   // PoW cost (nil = disabled)
  uint(1)                    // protocol version
]
```

RFed's channel-federation destinations are described in §2. `rfed.node`
carries RFed app_data, and when propagation is enabled `lxmf.propagation`
carries the standard LXMF app_data shown above.

---

## 13. Configuration

### Reticulum Native Config File

Located at `<config_dir>/config`. The file uses Reticulum's native config
format, not TOML. All settings are optional; a commented sample is written on
first run, and `config.txt.example` is a ready-to-edit starting point.

```ini
[node]
name                         = rfed
announce_interval_minutes    = 360
announce_at_start            = yes
lxmf_propagation             = no
lxmf_propagation_autopeer    = no

[storage]
limit_mb          = 2000
transfer_limit_mb = 500
sync_limit_mb     = 1000

[peering]
static_peers         = aabbccdd...
from_static_only     = no
peering_cost         = 18
trusted_backup_peers = aabbccdd...
primary_node         = aabbccdd...
secondary_nodes      = 11223344...
owner_offline_secs   = 90
propagation_peers    = aabbccdd...

[policy.default]
stamp_cost                = 16
stamp_flexibility         = 3
deferred_queue_limit      = 256
allow_notify_registration = yes
allow_subscription        = yes
trusted_backup_only       = no

[policy.vip]
stamp_cost                = 4
stamp_flexibility         = 2
deferred_queue_limit      = 2048
allow_notify_registration = yes
allow_subscription        = yes
trusted_backup_only       = no

[vip]
subscribers = aabbccdd..., 11223344...
```

The `[reticulum]` and `[interfaces]` sections live in the same file and use
standard Reticulum syntax. List values are comma-separated hashes, and
booleans use Reticulum-style `yes` / `no`.

### Merge Order

CLI flags → config values → compiled defaults.

### Data Files

All persisted to `<config_dir>/`:

| File | Format | Contents |
|------|--------|----------|
| `identity` | Reticulum identity | Node X25519 + Ed25519 keypair |
| `subscriptions.rmp` | msgpack | Subscription table |
| `notify_registrations.rmp` | msgpack | Notify relay registrations |
| `deferred_delivery.rmp` | msgpack | Offline blob queue |
| `peers.rmp` | msgpack | Peer sync state & backoff timers |
| `blobs/<ch_hex>/<id_hex>` | raw bytes | Stored inner blobs |
| `lxmf_propagation/messagestore/<message_id_hex>` | raw bytes | Stored LXMF propagated messages (when enabled) |
| `lxmf_propagation/peers` | msgpack | Propagation peer state and sync backoff |
| `lxmf_propagation/node_stats` | msgpack map | Propagation message counters |

---

## 14. CLI Reference

```
rfed [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config <DIR>` | `~/.rfed` | Config & storage directory |
| `--rnsconfig <DIR>` | *(system)* | Reticulum config directory |
| `--identity <FILE>` | `<config>/identity` | Node identity file |
| `--name <NAME>` | `"rfed"` | Display name |
| `--announce-interval <MIN>` | `360` | Announce interval (minutes) |
| `--no-announce-at-start` | *(announce)* | Skip initial announce |
| `--stamp-cost <BITS>` | `16` | PoW stamp cost |
| `--stamp-flexibility <BITS>` | `3` | Stamp flexibility |
| `--peering-cost <BITS>` | `18` | Peering PoW cost |
| `--storage-limit <MB>` | `2000` | Blob storage limit |
| `--static-peer <HASH>` | *(none)* | Add static peer (repeatable) |
| `--from-static-only` | `false` | Only accept from static peers |
| `-v, --verbose` | | Increase log verbosity |
| `-q, --quiet` | | Decrease log verbosity |
| `-h, --help` | | Show usage |

---

## 15. Test Suite

The integration test suite lives in `cli-tests/rfed_tests/` and covers six
scenarios:

| # | Scenario | Description |
|---|----------|-------------|
| 1 | `live_fanout` | Subscribe → publish → verify immediate delivery |
| 2 | `deferred` | Publish while offline → come online → verify flush |
| 3 | `pull` | Publish while offline → explicit PULL → verify return |
| 4 | `notify` | Register relay → publish offline → verify wake packet |
| 5 | `sync` | Two-node: publish on A, subscribe on B, verify sync |
| 6 | `backup_failover` | Primary dies → backup activates → subscriber receives |

```bash
# Run all tests
./run_tests.sh all

# Run a specific scenario
./run_tests.sh 3
```

Test clients are Python scripts that use the reference Reticulum library
and the `channel_hash.py` utility module for deterministic hash computation.

---

## 16. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reticulum_rust` | local | Rust Reticulum transport layer |
| `lxmf_rust` | local | LXMF message handling & PN stamps |
| `rmp` / `rmpv` / `rmp-serde` | 0.8 / 1.0 / 1.1 | MessagePack serialisation |
| `serde` | 1.0 | Derive serialisation traits |
| `configparser` | 3 | Reticulum-native config parsing |
| `sha2` | 0.10 | SHA-256 hashing |
| `x25519-dalek` | 1.1.1 | X25519 key derivation |
| `ed25519-dalek` | 1.0.1 | Ed25519 key derivation |
| `rand` | 0.8 | Random message ID generation |
| `ctrlc` | 3.4 | Graceful shutdown (SIGINT) |

---

## 17. Capabilities Query

The `/rfed/capabilities` request path on `rfed.node` returns a msgpack Map
describing features, protocol version, and anti-spam parameters advertised by
this node.  Any caller may issue the request; the payload is ignored.

### Response Fields

| Key | Type | Description |
|-----|------|-------------|
| `protocol_version` | Integer | Wire-format version (currently `1`). Bump on breaking changes. |
| `display_name` | String | Human-readable node name from config. |
| `subscription` | Boolean | Whether the default policy allows subscription. |
| `notify` | Boolean | Whether the default policy allows notify registration. |
| `lxmf_propagation` | Boolean | Whether the full `lxmf.propagation` service is enabled. |
| `channel_stream` | Boolean | Whether live per-channel streaming is available. |
| `propagation_stream` | Boolean | Whether propagation streaming support is available (currently mirrors `lxmf_propagation`). |
| `backup` | Boolean | Whether backup failover is configured (primary or secondary nodes set). |
| `stamp_cost` | Integer / Nil | Required PoW leading-zero bits, or Nil if stamping is disabled. |

The map is intentionally extensible — clients must tolerate unknown keys.
Future versions may add fields such as `storage_available`, `peer_count`,
or feature-specific sub-maps.

### Example Response (decoded)

```
{
  "protocol_version": 1,
  "display_name": "my-rfed-node",
  "subscription": true,
  "notify": true,
  "lxmf_propagation": false,
  "channel_stream": true,
  "propagation_stream": false,
  "backup": true,
  "stamp_cost": 16
}
```

---

## License

See [LICENSE](rfed/LICENSE).

---

*This specification and the rfed codebase were developed through human–AI
collaboration using Claude (Anthropic) and GitHub Copilot. Architecture
decisions, code review, security audits, and testing were conducted by the
human author with AI assistance throughout the development process.*
