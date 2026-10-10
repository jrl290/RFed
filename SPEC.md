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
        sender              = the posting identity: the distro identity when
                              the device holds one, otherwise the device
                              identity (§17.12; RFed-spec/Channel.md
                              "Distro holders"). Subscriptions stay the
                              device's.
        msgpack_payload     = the LXMF payload; its fields map may carry the
                              Retichat field 0xD1 (FIELD_RETICHAT, a map) whose
                              key 0 is the poster's Channel Display Name (see
                              "Display name" below).

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
    A `/channel/publish` request on the RFed node's `rfed.link`
    (RFed-spec/Link.md), or a Reticulum DATA packet,
    DestinationType::Single, addressed to the node's legacy
    `rfed.channel` / `rfed.channel.publish` destination. RFed decrypts the
    outer envelope (the link, or the packet with its node identity),
    validates the stamp, strips it, and stores `inner_blob` keyed by
    channel_hash.

Layer 1' (Reticulum transport — fanout hop, one per subscriber):
    For every subscriber S of channel_hash, RFed pushes
        [ channel_hash(16) | inner_blob ]
    by the first live route of §7 that takes it (a `/delivery` request
    on S's bound rfed.link, a DATA packet on S's legacy
    rfed.channel.stream link, a DATA packet to S's rfed.delivery
    destination), and otherwise queues it for S's pull (§7).
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
5. **Key binding (MUST, before step 6).** Compute the `lxmf.delivery`
   destination hash of `sender_identity_pub`
   (`truncated_hash(name_hash("lxmf.delivery") || truncated_hash(sender_identity_pub))`)
   and compare it with `source_hash`. On mismatch reject the post and
   remember nothing (LXMF-rust/DISPLAY_NAMES.md §2.3).
6. Call `Identity::remember_destination(source_hash, sender_identity_pub, None)`
   to populate Reticulum's known-destinations cache.
7. Prepend the channel's `lxmf.delivery` destination hash to the
   LXMF tail and feed to
   `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`.
8. LXMF Ed25519 signature validation runs against the just-cached
   `sender_identity_pub`. **This is the integrity check of the post** —
   a forged `sender_identity_pub` produces `SIGNATURE_INVALID`. It does
   **not** protect the cache: the channel private key is derived from the
   channel name, so anyone who knows the name reaches step 3, and without
   step 5 a post claiming a contact's `source_hash` would overwrite that
   contact's stored key. Step 5 is what prevents that.
9. Only if steps 5 and 8 passed, read key 0 of `0xD1` from the fields (below).

`lxmf_rust::channel::unpack` implements steps 2–9 (and `pack` the
sender side) for both Retichat bridges.

### Display name (key 0 of field 0xD1)

The LXMF message may carry the Retichat field `0xD1` (`FIELD_RETICHAT`),
a msgpack map. Its key 0 is the poster's Channel Display Name as msgpack
bin (receivers accept bin or str), or a zero-length value meaning "no
name now": `{0xD1: {0: <name or empty>}}`. A `0xD1` that is not a map is
ignored whole. No key 0 means the post carries no name. Receivers use it only after the key binding and the
signature pass, and store it per `(channel, sender)`. The contract,
including when a client includes it, is LXMF-rust/DISPLAY_NAMES.md
(§2.3, §4.2, §5.2). RFed never sees it.

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
- **The prelude key must bind to `source_hash`** (its `lxmf.delivery`
  destination hash equals `source_hash`), checked before it is
  remembered. Receivers MUST reject posts that fail.
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
17. [Distro](#17-distro)

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

It is the channel's **identity** hash, not the `lxmf.delivery`
destination hash of the channel identity. The identity hash is what goes
in the first 16 bytes of every post, what RFed stores and fans out under,
and what clients send in subscribe, pull, stream-filter and notify
requests. RFed never derives it; it only compares the 16 bytes it is
given. The `lxmf.delivery` destination hash of the channel identity is
used for one thing only: the inner LXMF message is addressed to it and
signed over it. The sender drops it, and the receiver re-derives it to
rebuild the signed bytes (step 7 of the receive path). It is never on the
wire.

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

For **private** channels, the first segment (the root) is any segment other
than `"public"`: lowercase letters, digits and `-`, no `.`. Clients default
it to 16 lowercase hex characters (64 bits from a CSPRNG) and let the user
edit it, so a shared private channel can be joined by typing or pasting its
full name; entering `root.name` in the name field fills the root and the
name. Since possession of the channel name equals possession of the
decryption key, the random root makes the name impractical to guess.
Distribute the full channel name out-of-band to intended members only.
Existing channels keep their roots (older clients generated 8 hex
characters); nothing in the protocol depends on the root's length.

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
| `rfed.distro.register` | `["distro", "register"]` | Distro device registration |
| `rfed.distro.unregister` | `["distro", "unregister"]` | Distro device removal |
| `rfed.distro.list` | `["distro", "list"]` | Distro device listing |
| `rfed.link` | `["link"]` | Every operation above, both directions, over one link |

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

**rfed.distro.*** (distro service destinations):
| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.distro.register` | `/rfed/distro/register` | Device | `msgpack [bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey)]` | `msgpack bool` |
| `rfed.distro.register` | `/rfed/pull` | Device | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) distro_hash, bin blob], …], bool more_pending ]` |
| `rfed.distro.unregister` | `/rfed/distro/unregister` | Device | `msgpack [bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey)]` | `msgpack bool` |
| `rfed.distro.list` | `/rfed/distro/list` | Device | `msgpack [bin(16) distro_identity_hash, bin(64) distro_pubkey, bin(64) sig(distro_identity_hash)]` | `msgpack [bin(16) device_lxmf_hash, ...]` |

**rfed.delivery** (live fanout destination + legacy aggregate pull):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/pull` | Subscriber | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) channel_hash, bin blob], …], bool more_pending ]` |

**PULL paging** (user-initiated; mirrors chat-history "Load earlier
messages"): each call drains at most one page (`deferred_pull_batch_limit`
or `DEFAULT_PULL_PAGE_SIZE = 25`) and returns `more_pending = true` when
additional entries remain for the caller. The client offers another
page-load action while `more_pending` is true and stops once it is false.
Drain is destructive on the server side — once a page has been returned
those blobs are gone from this node and will only re-arrive via fanout
from another session or sync from the origin.

**PULL error responses.** PULL is the one rfed request family authenticated
by the caller's **link identity** rather than a signed payload, which exposes
it to the LINKIDENTIFY race: identify is fire-and-forget, so a request can
reach the node before the identify has (the race that moved every other
endpoint to signed payloads in the first place). Error handling therefore
follows the reference LXMF Propagation protocol exactly:

- Unidentified caller → response is a bare msgpack integer `0xF0`
  (`ERROR_NO_IDENTITY`, LXMF/LXMPeer.py) — **never silence**. A node must
  not answer an unidentified PULL by sending nothing: the client cannot
  distinguish that from a dead node and burns its full timeout budget.
  (rfed did exactly this until 2026-08-17.)
- Malformed payload (channel-scoped PULL only) → `0xF4` (`ERROR_INVALID_DATA`).
- Client reaction, per LXMF/LXMRouter.py `message_list_response`: on `0xF0`
  or `0xF1`, **tear the link down** and re-identify on a fresh link at the
  next attempt. No in-place retry.

Success responses remain the `[[pairs...], more_pending]` array, so a client
distinguishes refusal from success by type: integer = error code, array =
page. This matches how the propagation `/get` path already behaves on both
node and client.

**rfed.notify** (subscriber → node):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/notify/register` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/unregister` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/clear` | Subscriber | *(empty)* | `msgpack bool` |

### `rfed.link` — one destination for all of it

Normative spec: **[RFed-spec/Link.md](../RFed-spec/Link.md)**. Path table in
code: `rfed/src/link_session.rs::paths`.

Every destination above is also reachable on the single `rfed.link`
destination, addressed by request path instead of by destination hash. The
path is the destination's aspect chain with `.` replaced by `/`, plus the
operation verb when the aspect chain does not already name it —
`rfed.channel.pull` `/rfed/pull` becomes `/channel/pull`. Payloads and
responses are byte-identical to the tables above; only the routing differs.

Two things are genuinely new rather than relocated:

- **`/channel/publish` answers.** The legacy publish is a fire-and-forget
  packet, so a rejected stamp is indistinguishable from a lost one. As a
  request it responds `msgpack [bool, str|nil]` with `too_short`,
  `stamp_too_short`, `stamp_invalid`, `stamp_legacy`, or `store_failed`.
  A publish over the link MDU is still a request — RNS carries it as a request
  Resource — and is answered the same way. A bare Resource on the link is also
  ingested, but gets no answer.
- **Node → client requests.** After `/channel/stream/open` or
  `/propagation/stream/open` binds the link, the node pushes back over it:
  `/delivery` (`channel_hash(16) | inner_blob`), `/lxmf/delivery` (packed
  LXMF), `/notify` (wake map). The client's `msgpack bool` response is the
  delivery proof. An unanswered channel `/delivery` or distro `/lxmf/delivery`
  push moves the blob to the deferred queue, and the client collects it with
  `/channel/pull` or `/distro/pull`. An unanswered `/lxmf/delivery` of a
  directly-addressed message is not deferred: the message stays in the
  messagestore and propagation sync finds it. See §7 "Live delivery and its
  proof".

`rfed.link` is additive. Every destination above stays registered, announced,
and answering, and no deployed client has to move.

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
  pub), then the LXMF tail. Receivers MUST first check the key
  binding: the `lxmf.delivery` destination hash of `identity_pub`
  must equal `source_hash` taken verbatim from the LXMF tail, or the
  post is rejected and nothing is remembered. Only then call
  `Identity::remember_destination(source_hash, identity_pub, None)`
  and invoke `LXMessage::unpack_from_bytes`. **Do NOT compare
  `truncated_hash(identity_pub)` itself with `source_hash`** — that is
  the bare identity hash, not the lxmf.delivery DESTINATION hash, so
  the equality never holds and would reject every legitimate message.
  LXMF's Ed25519 signature validation authenticates the post (forged
  `identity_pub` → `SIGNATURE_INVALID`); the key binding protects the
  known-destinations cache, which the channel key alone does not,
  since anyone who knows the channel name holds it. The LXMF fields
  may carry key 0 of the Retichat field `0xD1`, the poster's Channel
  Display Name, used only once both checks pass (see "Display name
  (key 0 of field 0xD1)" above).
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
  "receiver": bin(16),    // subscriber's lxmf.delivery hash (always present)
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

The response is subject to two caps, always set:
- **`channel_transfer_limit_mb`** (`[storage]`, default 100): the most one
  response carries (per peer request)
- **`channel_sync_limit_mb`** (`[storage]`, default 1000): the most sent to
  all peers together per hour

B builds the response for A's whole gap while holding the FedSync and
BlobStore locks and reading every blob from disk, so it is never uncapped.
What a response leaves out is in the gap of A's next sync. Until 2026-09-28
the caps were `transfer_limit_mb` / `sync_limit_mb`, which are also the
`lxmf.propagation` node's announced limits (§10); left unset for that
announce (the shipped templates since then), channel sync had no cap at all.

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

Subscriptions map subscribers to channels and are persisted to disk in
SQLite (`subscriptions.sqlite3`, one row per entry; see §13 Data Files).

### Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `[u8; 16]` | Subscriber's identity hash |
| `channel_hash` | `[u8; 16]` | Channel hash |
| `added` | `f64` | Unix timestamp |
| `owner_node_hash` | `Option<[u8; 16]>` | Non-None = backup subscription |
| `last_refreshed` | `f64` | Backup TTL tracking |

The subscriber is a **device**: clients sign `/rfed/subscribe` with their
device key, also when they post as a distro (§17.12). The node keeps one row
per channel, one bound `rfed.link` (RFed-spec/Link.md), one deferred bucket
(§7) and one wake address (§9) per subscriber hash, which is why devices
never subscribe under a shared hash. A node refuses a subscription signed
with the key of a distro registered at it (below).

### Channel and distro hashes

Channel hashes (identity hashes, §1) and distro hashes (`lxmf.delivery`
hashes, §17.5) are both 16-byte routing hashes in one namespace: the
BlobStore, the sync manifest and the deferred queue key blobs by them alike.
A node keeps the two apart for every distro registered at it, judged against
its own DistroTable (`DistroTable::is_distro`) when the request or the blob
arrives:

- **Subscribe.** `/rfed/subscribe` (`/channel/subscribe` on `rfed.link`)
  stores nothing and answers a bare msgpack `false`, as for any refused
  subscription, when `channel_hash` is a registered distro's
  `distro_lxmf_hash`, and when the payload is signed with a registered
  distro's key (the signer's `lxmf.delivery` hash is a `distro_lxmf_hash`):
  a distro's devices subscribe with their own keys (above). The channel
  hash is judged first. Each refusal has a log line of its own
  (`subscribe`, `SubscribeRefusal`).
- **Sync ingest.** For a routing hash that is a registered distro, sync
  ingest (§4 step 4, §17.7) runs the distro fan-out only, never the channel
  fan-out. This stops delivery to a subscription row that exists anyway: one
  made before the distro registered here, a backup row pushed by a peer, or
  one stored before this rule.
- **Publish.** A publish under a registered distro's hash (§8) is stored and
  is not refused, but reaches no channel subscriber: `plan_channel_fanout`
  plans none for that hash, whatever rows it has.
- **Backup.** `/rfed/backup/push` (§11) stores no pair under a registered
  distro's hash, nor one whose subscriber is a registered distro; it stores
  the rest of the batch and answers `true`. The backup tick delivers to no
  backup row under a registered distro's hash.

Without them anyone could subscribe to a user's distro address as a channel
and be sent that distro's messages as this node pulled them from its peers:
still encrypted to the distro key, but with their timing and size. Found by
reading the code on 2026-10-03, not observed. Before this rule
`subscribe_cb` checked only the length of the hash; where the rule stands in
the code is in §17.12, "Implementation index".

If the DistroTable cannot be read (its lock poisoned), each rule fails
closed and logs at error level: subscribe and the backup push are refused,
sync ingest and a publish fan out to no one (the blob stays stored), and
the backup tick delivers to no row. A refused backup push makes its owner
queue the whole batch and push it again at every backup tick
(`requeue_backup_pairs`), an application-level retry older than this rule
(DESIGN_PRINCIPLES §3; open).

These rules stop a node *pushing* a distro's messages to a stranger and
waking them for it. They do not stop anyone *reading* the stored
ciphertext. Not covered:

- **Sync reads.** OFFER answers any caller with the node's whole store
  manifest (§4 step 1) and MESSAGE_GET with any blob by id. Both are
  registered `ALLOW_ALL` and never look at the caller, on `rfed.node`
  (`/rfed/offer`, `/rfed/get`) and on `rfed.link` (`/node/offer`,
  `/node/get`), which every web client opens. So anyone can read every
  distro message a node holds, the `rfed.distro.channel` membership
  messages (§17.12) and the §17.11 sent copies included, without
  subscribing to anything: the ciphertext, its size and id, and its timing
  by polling. Peers need the distro blobs, so they cannot be left out of
  sync; closing this needs peers to authenticate to OFFER and GET, which is
  James's decision (open, 2026-10-03). Found in review on 2026-10-03 with a
  probe test kept outside the repo; not observed in use.
- **Other nodes.** A node knows only its own DistroTable. Where a distro is
  not registered, its hash can still be subscribed as a channel (and its
  key can subscribe), and that node then pulls the distro's blobs from its
  peers for the subscriber (§4 step 2): the same ciphertext.
- **A distro that leaves.** Once the last device of a distro unregisters at
  a node, its hash is no longer a distro's there, while the BlobStore keeps
  its messages until they expire (§5). A backup row then pushed under it
  (any self-signed owner is accepted while `trusted_backup_peers` is empty,
  §11) is handed all of them, with a wake, at the next backup tick: the
  ciphertext the sync reads above already hand out.
- **A publish, onward.** What a peer's distro fan-out makes of a publish
  under a distro hash is a message to the distro, which anyone can already
  send through `lxmf.propagation`.

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

When a subscriber is offline during fanout, or a live push to it is never
confirmed, blobs are queued in the deferred delivery queue and persisted to
disk (`deferred_delivery.sqlite3`, one row per blob, in queue order).

### Live delivery and its proof

Channel and distro fan-out try the subscriber's live routes in order, and
stop at the first one that takes the push:

1. **`rfed.link`** — a `/delivery` (channel) or `/lxmf/delivery` (distro)
   request on the subscriber's bound link. The client's `msgpack bool`
   response is the proof.
2. **Legacy stream link** (`rfed.channel.stream`, `rfed.propagation.stream`)
   — a link DATA packet sent **with a packet receipt**. The client's link
   proof of that packet is the proof. A client MUST prove every DATA packet
   it receives on a stream link (the Reticulum-rust link proves each one
   when it has a packet callback); a client that does not will see each push
   handed off and delivered again by pull.
3. **`rfed.delivery` packet** (channels only; distro never uses it, §17.3) —
   a single DATA packet to the subscriber's delivery destination, sent **with
   a packet receipt**. The client's proof of that packet is the proof. A
   client MUST prove every packet it receives on `rfed.delivery` (PROVE_ALL);
   Retichat Android, iOS and web do since 2026-09-26.

   **Interim (from 2026-09-26, about a month):** the packet's proof is
   *observed*, not required (`handoff::DELIVERY_PACKET_PROOF`). The packet is
   sent once and counts as delivered; the node logs `[push] … proved` or
   `[push] … unproven; sent once`, which shows how many devices run an app
   that proves. Required against apps that never prove, every packet would be
   handed off and the announce flush would send the queued copy again on each
   announce. When most devices prove, the proof becomes required as below.
4. Otherwise the blob is handed off at once.

A push that is **never confirmed** is not lost and is not re-sent on another
live tier: it is **handed off** once (`handoff::defer_then_wake`; a distro
device's by `handoff::distro_hand_off`, §17.3). The blob
moves to the deferred queue, and then the subscriber is pushed through its
notify registrations (§9) so that it collects the blob with `/channel/pull`
or `/rfed/pull`. That is a change of route, not a retry. Tier 1 is
unconfirmed when the request fails (no response before the request
timeout, or the link closes first); tiers 2 and 3 when no proof arrives
before the receipt concludes — the RNS receipt timeout (for a link packet
the link's RTT × traffic timeout factor; for a packet to a destination
6 s plus 6 s per hop) is the failure event, and a link that closes before
the proof ends there too. The hand-off runs at most once per push per
subscriber. The `rfed.delivery` announce flush of queued channel blobs sends
with a receipt too, and, once the packet proof is required, hands off what
is not proved.

Until 2026-09-26 a tier-3 packet counted as delivered once it left, an
unconfirmed tier-1 or tier-2 push was deferred but no one was pushed, and
distro fan-out pushed no one at all: a subscriber whose app had died, its
path still held, lost the message or learnt of it only at its next pull.

Before 2026-09-24 tier 2 counted a packet the link accepted as delivered. A
device that died without closing its link (an iOS app killed or suspended,
an Android app frozen) kept an ACTIVE-looking link until keepalive
staleness, and every blob pushed in that window was lost.

A proof can arrive after the receipt has timed out. It still counts as
delivery (Reticulum-rust B35): a push that is still open when it lands is
delivered and not deferred, but a push already deferred stays deferred, so a
client can receive the same blob live and again by pull. Clients dedupe: distro blobs by a seen
key of `source + LXMF timestamp`, and a stored distro message by an id of
source, timestamp and content (§17.11 rule 5); channel blobs by their own
message identity.

One deferred bucket holds everything for an identity, and one identity, a
device's, is often both a channel subscriber and a distro device (§6,
§17.12). Each pull takes only its own kind: `/distro/pull` (and `/rfed/pull`
on `rfed.distro.register`) returns
only blobs for distros registered at this node, `/channel/pull` only the
requested channel's, and `/rfed/pull` on `rfed.delivery` returns both, for
the client to route by the leading hash.

A directly-addressed LXMF message streamed on `rfed.propagation.stream`
stays in the messagestore either way, so an unconfirmed push is not
deferred: the recipient is sent its notify wake instead (the same wake a
message gets when no live route took it), and fetches the message by
propagation sync.

### Limits

| Scope | Default | Configurable |
|-------|---------|-------------|
| Per subscriber (default tier) | 256 blobs | `policy.default.deferred_queue_limit` |
| Per subscriber (VIP tier) | 2048 blobs | `policy.vip.deferred_queue_limit` |
| Global | 4096 entries | Hard cap |

When a per-subscriber limit is exceeded, the oldest entry is evicted, and
the hand-off that evicted it logs a NOTICE naming the recipient and the
evicted entry's routing hash. When the global limit is reached, a new entry
is dropped, and the hand-off that tried to queue it logs a WARNING naming
the recipient and the routing hash (`DeferredQueue::enqueue` returns
`EnqueueOutcome`; the hand-off's `[handoff]` line reads `NOT queued: global
limit`). The other callers, which queue several blobs for one subscriber at
once (a backup node adopting an offline owner's subscriber, and the
announce flush putting back what it drained and could not send), log the
same per run: a WARNING `… NOT queued: global limit, lost to the pull` for
the refused blobs and a NOTICE for the evictions, and count as queued only
what was (`DeferredQueue::enqueue_all`, `EnqueueTally`). An entry older than 7 days is evicted, and the node logs, per
recipient and routing hash, how many expired unpulled (a WARNING for a
distro registered here).

### Delivery Triggers

1. **Subscriber comes online** — delivery destination announces; node
   drains deferred queue and sends each blob.
2. **PULL request** — subscriber explicitly requests pending blobs via
   `/rfed/pull` (or `/channel/pull`, `/distro/pull` on `rfed.link`); queue is
   drained and returned as a msgpack array.
3. **Periodic eviction** — entries older than 7 days are pruned hourly.

---

## 8. Fanout & Double Envelope

### Fanout Process

When a channel blob is ingested — a publish (a DATA packet to `rfed.channel`
or `rfed.channel.publish`, a `/channel/publish` request or bare DATA or
Resource on `rfed.link`) or a blob from peer sync (§4) — the node snapshots
the channel's subscribers (`plan_channel_fanout`) and `fanout_blob()` takes
each in turn:

1. Skip a backup subscription whose owner is still online (§6, §11).
2. Try the subscriber's live routes in the order of §7 "Live delivery and its
   proof" — a `/delivery` request on its bound `rfed.link`, a DATA packet on
   its legacy `rfed.channel.stream` link, a DATA packet to its
   `rfed.delivery` destination — and stop at the first that takes the push.
   The payload is `[ channel_hash(16) | inner_blob ]` on every route.
3. When no route takes it, or the one that took it never confirms it, hand
   the blob off once: queue it under the subscriber's identity hash and wake
   the subscriber through its notify registrations (§7, §9).

The poster is not left out. RFed cannot tell who posted (the source is inside
the EC envelope), so a poster that is subscribed is sent its own post back,
and so is every sibling device of its distro that subscribed; clients
recognise their own posts and dedupe them (RFed-spec/Channel.md, "Distro
holders").

Distro blobs never take this path. Sync ingest runs the distro fan-out for
them (§17.3, §17.7), and no channel fan-out for a routing hash that is a
distro registered at this node (§6, "Channel and distro hashes"). The
`lxmf.propagation` intercept runs only the distro fan-out, and a channel
publish under such a hash is stored and fanned out to no one
(`plan_channel_fanout`, §6).

### Double Envelope

```
┌─── Outer Envelope (rfed → subscriber) ───────────────────────────┐
│  The route of §7: a /delivery request on the subscriber's        │
│  rfed.link, a DATA packet on its rfed.channel.stream link, or    │
│  a Single packet to its rfed.delivery (all encrypted)            │
│  Payload: [ channel_hash(16) | inner_blob ]                      │
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
`~/.rfed/notify_registrations.sqlite3` and survive node restarts.

#### NotifyRegistration Record

Each registration is stored as:

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `bin(16)` | Subscriber's `lxmf.delivery` destination hash, derived from the identity hash of the key that signed the registration, for LXMF and channel registrations alike. It is the key the device registers its push token under with the bridge. (Until 2026-09-26 channel registrations used the identity hash, which no bridge had a token for; stored rows are re-keyed once on load.) |
| `relay_hash` | `string(32)` | Hex-encoded relay destination hash |
| `registered` | `f64` | Unix timestamp of registration (for expiry/refresh) |

A subscriber may register multiple relays.  Each relay receives wake
packets independently.

### 9.2 Relay Destination Addressing

The rfed node sends each wake to **exactly the registered relay hash**, as a
**Reticulum Single destination**:

| Component | Value |
|-----------|-------|
| Destination hash | The registered relay hash, unchanged |
| Name | Whichever of `apns.relay` (apns-bridge) or `rfed.notify` (fcm-bridge) derives the registered hash from the identity |
| Destination type | `Single` (asymmetric encryption, multi-hop routed) |
| Identity | Recalled from Reticulum transport by the 16-byte relay hash |
| Ratchet | The one the relay announced for that hash, if any |

The relay must announce the registered destination so that Reticulum
transport can route packets to it and rfed can recall its identity. A
registration whose hash neither name derives from the recalled identity is
logged as a WARNING and not woken. Until 2026-09-25 rfed built every wake
as `rfed.notify` under the relay's identity, whatever hash was registered.

### 9.3 Wake Packet Wire Format

The wake packet payload is a **msgpack Map** with string keys and binary
values.  It contains only destination hashes — never message content.

| Key | Type | Present | Description |
|-----|------|---------|-------------|
| `"receiver"` | `bin(16)` | **Always** | Subscriber's `lxmf.delivery` destination hash: the key its registration and its push token are stored under, for LXMF, channel and distro wakes alike |
| `"sender"` | `bin(16)` | Optional | Sender's RNS destination hash (LXMF path only) |
| `"channel"` | `bin(16)` | Optional | Channel hash (rfed.channel fanout path only) |

The map contains **at most 3 entries**.  Clients must tolerate unknown keys
in future versions.

**Encoding:** `rmpv::Value::Map` (msgpack fixmap or map16).

#### Example: Channel Fanout Wake

When a blob arrives on `rfed.channel.publish` for a subscribed channel:

```
msgpack Map {
  "receiver" → bin(16)   ← subscriber's lxmf.delivery hash
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
2. rfed snapshots the subscriber's registrations, releases the registry (and
   any node lock), and for each relay, on the calling thread (no network wait):
   a. Decodes the 32-char hex relay hash to 16 bytes.
   b. Checks for a path to that hash; if none, requests one and drops the wake.
   c. Recalls the relay's identity; if unknown, requests a path and drops the wake.
   d. Builds the Single destination for the registered hash (§9.2); if no
      known name derives it, requests a path and drops the wake. The path
      response is the relay's announce, and its key replaces a stale one.
   e. Sends the msgpack wake packet as a Reticulum packet.
3. A wake counts as sent only when an interface took the packet. Drops are
   logged at NOTICE (no path, no identity) or WARNING (anything else) and are
   **not retried** (DESIGN_PRINCIPLES §3). The subscriber still receives the
   message via deferred queue pull or live fanout on their next connection.
4. A registration stores the registrant's key for the relay hash only when
   that key derives it (a relay the subscriber hosts itself).

### 9.5 Relay Implementation Guide (e.g. Retichat iOS)

A relay is a service that:

1. **Announces** a Reticulum identity on its wake destination, `apns.relay`
   or `rfed.notify` (`DestinationType::Single`), and registers that
   destination's hash with rfed (§9.2).
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
  eligible propagation peers. A sync Resource from a peer (the sender's
  identity on the link maps to a peer's `lxmf.propagation` hash) is handled
  for that peer, every message in it including ones rfed already held, and is
  queued for the other peers only (LXMF 1.1.1
  `propagation_resource_concluded`, `from_peer`). A client's PUT goes to
  every peer. The reference reads the identity off the link when the
  Resource concludes; rfed records it when the Resource is advertised,
  because by the time the Resource concludes the proof has gone out and the
  sender may already have closed the link, which rfed can then no longer
  ask. The per-batch log line names the origin: a peer, a non-peer identity,
  or a sender with no identity.
4. Recipients retrieve stored messages with the standard LXMF `GET` path, and
  peers exchange OFFER / GET sync with LXMF-rust `lxmd` instances and other
  rfed nodes.
5. If the recipient has notify relays registered, rfed also dispatches wake
  packets with `receiver` and optional `sender` hashes.

`lxmf_propagation_autopeer` controls announce-based discovery, while
`[peering].propagation_peers` pins static propagation peers.

### Outbound peer sync

rfed pushes stored messages to its propagation peers as the Python reference
does (LXMF 1.1.1 `LXMRouter.sync_peers`, `LXMPeer.sync` / `offer_response` /
`resource_concluded`); code in `rfed/src/lxmf_propagation.rs`, "Outbound peer
sync".

1. **Choice.** Every 24 s (the reference's `JOB_PEERSYNC_INTERVAL` × 4 s) one
   IDLE peer with unhandled messages is chosen: at random among the 2 fastest
   alive peers (by the rate of their last completed sync) plus as many of
   unknown speed; only when no alive peer waits, at random among unresponsive
   peers whose backoff has run out. Sessions already running continue on
   their own events, so several peers sync at once. (While the outbound
   budget binds, the choice is the least recently served, alive or
   unresponsive: see "Sharing the budget" below.)
2. **Link.** The session opens a held link to the peer's `lxmf.propagation`
   destination through AppLinks. Each attempt adds 12 min to the peer's
   backoff; an established link clears it.
3. **Offer.** On the link: identify, then `/offer` `[peering_key, [id, ...]]`,
   back to back. Ids go lightest first (age × size); an id over the peer's
   per-message transfer limit is marked handled unsent; the batch stays under
   the peer's sync limit (KB, estimated as size + 16 B per message + 24 B).
4. **Response.** `false`: all offered ids handled. `true` / `[ids]`: the
   unwanted ones handled, the wanted ones sent. Errors: `0xF0` identify again,
   `0xF1` unpeer, `0xF3` regenerate the peering key once per announced cost,
   `0xF6` no sync for 180 s (the peer stays alive).
5. **Transfer.** The wanted messages (each stored file: message + stamp) go as
   ONE `RNS.Resource` of msgpack `[time, [lxm, ...]]` (float, array of bin) —
   the format the reference and rfed's own inbound path ingest. They are
   marked handled **only when the Resource concludes COMPLETE**. A failed
   offer, a failed Resource or a lost link returns the peer to IDLE with every
   id still unhandled.
6. **Persistent strategy.** After a COMPLETE the session carries on with the
   next batch while the peer still lacks messages (while the outbound budget
   binds and other ready peers wait, only until it has sent its fair share:
   see "Sharing the budget").

Departures from the reference, each for a reason:

- **Links through AppLinks**, never built by rfed (Reticulum-rust
  `SUBSYSTEMS.md` §1). AppLinks' path race replaces the reference's path
  request and 7.5 s sleep; its DISCONNECTED report is the failure event. The
  held link is released (`AppLinks::close`) wherever the reference tears its
  link down, except that the persistent strategy's next batch goes on the
  still-up link instead of a new one. A session runs only on a link it opened
  with `open_persistent`, so that AppLinks reports its loss: a link already
  held when a session starts from IDLE, one that comes up for an IDLE peer or
  for a destination that is no longer a peer, are closed; a second link that
  comes up mid-session (it replaced the session's link in AppLinks) is closed
  and the session ends with its ids unhandled. A report of a link AppLinks no
  longer holds (one already closed) is stale and ignored.
- **Not-ready peers are never chosen.** A peer whose stamp costs are unknown
  or whose peering key is still being generated is skipped; keys are ground
  in the background. The reference chooses such a peer and only postpones,
  and rfed used to choose the first IDLE peer every tick, so one peer grinding
  its key held up every peer (3.5 min, staging 2026-09-27). An alive peer
  still in link-attempt backoff is marked unresponsive when found, as the
  reference's `sync()` does when it chooses one.
- **Per-minute outbound budget** (`DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN`, 600).
  Guarantee: for every moment t, the messages in sync Resources handed to a
  link in (t − 60 s, t] number at most the budget, all peers together,
  across a restart too. A message counts from the moment its Resource is
  handed to the link (just before the `sending N message(s) to peer X as a
  Resource` log line), whether or not the Resource then completes; spans are
  measured on a monotonic clock. The window rolls — it is not a calendar
  minute: an offer may take only the budget less what was handed over in the
  last 60 s, less what running sessions reserve (a session reserves its whole
  offer until the answer, then the wanted ids until their Resource is handed
  over, when the reservation becomes the send). Restart: the send record is
  not persisted; instead nothing is offered for the first 60 s after start,
  as if the last run had spent the whole budget the moment this one started.
  The last run's final send came before it stopped, so no second budget
  opens within 60 s of it. That holds after a crash or a kill, which a record
  written at shutdown would not, puts no disk write in the send path, and
  never compares two runs' wall clocks. (Until 2026-09-28 the budget was a
  fixed minute started lazily and reset by a restart: 1200 left in 26 s in
  one process and 1200 in 58 s across a restart, staging.) Offers are also
  capped at 500 ids.
- **Sharing the budget.** The budget is rfed's own departure, and the
  reference's choice was never made to share one: its persistent strategy
  keeps a session going while the peer lacks messages, and its pool favours
  the fastest peers. Under the budget that starved peers (staging
  2026-09-28): one session took the whole 600 (500 on the offer, 100 more on
  the held link), so one peer was served per ~73 s, and the pool chose the
  same fast peers again (one peer 7 sessions in a phase) while 7 of 20 got
  nothing in 30 minutes. So while the budget **binds** — the ready peers
  step 1 could choose now, alive (waiting) or unresponsive with their
  backoff run out, each counted up to one offer, want more than is left of
  it — three rules apply, and none otherwise:
  - a session's **turn** is a **fair share** of messages **sent**: the
    budget divided by those ready peers (this one included), but never
    less than one tick's worth of it (budget × 24 s / 60 s, 240 of 600). A
    new session starts only on a tick, so at most 2.5 start in a minute; a
    smaller share would leave the budget unspent and serve no peer sooner.
    Each offer is cut to what is left of the share (and of the budget), so
    no turn sends more than its share and no batch takes the whole budget
    while another ready peer waits;
  - until its share is sent the session takes its next batch on the held
    link; once it is sent (or the budget is spent, or the link is gone) the
    session ends (the link is released) while other ready peers wait, and
    waits for its turn like them. A turn used to be one batch, and a batch
    is often far smaller than the share: ~52 messages of 20 KB fill a
    Resource, and a peer that already holds most of an offer (normal in a
    mesh) wants only part of it. With 20 peers for 8 minutes, turns of one
    batch sent 1040 and 480 of a budget of 4800 (review, 2026-09-28); turns
    of a share send 4080 and 3996 (tests
    `the_budget_is_spent_while_it_binds_when_batches_are_byte_limited`,
    `..._when_peers_want_part_of_each_offer`);
  - the choice (step 1) is the ready peer whose last turn
    (`last_sync_attempt`) is **oldest**, at random among equals, instead of
    the fastest-peer pool — unresponsive peers past their backoff included,
    and they count in the share and make a running session yield like
    alive ones. The reference chooses an unresponsive peer only when no
    alive peer waits, which relies on the waiting set draining quickly;
    under the budget it does not, so one failed link attempt (12 min of
    backoff, then the next tick marks the peer unresponsive) left a peer
    with nothing until its next announce, every 6 h from lxmd by default
    (review, 2026-09-28: 0 of 3000 in 30 minutes). Now its last turn is
    the oldest once its backoff has run out, and it is chosen within a tick
    or two (test `an_unresponsive_peer_takes_its_turn_while_the_budget_binds`).
    An unreachable peer costs one link attempt per turn, and its backoff
    grows by 12 min with each.

  With 20 ready peers each lacking many messages, one peer is served per
  tick, all 20 within ceil(20 / 2.5) = 8 minutes, in turns of 240 / 240 /
  120 per 72 s (the budget spent, never exceeded): test
  `every_ready_peer_gets_a_turn_while_the_budget_binds`.
- **One Resource segment per batch** (`MAX_SYNC_RESOURCE_BYTES`, ~1 MiB).
  Reticulum-rust sends an in-memory Resource as one segment of any size, and
  receivers refuse a segment over ~3 MiB; the rest goes in the next batch. A
  message larger than a segment is marked handled for the peer unsent, and
  logged.
- **`0xF0` (no identity)** is answered with one more identify per link, not
  one per answer, so a peer that never records the identity cannot loop the
  session. **`0xF6` (throttled)** ends the session at once (the reference
  leaves it waiting for its link to close) and holds the peer for 180 s
  (`throttled_until`) WITHOUT marking it unresponsive: the reference never
  chooses or demotes a peer it holds on its link, and that peer is alive and
  waiting again when the link closes. A 1.1.1 PN throttles any offer that
  arrives while it validates a batch, so this is routine; demoted, the peer
  waited behind every alive peer until its next announce. **`0xF3`
  (invalid key)** discards the peering key and grinds a new one at the
  announced cost, once per announced cost: that repairs a key ground under
  another rfed identity or persisted from an older stamper. If the peer
  refuses that key too, it validates against a cost rfed has not heard yet,
  and another key at the same cost cannot fare better, so the peer is not
  chosen again until it announces a different peering cost. (The reference
  has no `0xF3` branch: it ends the session with the key kept and offers
  again at every choice. rfed used to regrind at the same cost after every
  refusal: a full PoW grind, a link and an offer per cycle.)
- **A lost link ends the session at once**, even with a Resource in flight,
  as the reference's `LXMPeer.link_closed` does (the peer goes back to
  IDLE). The Resource concludes FAILED on its own: the close cancels one in
  flight, one still waiting to be advertised fails at its next 0.25 s wait
  step (Reticulum-rust 6e53dea, `PARITY-AUDIT-1.5.2.md` A31), and one built
  after the close is refused, so `send_resource` returns the error (A32).
  Its ids stay unhandled; if it had in fact completed, the next offer finds
  the peer has them. The departure is the late callback: it belongs to an
  ended session, is recognised by its session number and is ignored, where
  the reference's `resource_concluded` tears down the link and clears the
  transfer of whatever session the peer is in by then.
- **Message files that cannot be read.** A file that is gone (`NotFound`)
  takes its message out of the store index and out of every peer's queues,
  with a warning: nothing can be sent or served from it again, and left
  queued it was offered, with a link opened for it, to every peer lacking it
  until it expired (7 days). The reference skips a missing file silently and
  marks it handled for that peer on COMPLETE. Any other read error (a
  permission problem, EIO) leaves the id unhandled, with a warning, as the
  reference's failed `open()` does.
- **Backoff is not reset by announces**, and the **startup backlog** (messages
  stored before start) is held back from sync for an hour; both predate this.
- **No 5-second assertion on the Resource or on the offer's round trip**
  (DESIGN_PRINCIPLES §1). The Resource's completion scales with size and RTT
  (as for app-links' Resources). The offer's round trip includes the remote
  peer choosing which offered ids it wants, over however many hops it sits
  (6-14 s to distant production peers, 2026-09-29), which rfed does not
  control; James removed that assertion on 2026-09-29. rfed logs each offer's
  round trip at NOTICE instead ("offer to peer X: answered after N s").

Known departure not yet fixed, outside rfed:

- **AppLinks re-opens a lost sync link once** (Reticulum-rust `SUBSYSTEMS.md`
  §1: "one automatic re-open attempt"). `open_persistent` is the only
  AppLinks mode that holds a link, and it re-arms that re-open on every
  establishment, so when the peer closes the sync link, or it goes stale,
  AppLinks expires the path, requests it and builds a new link that no
  session asked for (DESIGN_PRINCIPLES §3); the reference's
  `LXMPeer.link_closed` only returns to IDLE. rfed ends the session on the
  DISCONNECTED and closes the stray link when it comes up (above). Because
  `AppLinks::close` does not cancel an attempt already in flight, a session
  started while that re-open is still racing can run a second attempt beside
  it, and the one overwritten in AppLinks' registry is never torn down
  locally (a Python peer drops it after 180 s idle; an rfed peer keeps
  it). The fix belongs in AppLinks: a held-link mode without the
  close-triggered re-open, and a per-registration generation that `close`
  bumps and an attempt checks before it registers its link.

Fixed outside rfed: until Reticulum-rust 6e53dea (2026-09-28, A31) a sync
Resource whose link closed before it was advertised never concluded, its
advertise thread spinning every 250 ms for the life of the process with the
batch (up to ~1 MiB) held. A running rfed has the fix only if it was built
against 6e53dea or later: `rfed --build` prints the sibling commits it was
built from.

### Announce Metadata

The LXMF propagation destination announces with app_data:

```
[
  false,                            // protocol version marker
  unix_timestamp,                   // announce time
  true,                             // is active propagation node
  transfer_limit_kb,                // per-message limit, KB of 1000 B
  sync_limit_kb,                    // per-sync limit, KB of 1000 B
  [stamp_cost, flexibility, cost],  // PoW parameters
  {0x01: node_name}                 // metadata map
]
```

Both limits are integers in the reference's kilobytes of 1000 bytes, as LXMF
1.1.1 announces them and as every reader (`LXMPeer.sync`, rfed's own offer
planning) multiplies them back by 1000. `[storage] transfer_limit_mb` /
`sync_limit_mb` stay in MB (× 1024² bytes) and are divided by 1000 for the
announce; unset they are 256 and 10240 (LXMF's `PROPAGATION_LIMIT` and
`SYNC_LIMIT`). The sync limit is never below the per-message limit, as in
`LXMRouter.__init__`. Until 2026-09-28 rfed announced MB here, truncated, so a
default rfed announced `0` and `10`: every peer, Python or rfed, read a 0 KB
per-message limit and marked every message for rfed handled without sending
it. The shipped templates (`config.txt.example`, `rfed-nas.config`, the
first-run sample) leave both keys unset: their old 100 / 1000, announced for
real, said 100 MB per message and ~1 GB per sync, ~410× and ~100× the
reference; whole MB cannot express 256 KB. (`rfed.node` channel sync has
caps of its own, `channel_transfer_limit_mb` / `channel_sync_limit_mb`, §4.)

rfed holds senders to what it announces, as LXMF 1.1.1
`LXMRouter.propagation_resource_advertised` does: a propagation Resource
whose data size (the advertisement's `d`) is larger than the announced
per-sync limit × 1000 B is refused at its advertisement, with a log line
naming the size, the limit and the link. As in the reference there is no
per-message size limit on receipt — the per-transfer limit is the sender's
to apply (`LXMPeer.sync`, rfed's `plan_offer`); the reference's one
per-message check on receipt, `LXStamper.validate_pn_stamp` (a message no
longer than LXMF_OVERHEAD + STAMP_SIZE, or with a stamp under the cost, is
dropped), runs in rfed through the same stamper, and each batch's log line
counts those drops as `bad-stamp`.

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

A distro registered at the backup node is not a channel there (§6, "Channel
and distro hashes"): the push stores no pair under its hash and none whose
subscriber is the distro, and still answers `true` for the batch so that the
owner does not push it again; the tick delivers to no backup row under its
hash. The tick otherwise queues every blob the BlobStore holds under a row's
hash for the row's subscriber.

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
# transfer_limit_mb = 1     # unset: LXMF's 256 KB per message (§10)
# sync_limit_mb     = 10    # unset: LXMF's 10240 KB per sync (§10)
channel_transfer_limit_mb = 100   # /rfed/get per response (§4); unset: 100
channel_sync_limit_mb     = 1000  # /rfed/get per hour, all peers; unset: 1000

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
| `subscriptions.sqlite3` | SQLite | Subscription table |
| `notify_registrations.sqlite3` | SQLite | Notify relay registrations |
| `deferred_delivery.sqlite3` | SQLite | Offline blob queue |
| `distro.sqlite3` | SQLite | Distro device registrations (§17.6) |
| `distro_announces.sqlite3` | SQLite | Pre-signed distro announces |
| `peers.rmp` | msgpack | Peer sync state & backoff timers |
| `blobs/<ch_hex>/<id_hex>` | raw bytes | Stored inner blobs (written as `<id_hex>.tmp`, then renamed) |
| `lxmf_propagation/messagestore/<message_id_hex>` | raw bytes | Stored LXMF propagated messages (when enabled) |
| `lxmf_propagation/peers` | msgpack | Propagation peer state and sync backoff |
| `lxmf_propagation/node_stats` | msgpack map | Propagation message counters |

The SQLite stores run in WAL mode (each has `-wal` and `-shm` files beside
it) and write one row per change, so a node stopped at any moment keeps every
committed change. Until 2026-09-26 they were msgpack files of the same name
with `.rmp`, each rewritten whole on every change, and one that did not decode
loaded as empty and was overwritten. On first start a node imports each
`.rmp` file once and renames it `<name>.rmp.imported-<unix secs>`; a file that
cannot be read is renamed `<name>.rmp.unreadable-<unix secs>` and logged
(`[store]`), never overwritten. Neither is deleted.

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

The integration test suite lives in `cli-tests/rfed_tests/` and covers:

| # | Scenario | Description |
|---|----------|-------------|
| 1 | `live_fanout` | Subscribe → publish → verify immediate delivery |
| 2 | `deferred` | Publish while offline → come online → verify flush |
| 3 | `pull` | Publish while offline → explicit PULL → verify return |
| 4 | `notify` | Register relay → publish offline → verify wake packet |
| 5 | `sync` | Two-node: publish on A, subscribe on B, verify sync |
| 6 | `backup_failover` | Primary dies → backup activates → subscriber receives |
| 7 | `prop_notify` | Register via rfed.notify → send LXMF propagation → relay woken |
| 9 | `nse_timing` | Full propagation store-forward with tight NSE-like sync budget |
| — | `distro_e2e` | Distro register → propagate → PULL via rmap.world |

```bash
# Run all tests
./run_tests.sh all

# Run a specific scenario
./run_tests.sh 3

# Run distro E2E test (requires seeded identity, see seed_test_identity.sh)
RFED_TEST_HOST=rmap.world \
RFED_TEST_CONFIG_DIR=/tmp/rfed-local-rmap-client \
RFED_TEST_RUN_DIR=/tmp/rfed-actual-local-harness \
RFED_UPLINK_PORT=4242 \
RFED_LOCAL_CONFIG=/tmp/rfed-actual-local-rmap-only \
RFED_LOCAL_IDENTITY=... \
RFED_IDENTITY_HASH=... \
RFED_PUBLIC_KEY=... \
PYTHONPATH=... python distro_e2e_test.py
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
| `distro` | Boolean | Whether distro (multi-device fanout) is available. Always `true` on current rfed. |
| `distro_sync` | Boolean | Whether this node honours the §17.13 distro sync proof on `lxmf.propagation` uploads. Mirrors `lxmf_propagation`. |
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
  "distro": true,
  "backup": true,
  "stamp_cost": 16
}
```

---

## 17. Distro

Distro (Distribution List) provides personal multi-device message fanout for a
shared LXMF identity.  A user with multiple devices (phone, laptop, LoRa
messenger) registers each device's `lxmf.delivery` address under a single
"distro identity."  Any LXMF message sent to the distro identity is
automatically fanned out to all registered devices.

### 17.1 Architecture

Distro is a **double-wrap, server-blind** relay (same trust model as channels):

```
Sender → LXMF message encrypted to distro identity
       → lxmf.propagation PUT (standard LXMF path)
       → RFed intercepts, stores in BlobStore (NOT messagestore)
       → RFed fans out to each registered device (§17.3): /lxmf/delivery on
         its rfed.link, else its rfed.propagation.stream, else queued for
         /distro/pull with a notify wake — never an rfed.delivery packet
       → Device decrypts with the shared distro key
```

**Key differences from channels:**

| | Channel | Distro |
|---|---|---|
| Identity model | Derived from channel name | Standard LXMF identity, shared out-of-band |
| Registration | Self-service (know name → join); the subscriber is the device, signing with its own key | Owner-managed (distro key proves ownership); each device registers under the distro |
| Sender experience | Must know channel name, derive keys | Sends normal LXMF to a normal address |
| Reply identity | The poster's posting identity: the distro when the device holds one, otherwise the device (§17.12) | All devices reply as the distro identity |
| Ingress | `/channel/publish` on `rfed.link`, or a DATA packet to the legacy `rfed.channel` / `rfed.channel.publish` | `lxmf.propagation` (intercepted) |
| Membership across a distro's devices | Synced by the `rfed.distro.channel` message (§17.12); each device subscribes itself | Each device registers itself |
| Routing hash | Channel identity hash (§1); a registered distro's hash is refused (§6) | The distro's `lxmf.delivery` hash |

### 17.2 Cross-Node Distribution

Distro messages are stored in **BlobStore** (not the LXMF propagation
messagestore) and synced between RFed nodes via **FedSync** (the same
`rfed.node` OFFER/MESSAGE_GET engine channels use).  This avoids polluting
the vanilla `lxmd` propagation mesh with messages those nodes can never
deliver.

Each RFed node maintains its own **DistroTable** — a per-node registry of
which devices have registered locally.  A node pulls distro blobs from
peers when it has at least one local device registered for that distro hash.

### 17.3 Delivery

A distro message reaches each registered device the way a propagated
message reaches its recipient (§7 "Live delivery and its proof"):

1. `/lxmf/delivery` on the device's bound `rfed.link`: the bare LXMF blob,
   confirmed by the response;
2. else its `rfed.propagation.stream` link: the bare LXMF blob, confirmed by
   the link proof;
3. else, and whenever 1 or 2 goes unconfirmed, a **hand-off**: the blob is
   queued in the **DeferredQueue** under the device's identity hash, and then
   the device is pushed through its LXMF notify registrations (§9), stored
   under its `lxmf.delivery` hash, so that it collects the blob with
   `/rfed/pull` (`handoff::distro_hand_off` with `Wake::Push`). Queue first:
   the push makes the device pull. The push carries no sender and no channel.
   A blob that arrived with an accepted §17.13 sync proof is queued and not
   pushed (`Wake::QueueOnly`), at every hand-off point alike, unless the
   device then holds 64 or more queued blobs of the distro, or the queue
   holds three quarters of its global limit or more: then it is pushed as
   above.

The leading 16 bytes of the blob are its destination, the distro's
`lxmf.delivery` hash, which is how the device tells a distro message from
one addressed to itself. The blob is a standard LXMF propagation message,
encrypted to the distro identity's X25519 key; RFed never decrypts it.
`/rfed/pull` returns `[distro_lxmf_hash, lxmf_blob]` pairs (§17.8).

No distro message is sent as an `rfed.delivery` packet, and the
`rfed.delivery` announce flush leaves distro blobs queued: nothing confirms
such a packet. Until 2026-09-26 a device with no live session was sent one
and it counted as delivered, and no distro fan-out pushed anyone: an Android
or iOS device whose app was closed got no push for its distro, and a device
whose app had died, but whose path rfed still held, lost the message.

### 17.4 RNS Destinations & Request Paths

| Destination | Aspects | Request Path | Purpose |
|---|---|---|---|
| `rfed.distro.register` | `["distro", "register"]` | `/rfed/distro/register` | Register a device |
| `rfed.distro.unregister` | `["distro", "unregister"]` | `/rfed/distro/unregister` | Remove a device |
| `rfed.distro.list` | `["distro", "list"]` | `/rfed/distro/list` | List registered devices |

All three use `DestinationType::Single`.

### 17.5 Registration Protocol

The distro owner proves possession of the distro private key by signing the
registration payload.  The protocol mirrors the channel subscription format:

**Register / Unregister:**
```
Payload: msgpack [ bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey) ]
```

`verify_signed_payload` extracts `(device_pubkey, distro_identity_hash, distro_pubkey)`
and validates `sig(device_pubkey)` against `distro_pubkey`.  The server derives:
- `distro_lxmf_hash` = `Destination::hash(app="lxmf", aspects=["delivery"], identity_hash=distro_identity_hash)`
- `device_lxmf_hash` = same derivation from `device_pubkey`

**List:**
```
Payload: msgpack [ bin(16) distro_identity_hash, bin(64) distro_pubkey, bin(64) sig(distro_identity_hash) ]
Response: msgpack [ bin(16) device_lxmf_hash, ... ]
```

### 17.6 DistroTable Schema

Per-node table persisted to `distro.sqlite3` (one row per device registration):

| Field | Type | Description |
|---|---|---|
| `distro_lxmf_hash` | `[u8; 16]` | Distro identity's `lxmf.delivery` hash (routing key) |
| `device_lxmf_hash` | `[u8; 16]` | Device's `lxmf.delivery` hash |
| `device_pubkey` | `[u8; 64]` | Device identity public key (for outbound delivery) |
| `added` | `f64` | Unix timestamp of registration |
| `owner_node_hash` | `Option<[u8; 16]>` | Reserved for backup failover (future) |
| `last_refreshed` | `f64` | Backup TTL tracking (future) |

### 17.7 Sync Engine Integration

The FedSync engine treats channel and distro blobs uniformly:

- **Manifest building** (`local_manifest`): includes blobs for channels with
  local subscribers AND distros with local devices.
- **Gap filtering** (`gap_from_peer`): pulls blobs for subscribed channels
  OR registered distros that the node doesn't already hold.
- **Post-ingest dispatch**: calls `distro_fanout()` for a hash that is a
  distro registered at this node and `fanout_blob()` for any other hash,
  never both (§6, "Channel and distro hashes"), then enqueues missed
  subscribers/devices in the DeferredQueue.
  A blob that arrives by FedSync carries no §17.13 proof, so its hand-off
  wakes (§17.13 "Not covered").

### 17.8 Deferred PULL on distro.register

In addition to `rfed.delivery`, the `/rfed/pull` request path is also
registered on `rfed.distro.register`. This allows a client to reuse an
existing distro.register link for PULL without establishing a separate
link to `rfed.delivery`.

This is important for relay nodes (e.g., rmap.world) that may drop rapid
successive link requests from the same client. By reusing the register
link, the client avoids a third LINKREQUEST that the relay might drop.

| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.distro.register` | `/rfed/pull` | Subscriber | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) distro_hash, bin blob], …], bool more_pending ]` |

The response format is identical to the `rfed.delivery` PULL response.
The `distro_hash` field contains the distro's `lxmf.delivery` hash
(the routing key), and `blob` is the raw LXMF propagation message.

### 17.10 Distro Announce

RFed rebroadcasts the pre-signed `lxmf.delivery` announce a device hands it
on `/rfed/distro/announce` (§17.4). Its `app_data` is the LXMF 0.5.0+ list
and marks the address as a distro:

```
[ announce_name,  // bin, or nil: the user's Announce Display Name, empty by
                  // default (LXMF-rust/DISPLAY_NAMES.md §2.2); other names
                  // travel inside encrypted messages, in key 0 of
                  // the Retichat field 0xD1
  nil,            // stamp_cost: none
  [ 0xD0 ] ]      // supported_functionality: SF_RFED_DISTRO
```

`SF_RFED_DISTRO = 0xD0` is an entry in the supported-functionality list
next to LXMF's `SF_COMPRESSION = 0x00`. The list has no custom range, so
the value sits far above what upstream counts up from zero and outside the
one-byte msgpack range it would fill first. Readers check membership only,
so the reference ignores it, and a device that also wants to claim
compression may list both.

This is the only way an address is known to be a distro. No device answers
a direct link to a distro address, so a sender that has seen the flag sends
PROPAGATED at once (LXMF-rust `LXMRouter::handle_outbound`, Retichat-js
`isDistro` contacts). The flag is learned from the announce a sender needs
anyway to encrypt to the address; nothing is queried, and a contact link
(`lxma://hash:pubkey`) carries a key, not this fact. `lxmf_rust::distro::
announce_payload` always writes the flag; `lxmf_rust::lxmf::
distro_from_app_data` reads it.

### 17.11 Sent-message sync

A message a device sends *as the distro* (§17.1: "all devices reply as the
distro identity") reaches its recipient but, without this section, none of
the distro's other devices: the conversation on each sibling shows only the
other side's half. The sending device therefore also sends a copy to the
distro itself, and every sibling files it as a message it sent.

**Who sends it.** A device holding distro identity D that sends an LXMF
direct message M as the distro (source = D's `lxmf.delivery` hash, signed
with D's key) to a recipient R, where R != D, also sends a copy C:

| | Copy C |
|---|---|
| Destination | D's `lxmf.delivery` |
| Source / signature | D, signed with D's key (the same "send as distro" path as M) |
| Title, content | Identical to M's. Text only: attachments are **not** copied; if M carried attachments, C's content is M's content unchanged and C carries none |
| `fields[0xFB]` (FIELD_CUSTOM_TYPE) | `"rfed.distro.sent"` |
| `fields[0xFC]` (FIELD_CUSTOM_DATA) | R's `lxmf.delivery` address, 32 lowercase hex characters |
| `fields[0xFD]` (FIELD_CUSTOM_META) | The **sending device's own** `lxmf.delivery` address, 32 lowercase hex characters |
| Method | PROPAGATED at once (D is a distro, §17.10), with a §17.13 sync proof; RFed intercepts it on `lxmf.propagation` like any distro message (§17.1) and fans it out to every registered device of D, the sender included, waking none (§17.13). Without an accepted proof (an older sender) an unconfirmed device is woken |

C is made once per message the user sent, not once per delivery attempt or
method: a DIRECT attempt of M followed by a propagated fallback is still one
message and one copy. C is packed and signed by D, encrypted to D and proven
for §17.13 once, when it is made, and the sending device keeps it until the propagation node proves it has it. An
upload of C that is not proved (its packet was reported lost, or the link
closed or the connection stopped first) is uploaded again when the
propagation link next comes up: an event, never a timer. That second upload
is a send retry, which DESIGN_PRINCIPLES.md §3 allows here only because
James decided it as an exception on 2026-10-03 ("what a device owes its
distro"), for C and the §17.12 membership message alone. James's rulings of
the same day, written under that exception in §3, say what "comes up" means
and bound the retry; §17.12 "On the sending device" states them. Every rule
of §17.12 "On the sending device" applies to C as written there for the
membership message, with two differences:

- Each copy is owed on its own, under its own LXMF message hash, and no
  later message replaces it.
- Giving up D does not drop it (James, 2026-10-03; DESIGN_PRINCIPLES.md
  §3). When the device forgets D or takes another distro, C is already
  packed and signed as D, so it stays owed to D and is still uploaded on
  later comings-up of the propagation link: the same packed message,
  encrypted to D. The device therefore keeps D's public key with C. C is
  never addressed to another distro, never sent under another distro and
  never packed again. Only the membership messages owed to D are dropped
  (§17.12).

Every upload of C is the same sealed message (§17.13), so RFed holds a second
upload as the message it already has and fans it out once; a sibling that
gets it twice anyway stores it once (rule 5). C's state never changes M's delivery state,
and it creates no message of its own on the sending device.

Retichat-js keeps C in its distro outbox from 73a725d (branch
`distro-channels-web`, not merged; §17.12 Implementation index). At 90640bf
it follows these rules. 145ca2f did not: it dropped C when the device gave
up D, and a flush of the outbox already under way could upload C again on
its own failure. 74fbbcd brought it in line ("Retichat-js departures" in the
§17.12 Implementation index). 367b266's departure, a failure record kept
per channel, touched only the membership messages: each sent copy is owed
under its own id, so no other message's decision could take its record.
Retichat-ios at 07f6d70 and Retichat-android at 47bdb0a still hand C to
the LXMF router once and keep nothing (`ChatRepository.sendDistroSentCopy`
on both), so a copy whose upload is not proved, or that is made while no
propagation link can be had, is lost. Their follow-up is "The phones'
outbox" in the §17.12 Implementation index.

**No copy is sent for:** identity transfers (`"rfed.distro.transfer"`,
§17.9), delivery notifications and ticket-only messages, group messages,
channel messages, messages whose destination is D itself (the channel
membership messages of §17.12 among them), or when the device holds no
distro identity. A channel post needs no copy: every sibling subscribed to
the channel receives the post itself (§17.12).

**Receiving.** A device unwraps a fan-out blob with its distro key (§17.3).
A message whose `fields[0xFB]` is `"rfed.distro.sent"` is a copy, and the
device applies these receive rules to it in order; the first rule that drops
the copy ends the check. A message from D without the marker keeps its
existing behaviour.

1. **Source.** If the unwrapped source is **not** the device's own distro
   D, the copy is ignored and logged: a genuine copy always comes from D,
   and anyone else claiming the marker is filing words into the user's
   conversations.
2. **Signature.** A copy whose source is D MUST carry a valid LXMF
   signature by D's key. A copy that fails the check is dropped with a log
   line and is never stored or shown. Rule 1 alone proves nothing: the
   LXMF source hash is plaintext inside the encrypted body, and D's public
   key is announced (§17.10), so anyone can encrypt a message to D that
   claims source D. Only the distro key can produce a genuine copy, and
   that holds only because of this check. The check is the one LXMF makes
   on every message it unpacks (`LXMessage.unpack_from_bytes`): with `dest`
   D's 16-byte `lxmf.delivery` hash that prefixes the blob, `src` and
   `signature` the first 16 and the next 64 bytes of the decrypted
   plaintext, and `payload` the msgpack bytes after them, the signature
   must be D's Ed25519 signature over
   `dest || src || payload || SHA-256(dest || src || payload)`. If the
   payload array carries a fifth element (a stamp), `payload` is instead
   the first four elements, `[timestamp, title, content, fields]`,
   re-packed with msgpack, because LXMF builds the signed data before it
   appends the stamp.
   `lxmf_rust::distro::unwrap_blob` enforces this rule for both native
   bridges: it returns an error for a copy that claims source D without
   D's signature, so Android's `nativeDistroUnwrap` and iOS's
   `retichat_distro_unwrap` return no message and the client logs the
   rejection.
3. **Own echo.** If `fields[0xFD]` equals this device's own
   `lxmf.delivery` address, the copy is this device's own echo. It is
   dropped silently, but still recorded for deduplication.
4. **Recipient.** `fields[0xFC]` must be exactly 32 hex characters and
   must not be D itself (a sender never copies a message addressed to D,
   so such a copy is malformed); anything else is dropped with a log line.
5. **Store.** A copy that passes rules 1-4 is stored as an **outgoing**
   message in the direct conversation with R:
   - sender D (it came from the distro, i.e. from "me");
   - state SENT, never DELIVERED: this device cannot know whether R
     received M;
   - timestamp = C's LXMF timestamp;
   - message id derived exactly as for any other distro fan-out message
     (source + timestamp + content), so a copy arriving twice (live fan-out
     and `/rfed/pull`, §17.8, or two uploads of one C by the sender) is
     stored once;
   - the conversation with R is created if it does not exist, with no
     contact request and no stranger filter, since the user wrote to R;
   - no push or local notification: it is the user's own sent message.

`lxmf_rust::distro::unwrap_blob` reads the marker for both native bridges:
`DistroMessage.sent_to` is `fields[0xFC]` lowercased, and is set only when
the type matches and the value is 32 hex characters. `DistroMessage.sent_by`
is `fields[0xFD]` lowercased, and is set whenever the type matches (empty
when 0xFD is absent), so the client can still apply rule 1 to a marker from
another source. A set `sent_by` with no `sent_to` is therefore a copy with a
malformed 0xFC, which rule 4 drops. The unwrap JSON of Android's
`nativeDistroUnwrap` and iOS's `retichat_distro_unwrap` carries them as
`"sent_to"` and `"sent_by"` (string or null).

**Older clients.** A client that predates this section does not know the
marker and shows each copy as an incoming message from the distro address,
in a conversation with D. That remains so until the client is updated. It is
not worked around on the sending side or in RFed: RFed never decrypts the
copy, and suppressing copies to hide it would take the feature away from
updated siblings.

**Privacy.** `fields[0xFD]` reveals which device sent M. C is encrypted to D,
so only holders of the distro key can read it, and they are the user's own
devices, which already know one another's addresses from
`/rfed/distro/list` (§17.5). RFed and relays see only an ordinary distro
blob.

### 17.12 Channels and the distro

Decided by James, 2026-10-03. RFed joins the two mechanisms nowhere: it never
sees who signed a post (the source is inside the EC envelope), its channel
fan-out reads only the subscription table (§8), and its distro fan-out
carries only messages addressed to a distro (§17.3). This section is the
contract for a device that holds a distro identity D and uses channels.
Before it, every client signed its posts, subscribed, and kept its channel
list as the device alone (Retichat-js 24d83e6, Retichat-ios 07f6d70,
Retichat-android 47bdb0a), so a user's own post from another device showed
as a stranger's, and each device had to join each channel itself.

**Posting and subscribing.** Normative in RFed-spec/Channel.md, "Distro
holders"; in short:

- A post is signed by D: its `source_hash` is D's `lxmf.delivery` hash and
  its RTID prelude carries D's public key. Without a distro, the device signs.
- `/rfed/subscribe` and `/rfed/unsubscribe`, the stream-open signature, the
  link's identify (and so every pull) and the channel notify registrations
  stay the **device's**. RFed keeps one subscription row, one bound
  `rfed.link`, one deferred bucket and one wake per subscriber hash (§6, §7,
  §9). Devices subscribed under D would be one subscriber: the last to bind
  would get every push, the first to pull would take what the others missed,
  and every wake would go to D. They would steal each other's posts.
- A received post is the user's own when its source is the device's
  `lxmf.delivery` hash or D's. It is shown as outgoing, never notified, never
  counted as a sender, and deduplicated by `(source, timestamp_ms)` against
  what the client has stored, rfed's echo of the post included. One stored
  from RFed (a sibling's post) has state SENT, as §17.11 rule 5 gives a sent
  copy. It came from RFed, so RFed has it. It is never DELIVERED, since a
  channel post has no per-reader confirmation, and never sending or failed.
- The Channel Display Name state is kept per channel and posting identity.
  It learns from D's posts that reach the device, whichever device sent
  them, but only a value equal to the one this device would send itself
  (LXMF-rust/DISPLAY_NAMES.md §4.2).

**Membership sync.** Joining or leaving a channel on one device is applied on
every other device of D. The change travels as a distro message through the
existing fan-out, the way a sent copy does (§17.11); each sibling then
subscribes or unsubscribes with its own device key. RFed needs no change.

*Who sends it.* A device holding D whose channel list changes by the user's
own action — the user joins a channel not in the list, or leaves one that is
— sends one membership message C. Nothing else sends one: not a change made
by applying a received C, not restoring or re-subscribing the list at start,
not a stamp refresh, not a join of a channel already in the list, and not a
device that holds no distro.

| | Membership message C |
|---|---|
| Destination | D's `lxmf.delivery` |
| Source / signature | D, signed with D's key (the "send as distro" path of §17.11) |
| Title, content | Empty |
| `fields[0x0C]` (FIELD_TICKET) | An empty bin. It is no ticket: it is there so that older clients take C for a delivery notification and drop it (below; web builds before 2026-09-30 do not). Receivers neither read nor remember it |
| `fields[0xFB]` (FIELD_CUSTOM_TYPE) | `"rfed.distro.channel"` |
| `fields[0xFC]` (FIELD_CUSTOM_DATA) | A msgpack array, as a native array, never a bin holding packed msgpack (CHECK_THESE_THINGS_FIRST.md §11): `[op, name, at_ms]`. `op` is the str `"join"` or `"leave"`. `name` is the channel's full name as the sending device stores it, as UTF-8 str (receivers accept bin too): `<root>.<name>` for every channel joined since the name rules of 2026-09-27, and for a channel joined earlier the name it was joined with, which may break those rules (Retichat-js before b75e02e joined any trimmed name). `at_ms` is the time of the user's action in milliseconds since the epoch (rule 5 below): a msgpack integer from 0 to 2^53 − 1, in any integer encoding: the web writes int 64 (`0xd3`), rmpv and umsgpack write uint 64 (`0xcf`) ("`at_ms` on the wire" below). A larger value is no `at_ms`, and rule 4 drops it. Receivers ignore elements after the third |
| `fields[0xFD]` (FIELD_CUSTOM_META) | The **sending device's own** `lxmf.delivery` address, 32 lowercase hex characters |
| `fields[0xD1]` | None: C is a message to one's own devices and carries no Message Display Name (DISPLAY_NAMES.md §4.1) |
| Method | PROPAGATED at once (D is a distro, §17.10), with a §17.13 sync proof; RFed intercepts it on `lxmf.propagation` and fans it out to every registered device of D, the sender included, waking none (§17.13) |

The name is all a sibling needs to join. For a public channel it is
`public.<name>`. For a private channel it is `<root>.<name>`, which is the
invite and the key at once: the channel identity is derived from it (§1), and
there is no other key material. C is encrypted to D, so only holders of D's
key can read it; RFed, relays and peers see an ordinary distro blob.

*`at_ms` on the wire.* msgpack has two 64-bit integer types, and the clients
write different ones for the same value. Both are valid C, and the type
carries no meaning:

- Retichat-js writes **int 64** (`0xd3`, eight bytes, big-endian two's
  complement). `channelSyncFields` passes `BigInt(atMs)`, and msgpackr writes
  a BigInt below 2^63 that way; a plain JavaScript number above 2^32 would go
  as a float 64, which is no `at_ms`. 2026-01-01 00:00 UTC is
  `d3 00 00 01 9b 76 da a8 00`.
- An rmpv writer (LXMF-rust, so iOS and Android) and the Python reference
  (umsgpack) write the smallest encoding, which for any time after
  1970-02-19 (2^32 ms) is **uint 64** (`0xcf`).

A receiver MUST accept every msgpack integer encoding (positive fixint,
uint 8 to 64, int 8 to 64) and judge the value, never the type byte.
LXMF-rust reads it with `rmpv::Value::as_u64()`: rmpv 1.0.0 decodes an int 64
holding a non-negative value as a positive integer, so `as_u64()` gives the
value for `0xd3` exactly as for `0xcf`, and `None` for a negative integer or
a float. Retichat-js reads it from the payload's bytes (`lib/channel_sync.js`
`readChannelSync`, through `msgpack_raw.js` `readHead`), every integer
encoding included. A float (`0xca`, `0xcb`), even an integral one, a negative
integer, a str and a nil are no `at_ms`, and rule 4 drops them.

The value is bounded at 2^53 − 1, on both sides. A writer MUST NOT write a
larger one: the web holds `at_ms` in a JavaScript number, which is exact only
up to there, and its writer refuses a larger one. A receiver MUST drop a
larger one under rule 4, whatever its encoding, because the clients would
otherwise order it differently. `readHead` turns a 64-bit integer into a
JavaScript number, which rounds above 2^53 − 1 (2^53 + 1 reads as 2^53),
while `as_u64()` keeps it exact. A join at 2^53 + 1 and a leave at 2^53 would
then be equal times on the web, where rule 5 keeps the leave, and different
times on a phone, where it keeps the join. So LXMF-rust takes `as_u64()` and
then refuses a value above 2^53 − 1, and the web refuses a value that is not
`Number.isSafeInteger` (every value read from 2^53 up rounds to 2^53 or
more, which is not). A millisecond clock stays below the bound for about
285,000 years, so no real C is dropped by it.

The type does not affect rule 2. C's payload has four elements and no stamp (D
asks none, §17.10), so every receiver checks D's signature over the payload
bytes as received (§17.11 rule 2), as the reference does for an unstamped
message. A receiver MUST NOT decode C's payload and re-pack it to check the
signature: rmpv and umsgpack re-pack the web's `0xd3` as `0xcf`, the hash
changes, and every C from the web would fail rule 2. In LXMF-rust,
`distro::unwrap_blob` (its `lxmf_signature_valid`) hashes the received bytes
and is the check to use. `LXMessage::unpack_from_bytes` re-packs every
payload, stamped or not, so it is not. Checked on 2026-10-03 with a C built by
Retichat-js a448e98's own `channelSyncFields` and `LXMessage.pack`: the
shipped `unwrap_blob` reports `signature_validated` and
`is_delivery_notification`, and `as_u64()` gives `at_ms`; D's signature fails
over rmpv's re-pack of the same payload. The web reads a `0xcf` `at_ms` as it
reads its own.

*On the sending device.* One C is made per change. Its delivery state changes
nothing in the sending device's list, which changed when the user acted. The
device still keeps C until the propagation node proves it has it:

- C is packed and signed by D, encrypted to D and proven for §17.13 once,
  when the user acts, and written with its proof to persistent storage
  before anything can yield.
- It is uploaded at once when the propagation link is up, and otherwise when
  the link next comes up. That wait is the ordering of DESIGN_PRINCIPLES.md
  §5, not a retry: the link coming up is the readiness signal, and C has not
  been sent before it. Only events start an upload: the user's action, the
  link coming up, and, for an upload left open on a STALE link that a newer
  link replaced, that old link's close while the newer link is up (the third
  ruling, below), or the exchange's report that the upload's packet was
  lost, which counts the same as that close (James, 2026-10-04). Only events
  end one: the node's proof, or one of the three failures below. A build
  that throws ends the attempt before anything leaves ("A build that throws
  is a failure", below). There is no timer.
- The node's proof settles C: it is owed no more and never goes again. A
  proof that comes after the upload was reported lost settles it too.
- An upload that is not proved (its packet was reported lost, or the link
  closed or the connection stopped first) is a failure, and the device says
  so: a log line, and an error the client can show the user. C stays owed.
  An upload that fails after C is owed no more (another upload of it was
  proved, a later action replaced it, or it was dropped with D) failed no
  one: it is logged as that, with no error.
- **C whose upload was not proved is uploaded again when the propagation
  link next comes up.** Decided by James, 2026-10-03. It is a send retry,
  which DESIGN_PRINCIPLES.md §3 forbids, and it is allowed here as the
  exception §3 records as "what a device owes its distro": a membership
  message or a §17.11 sent copy is kept until the propagation node proves
  it, an upload that is not proved is followed by another when the
  propagation link next comes up, an event and never a timer, and only the
  newest action per channel is ever owed. The exception covers those two
  distro messages only, not DMs, links or path requests. James's rulings of
  the same day, written under it in §3, are its bounds, and every client
  keeps them. This section numbers them in §3's order: the first is what
  "comes up" is, the second that a failure alone never sends an upload
  again, the third the replaced STALE link (these three just below), the
  fourth the phones' "packet reported lost" ("The phones' outbox" in the
  Implementation index), and the fifth a distro given up (below). The
  bullets after the three rulings apply them. Each one that is this
  section's own rule or reading, not James's words, says so.
  - **What "comes up" is.** The propagation link comes up when a new
    propagation link is established, or when a STALE link recovers because
    the node is heard from on it again. Both count (James, 2026-10-03). A
    STALE link is one the node has not been heard on, and its recovery is
    the node heard on it again: an event, not a clock.
  - **Never on its own failure.** An upload is never sent again on the
    strength of its own failure alone. A failure waits for the next
    coming-up, even when a send pass is already running on the link that is
    up (James, 2026-10-03). A send pass (a flush) is what one coming-up
    starts, and nothing else starts one. It uploads an entry only if the
    entry's last failure was decided before that coming-up. That holds
    whoever made the upload that failed: the pass itself, an earlier or a
    newer pass, the user's own action while the link was up, or a link
    since replaced. So an upload decided unproved while a pass builds an
    earlier entry is not uploaded by that pass. It goes once on the next
    coming-up, which may be on the same link (its recovery from STALE).
    Never a timer, and never the failure itself.
  - **A STALE link replaced by a new one decides nothing** (James,
    2026-10-03). The node may still prove the upload over the old link, and
    the old link keeps its grace for that late proof. A proof over it
    settles C, with one upload, one stamp and one fan-out. If the old
    link's own close then finds the upload unproved while a newer
    propagation link is already up (ACTIVE), that close is the event, and C
    goes once on the newer link at once. The exchange's report that the
    upload's packet was lost counts the same as that close (James,
    2026-10-04). Until that day this section counted the loss report under
    the ruling without saying that it was not James's words (the verifier
    of 2683ea4). The newer link came up while the upload was open, and the
    in-flight bound below held C back then. If no newer link is up, C waits
    for the next coming-up. A failure of the upload on the newer link
    follows the second ruling: it waits for the next coming-up. A connection
    that stops decides every upload and sends nothing, since no link stays
    up after it.
  - **A late proof after the third ruling's send** (this section's rule).
    When the loss report for the old link's upload sent C on the newer
    link, and the node then proves that first upload late over the old
    link, the late proof settles C. C is owed no more and does not go
    again, and the upload on the newer link changes nothing. If both
    uploads reached the node, the siblings get C twice and hold the second
    as a repeat ("Receiving"). That is the cost of a loss report that was
    wrong, as with any upload.
  - **A failure belongs to the exact message** (this section's rule, which
    the second ruling needs). A send pass reads when the last upload of
    that very message was decided unproved: the message as packed, owed
    under its id, not anything else owed under the same channel. A
    membership message that a later action on the channel replaced is owed
    no more. A decision about it never replaces, clears or stands for the
    newer message's record: not its proof or late proof, not its loss
    report or its link's close, not its build throwing. A message owed no
    more keeps no record. Without this rule the second ruling fails when two
    actions on one channel overlap. The join's upload is left open on a
    replaced STALE link, and the user's leave goes at once on the newer
    link. The leave's upload is reported lost while a pass builds an
    earlier entry. Then the old link's close decides the join, and its
    record takes the leave's place, so the pass uploads the leave again at
    once, on its own failure (Retichat-js 367b266, "Retichat-js
    departures").
  - **A replaced link's recovery is not a coming-up** (this section's
    reading of the first and third rulings together, not James's words). A
    STALE link that a new propagation link has replaced is no longer the
    propagation link. Under the third ruling it keeps only its grace for a
    late proof, and what is owed goes on the newer link. So when the node
    is heard on the replaced link again, no send pass runs on it, and what
    is owed waits for the current link's next coming-up. An upload still
    open on the replaced link is decided as the third ruling says.
  - Only the three events that §3 names decide an upload: the packet
    reported lost, the link closing, the connection stopping. Replacing a
    link is none of them. An upload that went as a Resource (a §17.11 sent
    copy larger than the link's MDU) has no packet to report lost: the
    Resource's own failure decides it, and with a newer link up it is the
    third ruling's event, as the loss report is (James, 2026-10-04: "same
    as a loss"). On the phones a Resource upload has no packet receipt to
    time out; its own failure is the same event (James, 2026-10-04).
  - **A build that throws is a failure** (this section's rule, under the
    second ruling). Building an upload (the distro's key, the encryption,
    the stamp, the packet) can throw before anything leaves. The device
    says so, C stays owed, and the failure is recorded as for an upload
    decided unproved, so no send pass already under way builds it again. It
    goes once on the next coming-up. A build abandoned because the link
    went down while it ran is no failure: nothing left and nothing is
    decided, and C goes when the link is next up. In Retichat-js a stamp
    that cannot be mined does not throw: `_buildPropagationPacked` sends the
    upload without one and logs that the node will refuse it. What throws
    there is the key, the encryption or the packet.
  - At most one upload of C is in flight. While an upload has left and is
    not decided, C is not uploaded again on any link, including a new link
    that replaced the old one. Two uploads at once would cost two stamps
    and give the siblings two fan-outs.
  - No count and no clock ends it. C stops being owed when the node proves
    it (a proof after the loss report included), when a later action on the
    channel replaces it, or when the device gives up D (below; a §17.11
    sent copy is not dropped then).
- Every upload of C is the same LXMF message, packed and sealed once
  (§17.13); RFed does not fan out a second upload of it. A sibling that gets
  C twice (the node had an upload whose proof never reached the sender, or the
  sender uploaded it again) holds the second as a repeat ("Receiving") and
  applies C once.
- At most one C is owed per channel. A later join or leave of the same
  channel replaces the C still owed, and a replaced C is never sent, by this
  device now or after a restart (in a browser, by a later page). That holds
  when C was replaced while its upload was being built. It also holds when
  storage refuses the C that replaces it: the device still takes the replaced
  C out of storage, with a write no larger than what storage holds. Sending a
  replaced C would be worse than losing it, because the siblings would make
  the change the user undid. Only the newest action goes, the one rule 5
  would keep anyway.
- When the device gives up D (forgets it, or takes another distro), every
  membership message C owed to D is dropped then, with a log line (James,
  2026-10-03; DESIGN_PRINCIPLES.md §3). It is not kept in case D comes back,
  and it is never sent under another distro. A kept C would go if D came
  back, after changes the user made without D that no C reported (a leave of
  the same channel, say), and the siblings would join a channel the user
  had left. An upload of C that has already left cannot be taken back: if
  the node proves it, D's devices apply it, and the log line says so. The
  §17.11 sent copies owed to D are not dropped. Each is already packed and
  signed as D, so it stays owed to D and is still uploaded to D on later
  comings-up, never re-addressed, never sent to another distro and never
  packed again (§17.11).

Retichat-js at 90640bf, the branch's final commit, meets every point,
including the Resource case James ruled on 2026-10-04 (above). 90640bf changes no
code of 2683ea4's, nor did b6c7f7f before it: their `app.js` and `lib/`
differ from 2683ea4's only in comments. 367b266
departed from one point: it kept a failure record per channel, so the
second ruling failed when two actions on one channel overlapped ("A failure
belongs to the exact message"). 9d45faa brought it in line. 145ca2f departed from three, each a
ruling James made on 2026-10-03:
- a flush already under way uploaded an entry again on its own failure;
- a replaced link's close left the entry waiting while a newer link was up;
- giving up D dropped the sent copies too.

74fbbcd brought it in line on all three, and 367b266 added the tests that
pin the second ruling for an upload that an earlier flush made. a448e98 had
departed from the last two points, and 3411e19 and 145ca2f brought it in
line on those ("Retichat-js departures" in the Implementation index). The
losses that remain on the sending device are listed under "Not covered"
below.

*Receiving.* A device unwraps a fan-out blob with its distro key (§17.3). A
message whose `fields[0xFB]` is `"rfed.distro.channel"` is a membership
message, and the device applies these rules to it in order; the first rule
that drops it ends the check. A membership message is a repeat (one copy from
the live fan-out and one from a pull, or the second upload of one C) only when
its LXMF message hash is one already seen. The id that §17.11 rule 5 gives
other fan-out messages, from source, timestamp and content, is not enough:
every C has source D and empty content, so two siblings' Cs made in the same
millisecond would share it, and one of the two actions would be lost.

1. **Source.** If the unwrapped source is not D, it is ignored and logged.
2. **Signature.** It MUST carry a valid LXMF signature by D's key, checked
   exactly as §17.11 rule 2 checks a sent copy; one that fails is dropped
   with a log line. D's public key is announced, so anyone can encrypt a
   message to D that claims source D. Without this check a stranger could
   make the user's devices join a channel of the stranger's choosing, or
   leave a channel and delete its history.
3. **Own echo.** If `fields[0xFD]` is this device's own `lxmf.delivery`
   address, it is dropped silently and recorded as seen: this device made
   the change when the user acted.
4. **Form.** `op` must be `"join"` or `"leave"`, `name` a non-empty str or
   bin, and `at_ms` an integer from 0 to 2^53 − 1, in any integer encoding
   ("`at_ms` on the wire"). A `join`'s name must also be one
   the client's own join accepts (the rules a typed name must pass). A
   `leave`'s name is not held to those rules. The channel it means is the one
   whose hash the name gives (§1, the derivation every client stores its
   channels under), so a channel joined before the rules (for example
   `public.Test`) can still be left on every device. Anything else is dropped
   with a log line.
5. **Order.** The device keeps, per channel hash, the last membership action
   it made or applied, `(op, at_ms)`, persisted, and kept after a leave. A
   message whose `at_ms` is older than the recorded one is stale and is
   dropped (recorded as seen). At an equal time a leave replaces a join and a
   join never replaces a leave, so every device ends in the same state in
   whatever order the messages arrive. A user's action on this device is
   recorded the same way, and the C it sends carries that record: its `at_ms`
   is the current time, or one more than the `at_ms` already recorded for the
   channel when that is later. So an action made after this device received
   a sibling's record is newer than that record on every device, even when
   this device's clock is behind the sibling's. The guarantee needs that
   record to have arrived. Actions that two devices make before either has
   the other's record (concurrent, or while one was offline) are ordered by
   their clocks alone. The larger `at_ms` wins everywhere, so with a clock
   behind, the action the user made later can lose. For example, A leaves at
   12:00, and B, ten minutes slow and not yet holding A's leave, joins at
   12:05 stamped 11:55: every device ends left. All devices still end in the
   same state.
6. **Apply,** with this device's own identity and its own configured RFed
   node, as the user's own join or leave on this device would:
   - `join` of a channel not in the list: the channel is added, then
     subscribed with the device key. It is stored before it is subscribed,
     so a subscription that cannot be made now is made by the client's own
     subscription of stored channels when its RFed link is ready, never by
     a retry (DESIGN_PRINCIPLES.md §3, §5);
   - `join` of a channel already in the list: nothing but the record;
   - `leave` of a channel in the list: unsubscribe with the device key,
     remove the channel's push registration, its posts and its names;
   - `leave` of a channel not in the list: nothing but the record.

   Then `(op, at_ms)` is recorded. Applying C never sends a membership
   message, so nothing loops. It asks nothing of the user: no notification,
   no alert, no prompt; the channel list simply changes.

*A device that is offline.* C is a distro blob like any other. A device with
no live route has it handed off (§17.3): queued in its deferred bucket. When C
carries an accepted §17.13 proof (every C a sealing device uploads to its
RFed) the device is not woken for it, within the bounds of §17.3: it applies
C when it next collects its backlog with `/distro/pull` (`/rfed/pull` on
`rfed.distro.register`), whatever starts that: the app opening, its
propagation stream opening, or a wake for anything else. A device that
applies C as it pulls and collects its distro and channel backlogs in one
pass collects the distro backlog first, so a leave is applied before a post
in the channel it left is shown or notified. An iOS notification service
extension does not apply C (the app does, when it next runs) and pulls a
channel a push names before the distro, so it can show a post in a channel
left on another device until the app has run. A C with no accepted proof (an
older sender) still wakes the device. A device registered at another RFed
node gets C through FedSync (§17.2), with a wake (§17.13 "Not covered").

*Not covered.* C can be lost before it leaves the sending device, and in
RFed's queue.

On the sending device, C is persisted until proved. It is uploaded when the
propagation link comes up, and after an upload that was not proved it is
uploaded again when the link next comes up (James's decided exception to
DESIGN_PRINCIPLES.md §3, "On the sending device" above). So none of these
loses C: the device is offline, the link is not up yet, the propagation
node's key is not known yet, a tab is taken over or closed, the connection
restarts, or an upload is not proved (its packet is reported lost, or the
link closes or the connection stops first; the failure is said). C goes when
the link next comes up. It is lost in these cases:

- Storage refuses to keep it (in Retichat-js, a full `localStorage`). The
  device then holds C in memory and sends it while it keeps running with the
  propagation link up (in a browser, while the page stays open); a restart
  before that (a reload, a closed tab) loses it. The refusal is logged and
  raised as an error, never silent. The C it replaced is not sent either, now
  or after the restart, because the device takes it out of storage with a
  write no larger than what storage holds. Storage that refuses even that
  write could hand the replaced C to a later page, and the device says so as
  an error (Retichat-js `DistroOutbox._write`).
- The device gives up D, or takes another distro, before C is proved. C is
  dropped then, with a log line. It is not sent under the other distro, nor
  under D if D comes back. An upload that had already left is not taken back
  and may still be proved. A §17.11 sent copy is not lost this way: it stays
  owed to D (§17.11).
- The device's storage is cleared (site data cleared, app removed) before C
  is proved, or the device never brings its propagation link up again.

In RFed's queue there are three ways (§7 "Limits"):

- The queue keeps an entry for 7 days.
- A device's bucket holds at most its per-subscriber limit (256 by default),
  shared with its channel posts, and the oldest entry is evicted first.
- The whole queue holds at most 4096 entries. When it is full, a new entry,
  C included, is dropped, and the hand-off logs a WARNING naming the device
  and D (`EnqueueOutcome::RefusedGlobalLimit`, `handoff.rs`).

When C is lost on the sending device, no sibling learns the change. A device
that is offline for longer than 7 days, whose bucket overflows, or whose C met
a full queue does not learn it either. A device that is reachable but is
neither opened nor woken for anything for 7 days loses, in the same way, a C
that did not wake it (§17.13); the node logs that expiry per device. Neither
does a device that imports D
after the change. Such a device keeps its own list until the next change of
that channel; there the user joins by name, as before. No catch-up exchange
is defined.

*Older clients.* C has empty content, a ticket and no attachment. Most clients
that predate this section take it for a delivery notification and drop it
without showing anything, but not every one. Some web builds older than
2026-09-30 show it:

- Retichat-js from adee619 (2026-09-30) through 24d83e6 drops it.
  `_handleDistroBlob` finds no sent-copy marker, `LXMF.isDeliveryNotification`
  is true (0x0C is present and not nil), and an empty bin is no ticket of the
  web's (`LXMF.webTicket`). So C is dropped with a console line, and a push of
  it is answered `false`.
- Retichat-js before adee619 **shows** it, as an empty incoming message from
  D. From 8ea775c (2026-08-16) the reason is that `_ticketFromFields` reads an
  empty bin as the empty string, which the test `ticket && !content` takes
  for no ticket. Before 8ea775c (for example 132ece1, 2026-08-01) there is no
  ticket test at all. Such a build still pulls from a current node. It lives
  on in a tab not reloaded since 2026-09-30, or wherever an older `app.js` is
  still served, and shows one such message per membership change until it is
  updated.
- Retichat-android from 076f310 (2026-09-23, its first build with a distro)
  through 47bdb0a drops it: `RfedDistroClient.handleBlob` returns on the
  unwrap's `is_delivery_notification`. Earlier builds hold no distro and
  never receive C.
- Retichat-ios from 24c64a4 (2026-08-16, its first distro client) through
  07f6d70 drops it: `RfedDistroClient.unwrapAndDeliver` makes it
  `.notification`. The NSE, which pulls distro messages from a6ac519
  (2026-09-26), drops it too: `NSEDistroPull.unwrapToShow` returns nil.

Without the ticket, or with any content, each build that drops C would store
it instead, as a message from the user's own distro address, and iOS and
Android would notify. Checked on 2026-10-03 by running the shipped
`lxmf_rust::distro::unwrap_blob` on C's bytes, and on the same bytes without
`0x0C` or with content. The web was checked the same way, with each build's
own decoder and the ticket test read from that build's `_handleDistroBlob`
(132ece1, 8ea775c, the commit before adee619, adee619 and 24d83e6).
`unwrap_blob` keeps reporting `is_delivery_notification` for C after this
section, so an app built against a newer LXMF-rust that does not read the
marker still drops it. An updated client reads the marker before its
delivery-notification test. An older device follows none of its siblings'
changes and sends none.

*Privacy.* `fields[0xFD]` reveals which device acted, to holders of D only,
as in §17.11. A private channel's name, its invite, sits encrypted to D in
RFed's BlobStore and deferred queues, as every distro blob does.

#### Implementation index

Where each part lives or is to be made, by function (not line).

| Part | Where | Status (2026-10-04) |
|---|---|---|
| Namespace guard (§6) | RFed-rust `rfed/src/destinations.rs`: `subscribe` (behind `subscribe_cb`), `plan_sync_dispatch` / `run_sync_dispatch` (sync ingest), `plan_channel_fanout` (a publish), `backup_push_response`, `backup_delivery_tick` | made 2026-10-03, not pushed or deployed: 454dc59 (subscribe, sync ingest), 7b19a94 (backup tick, BACKUP_PUSH), 49001ad (publish, the distro's own key); takes effect with an rfed redeploy. The sync reads of §6 "Not covered" stay open for James |
| Web: posting as D, own posts, dedupe, membership sync | Retichat-js, below | made 2026-10-03 and 2026-10-04 on branch `distro-channels-web` (main untouched at 24d83e6), not merged, pushed or deployed. Twelve commits, the last 90640bf, the branch's final commit: 69ff01e (the section); 9f058e9 (review of 69ff01e: a post's record keeps its packed timestamp, a named device never learns a sibling's clear, a dropped C is judged again, the distro's uploads said sent only on the node's proof); 73a725d (C and the §17.11 sent copy kept until proved, "On the sending device"; a cut upload decided; DISPLAY_NAMES §4.2 learned at the post's time); a448e98 (a flush checks each owed entry again before and after its build; a write storage refuses); 3411e19 (the second upload cited as James's §3 exception; what is owed to a distro given up dropped then, said; a refused write cuts storage down to what is still owed; `at_ms` bounded at 2^53 − 1; an upload whose C is owed no more not said to fail); 145ca2f (a replaced propagation link decides nothing, and an upload that has left blocks a second one on any link; an earlier flush never uploads again what a newer one saw lost; the drop line says when an upload already left); 74fbbcd (James's rulings of 2026-10-03, DESIGN_PRINCIPLES §3: a failed upload waits for the propagation link's next coming-up even while a flush runs; a replaced link's close, or the loss of its upload, with a newer link up sends the entry once on that link; giving up a distro drops only the membership messages owed to it, and a sent copy keeps its distro's key and still goes to that distro); 367b266 (review of 74fbbcd: tests for an upload that an earlier flush made, reported lost while a later flush on the same link builds, and an exact pin of the flush's two callers); 9d45faa (review of 367b266: a failure record belongs to one message, its id and its packed bytes, and is made only while that message is the one owed, so a decision about an older action on a channel never replaces or clears the newer action's record; the verifier's probe VR4-OW); 2683ea4 (review of 9d45faa: the pin of the flush's callers reaches through `_onPropagationLinkEstablished` and the two link events); b6c7f7f (verifier of 2683ea4: the pin of `_uploadOwed`'s three callers, and of their callers up to a DM's dispatch and the user's join and leave; comments credit the loss report in the third ruling to James, 2026-10-04; `app.js` and `lib/` differ from 2683ea4 only in comments); 90640bf (verifier of b6c7f7f: the pin reaches up to where each path to the upload begins, `_uploadForDistro` and the readers of what is owed are pinned, and so is every close, loss report and event the page and `lib/` make, however written; `app.js` and `lib/` differ from 2683ea4 only in comments). No departure is known at 90640bf. It passes the distro unit suites (`distro_outbox`, `distro_channels`, `distro_upload`, `distro_sent_sync`, `lxmf_signature`, `distro_channels_page`: 176 tests, 175 pass and the boot test skipped without `RETICHAT_BOOT_TESTS`; with it set, the boot test passes too). On the private staging chain on 2026-10-04, `stage_distro_channels` passed at 2683ea4, 154 of 154 checks, twice; that is 90640bf's code, which was not staged again. Its sections 9, 10, 10b and 11 run James's rulings: the second, the third, the second again where two actions on one channel overlap, and the fifth. The stage failed 367b266 in section 10b alone (1 of 154 checks), 145ca2f in sections 9, 10, 10b and 11 (4 checks), and 9f058e9 in 10 checks, the first of them section 0c's reload. The chain does not run the fifth ruling's other half, a distro replaced by another: that rests on unit tests. What each run showed is under "The web on the staging chain" below |
| Shared Rust for the phones | LXMF-rust, below | not started |
| iOS | Retichat-ios at 07f6d70, below | not started |
| Android | Retichat-android at 47bdb0a, below | not started |

**The web on the staging chain** (2026-10-04, 15:21 to 16:01Z). The chain
ran test-harnesses ba10bb7, the staging rfed binary 17641fb39035 (17641fb
to 950d53c changes only this file), the local PHP node (an export of
Reticulum-post 3281ad5 on 127.0.0.1:8080) and the RPi backbone. An old
build E, Retichat-js 24d83e6, ran on 127.0.0.1:8897. Each web export
(2683ea4, 367b266, 145ca2f, 9f058e9 and 24d83e6) matched `git archive` of
its commit byte for byte, apart from the export's own
`.staging-export.json`, whose commit matched. The refs were recorded before the first run
and after the last, and nothing changed between the two. Isolation was
checked before and after:
- no `STAGING_`, `HARNESS_` or `PROBE_` variable was set, and
  `STAGING_ALLOW_PRODUCTION_PHP` was unset;
- the gateway's `node_url` was 127.0.0.1:8080;
- the RPi had no uplinks, and its only peers were rfed, the gateway and
  the iOS simulator, all on the test Mac;
- no chain process held a connection to a non-private address;
- every URL in every run was on 127.0.0.1.

- `stage_distro_channels` at 2683ea4 ran twice (15:21:21 to 15:23:26Z and
  15:23:29 to 15:25:36Z) and passed 154 of 154 checks each time. In each
  run rfed took 26 uploads for D, counted in rfed's log: 9 in sections 0
  to 8, 5 in 9, 4 in 10, 7 in 10b and 1 in 11.
  - Section 0c passed: a join made before the propagation link could be
    up, kept across a reload, went once from the reloaded page. So did 5b,
    a leave whose upload was lost with the exchange, which went once more
    from the reloaded page on its link's "established". So did 5c, a join
    whose upload the node held but never proved, cut by the link's close;
    it went once more on the same page's next link-up, and the second copy
    was dropped as held. The round trip and the no-loop check passed too.
  - Section 9 (the second ruling). The send pass on the link's recovery
    from STALE listed 5 entries. A's own join was lost to the exchange's
    503 at 15:22:43.258Z while that pass built. At 43.652 A logged that the
    join waits for the propagation link's next coming-up. No upload decided
    unproved went again before a coming-up. All 5 went once on the
    re-opened link's "established" (48.869) and reached B.
  - Section 10 (the third ruling). The STALE link that was replaced decided
    nothing. One join was settled by the node's late proof over the old
    link, with one upload. The old link's own close began the other join's
    upload on the new link: at the page's first task after the close, its
    attempt was open there and its build had begun, before any timer the
    page set. The join was uploaded once, 96 ms after the close (104 ms in
    the second run). A's exchange was held from before the close, and
    nothing more reached A before the upload. The stage cannot tell apart a
    wait the page might take once that build has begun. Only
    DESIGN_PRINCIPLES §1's 5 s and the exchange's record bound it.
  - Section 10b (the second ruling, where two actions on one channel
    overlap). A joined a channel, and the join's upload stayed open on a
    link that went STALE and was replaced. A left the channel with the new
    link up. The leave's upload was lost at 15:23:11.246Z while the send
    pass on the new link's recovery built 4 earlier joins. The replaced
    link's own close then decided the join, at 11.250, as owed no more,
    with nothing to go again. When the pass reached the leave (11.624), A
    logged that it waits for the next coming-up. The leave and each earlier
    join went once on the next coming-up, and B joined and left once.
  - Section 11 (the fifth ruling, for a distro forgotten). The join owed to
    D was dropped, and A's log said so. The sent copy stayed owed, went
    once on the next coming-up and was proved, and B showed the message
    once.
- At 367b266 the stage failed 1 of 154 checks: section 10b, as it must.
  The leave was lost at 15:27:32.426Z, and the replaced link's close
  decided the join "owed no more" at 32.429. The same pass uploaded the
  leave again at 32.935, with no coming-up between, and A never said the
  leave waits. That upload was lost too, with the exchange down, so it
  never reached rfed, which took 26 uploads for D. Everything else passed.
- At 145ca2f the stage failed 4 of 154 checks, in sections 9, 10, 10b and
  11:
  - In 9, A's own join was uploaded at 15:29:16.087Z. The "recovered" pass
    began at 16.101, and the 503 lost the join at 16.112. The same pass
    uploaded it again at 16.610, with no coming-up between, and it was lost
    again at 16.615.
  - In 10, the old link's close left the other join owed until the next
    coming-up. It was not uploaded on the close, and rfed took 3 uploads in
    that section, not 4.
  - In 10b, the leave was uploaded again while the pass ran, and rfed took
    8 in that section, not 7.
  - In 11, the sent copy was dropped with D, so nothing was owed and B
    never got the message.

  Everything else passed, 0c, 5b, 5c and the round trip included. rfed took
  25 uploads for D: 9, 5, 3, 8 and 0.
- At 9f058e9 the stage failed 10 checks, and 141 passed. The first failure
  is 0c's reload check. The join, made before the propagation node's
  identity was ready, was given up at once, so the reload lost it and it
  was never uploaded. The others follow from that: 0c's second join, 5b,
  5c, the round trip, and sections 9, 10, 10b (two checks) and 11, which
  found nothing owed. rfed took 10 uploads for D.
- At 2683ea4, `stage_channel_send`, `stage_names` and distro-pipeline
  stages 3 to 6 passed. The harness's offline suite passed at ba10bb7: 389
  tests, 336 pass and 53 skipped without Chromium, and 389 of 389 with
  `RETICHAT_BOOT_TESTS=1`.
- Not staged: the other half of the fifth ruling. No section gives A a
  second distro, so the case of a device that takes another distro and
  still uploads its sent copy to the old one rests on unit tests ("D
  replaced by D2: the sent-copy owed to D still goes to D …" in
  `distro_channels.test.mjs`).

Faults that no stage judges. Their code is the same at 24d83e6, so they
predate the branch. These runs showed all three:

- A DM to a distro address waits the fixed propagation delay (5.0 s in
  stage 3), though it has no direct leg: a timer in place of an event.
- In stage 4, rfed logged a SEND-ASSERT ("link.establish succeeded after
  6.19s") for the Python reference sender's link to rfed's
  `lxmf.propagation`.

- A link request sent as a packet is decided only by its response
  budget, about 14.5 s, and never by the exchange's report that its packet
  was lost. This is a DESIGN_PRINCIPLES §1 gap (`lib/rns/link.js`;
  `link_request_lost.test.mjs` covers only LINKREQUESTs). In the first run
  at 2683ea4, A's `/channel/subscribe` failed at 15:22:57.694Z ("no response
  within 14562 ms"), 14.4 s after the 503 at 15:22:43.257Z reported its
  exchange's 3 packets lost. After the 503 at 15:23:11.246Z (15 packets
  lost), A's `/channel/stream/open`, `/channel/pull` and `/distro/pull`
  requests failed only at 15:23:25.688 to .694Z. The second run showed the
  same at 15:25:05.689Z and 15:25:36.291 to .308Z (14490 ms). An earlier
  staging of the same day (06:10Z, at 367b266) showed it too: in section
  9, the `/distro/pull` sent at a resume was lost with the 503 and failed
  only 14.4 s after the loss was reported.

**LXMF-rust** (shared by both phones).

- `distro.rs`: a constant `DISTRO_CHANNEL_TYPE = "rfed.distro.channel"`.
  `unwrap_blob` reports the marker as `DistroMessage.channel_sync`
  (`op`, `name`, `at_ms`, and `by` from 0xFD), set whenever the type
  matches, with an unusable value reported as absent so the client drops
  and logs it, as `sent_by` does for §17.11. `at_ms` is read with
  `Value::as_u64()` and must be at most 2^53 − 1, so the web's int 64 and
  rmpv's uint 64 both read, and a float, a negative value or a larger value
  is unusable ("`at_ms` on the wire"). It applies
  the D-signature check of §17.11 rule 2 to this type too, over the received
  bytes (`lxmf_signature_valid`, never a re-pack), and it keeps
  `is_delivery_notification` true for C. It also reports C's LXMF message
  hash (SHA-256 of dest, src and the signed payload), the repeat key of
  "Receiving". `DistroMessage::to_json` carries it as `"channel_sync"` (an
  object, or null), so `retichat_distro_unwrap` (iOS) and
  `nativeDistroUnwrap` (Android) pass it on unchanged.
- One writer for C's fields, `distro::channel_sync_fields(op, name, at_ms,
  device_hex)`, and a message setter for the bridges (C
  `lxmf_message_set_distro_channel_sync`, JNI
  `nativeMessageSetDistroChannelSync`): the generic setters
  (`message_add_field_string` / `_bool`) write only str and bool, and 0xFC
  is an array. It writes `at_ms` as `Value::from(u64)`, which rmpv packs as
  uint 64 (`0xcf`), and refuses a value above 2^53 − 1.
- `name_ledger::is_own_devices_message`: `DISTRO_CHANNEL_TYPE` too
  (DISPLAY_NAMES.md §4.1).
- `channel::pack`: unchanged; it signs with the identity it is given.
- Tests: C's shape unwraps as a delivery notification with the marker set
  (mutation: drop 0x0C and the notification flag goes); a C claiming D
  without D's signature is rejected; a marker from another source is
  reported for rule 1. A C made by Retichat-js (`channelSyncFields` and
  `LXMessage.pack`, `at_ms` as int 64) unwraps with the marker set, `at_ms`
  its value and the signature valid (mutations: reading `at_ms` only from a
  uint marker, or checking the signature over a re-pack, each drops the
  web's C). A uint 64 `at_ms` reads the same; a float 64 holding an integral
  value, a negative int 64, and 2^53 as uint 64 or int 64 are reported
  unusable, and 2^53 − 1 reads (mutation: `as_u64()` without the bound
  reads 2^53).

**Retichat-ios.**

- Posting: `RfedChannelClient.trySend` packs with the handle from
  `DistroManager.shared.sendingIdentity(deviceHash:deviceHandle:)`, not
  `identityHandle`; the optimistic post's `senderHash` (`sendMessageAsync`)
  and `canonicalId` in `trySend` take the posting hash, not `ownHashHex`.
  `identityHandle` (set by `RetichatApp`'s `channelClient.configure`) stays
  for `subscribeOnServer`, `leaveChannel`'s unsubscribe,
  `buildChannelStreamPayload`, `pullDeferred` and the channel registrations
  of `RfedNotifyRegistrar`.
- Own posts: `RfedChannelClient.dispatchVerifiedLxmf` sets `isOutgoing`
  when the sender is `ownHashHex` or `DistroManager.shared.deliveryHashHex`,
  and then calls no `noteSender` and posts no notification. It stores the post
  with `deliveryState` sent (`verifiedChannelMessageDeliveryState` already
  gives that for an outgoing post). It feeds the post's name to the §4.2 state
  only when the name equals the device's own (DISPLAY_NAMES.md §4.2). The
  NSE: `NSEChannelPull.run` drops the distro's hash from what it shows,
  beside `ownHash`.
- Name state: `channelPostName(for:)` and `recordPostName` keyed by channel
  and posting identity (`ChannelEntity.nameLastDigestHex` /
  `nameLastIncludedAt`, reset when the posting identity changes).
- Sending C: the user's join and leave (`joinChannel(name:
  rfedNodeIdentityHashHex:)`, `leaveChannel(channelHashHex:)` as the UI
  calls them) call a new `ChatRepository.sendDistroChannelSync`, which packs
  and signs C with D (as `sendDistroSentCopy` builds its copy) and puts it in
  the distro outbox ("The phones' outbox" below) instead of handing it to the
  router. `sendDistroSentCopy` moves onto the outbox too: today it submits
  the §17.11 copy once and keeps nothing ("Fire-and-forget" in its comment).
- Receiving C: a `channelSync` case of `RfedDistroClient`'s `Inbound`,
  chosen in `unwrapAndDeliver` before `.notification`, a repeat only by its
  LXMF message hash ("Receiving"); rules 1-5 in a pure
  `DistroCodec.channelSyncDisposition` beside `sentCopyDisposition`; rule 6
  in `RfedChannelClient`: a join stores the `ChannelEntity` and subscribes
  through `resubscribePersistedChannels` (today `joinChannel` subscribes
  before it stores), a leave runs `leaveChannel`'s clean-up without sending
  C. The per-channel `(op, at_ms)` record is new storage, kept after a
  leave.

**Retichat-android.**

- Posting: `RfedChannelClient.sendMessage` and `trySend` pack with
  `DistroManager.sendingIdentity(selfDestHash, identityHandle)`; the
  optimistic post's `sourceHashHex` and `canonicalMessageId` take the
  posting hash, not `StackRuntime.selfDestHash`. `StackRuntime.identityHandle`
  stays for `subscribeOnServer`, `leaveChannel`'s unsubscribe,
  `sendChannelStreamConfig`, `pullDeferred` and
  `RfedNotifyRegistrar.registerForChannel` / `deregisterForChannel`.
- Own posts: `RfedChannelClient.dispatchBlob` sets `isOutbound` for
  `DistroManager.deliveryHashHex` too, and then records no
  `recordChannelSender` and posts no notification. The row keeps `sendState`
  `SEND_STATE_SENT`, the entity's default. It feeds the post's name to the
  §4.2 state only when the name equals the device's own (DISPLAY_NAMES.md
  §4.2).
- Name state: `channelPostName` and `recordPostName` keyed by channel and
  posting identity (`ChannelNameStateEntity`, which needs a Room migration,
  or is cleared when the posting identity changes).
- Sending C: the user's join (`JoinChannelScreen` → `joinChannel`) and leave
  (`ChatListViewModel`, `ConversationScreen` → `leaveChannel`) call a new
  `ChatRepository.sendDistroChannelSync`, which packs and signs C with D (as
  `sendDistroSentCopy` builds its copy) and puts it in the distro outbox
  ("The phones' outbox" below) instead of handing it to the router.
  `sendDistroSentCopy` moves onto the outbox too: today it submits the §17.11
  copy once, logs its outcome, and keeps nothing.
- Receiving C: `RfedDistroClient.handleBlob` reads `channel_sync` before
  `if (isNotification) return`, a repeat only by its LXMF message hash
  ("Receiving"); rules 1-5 in a pure
  `DistroCodec.classifyChannelSync` beside `classifySentCopy`; rule 6 in
  `RfedChannelClient`: a join stores the `ChannelEntity` and subscribes
  through `resubscribePersistedChannels` (today `joinChannel` subscribes
  before it stores), a leave runs `leaveChannel`'s clean-up without sending
  C. The per-channel `(op, at_ms)` record is a new table, kept after a
  leave.

**The LXMF-rust router and C** (both phones). As built at 3e617aa,
`lxm_router.rs` sends a PROPAGATED message a second time when the node does
not prove it. When the packet's receipt times out or its Resource fails,
`propagation_packet_timed_out_shared` puts the message back to OUTBOUND and
the held propagation link is torn down, as the Python reference's
`LXMessage.__link_packet_timed_out` does. The router sends it again once the
link is open again. It opens that link for the message at most
`MAX_DELIVERY_ATTEMPTS` (2) times, paced by `DELIVERY_RETRY_WAIT` (2 s) and
`PATH_REQUEST_WAIT` (7 s), and then fails the message. The tear-down on the
receipt's timeout is what James ruled for the phones ("The phones' outbox"
below). The re-send is not the second upload James allowed ("On the sending
device"): it is paced by a timer, not by the propagation link's next coming
up, and it gives up after a count while C is still owed. Whether the
router's queue outlives a restart is not checked here either. So neither C
nor the §17.11 copy goes through the router's queue as it is: each is
uploaded from the phones' outbox below. If an upload goes through the
router, the router must not re-send it on its own.

**The phones' outbox** (both phones; the follow-up for the phone lanes).
Retichat-js 90640bf is the model (`lib/distro_outbox.js`, `DistroOutbox`
and `UnprovedUploads`; `_oweDistro`, `_sendDistroOutbox`,
`_unprovedSince`, `_distroAttemptOpen`, `_uploadOwed`, `_stillOwed` and
`_dropMembershipOwedToOtherDistros` in `app.js`), and the list below is the
contract. The phones must not copy the gaps that earlier web commits had
("Retichat-js departures" below):
- a flush that checks an entry only for being owed and not in flight, and so
  uploads again at once an upload decided unproved while it builds
  (145ca2f and before);
- a replaced link's close that leaves the entry waiting while a newer link
  is up (145ca2f);
- sent copies dropped with D (3411e19, 145ca2f);
- a failure record kept per channel and written whatever is owed, so that a
  decision about an older action on the channel takes the newer action's
  record, and a flush under way uploads the newer one again at once on its
  own failure (367b266).

"Tests every client makes for the sending device" below is the check.

- One persisted store of what the device owes D: new storage on iOS, a new
  Room table on Android. It holds C and the §17.11 sent copy. An entry keeps
  the LXMF message as D packed and signed it when the user acted (never
  packed again, so every upload is the same message), the distro it is owed
  to, that distro's public key (so that a sent copy can still be encrypted
  to it after the device gives it up), and what the log lines call it.
- A C's id is its channel hash. A later join or leave of that channel
  replaces it, and the replaced C never goes, even if its upload is being
  built. A sent copy's id is its LXMF message hash, and nothing replaces it.
- The entry is stored before anything can yield. It is uploaded at once if
  the propagation link is up, and otherwise when the link next comes up. It
  never starts the link.
- The link comes up when a new propagation link is established, or when a
  STALE propagation link recovers because the node is heard from on it
  again (James, 2026-10-03: both count). Each coming-up starts one flush of
  what is owed, and nothing else starts one: not a resume of the app, not a
  timer, not a failure. A STALE link that a new one has replaced is no
  longer the propagation link, and its recovery starts no flush. That is
  this section's reading of the first and third rulings, not James's words
  ("On the sending device"). One exception: an interface coming back online
  starts a flush of the uploads that never left the device (below).
- An upload that never left the device, because no interface could carry it
  (its packet could not be queued), is not a failure: nothing was sent. It
  goes when an interface comes back online, an event like the coming-up, as
  well as at the next coming-up. A loss after the packet left still waits
  for the next coming-up (James, 2026-10-06: on staging a short network drop
  left the propagation link up, so no coming-up followed, and such an upload
  waited 35 s for an unrelated close).
- The node's proof settles the entry, a proof after a loss report included.
  The loss report, the link's close and the app's stop each decide an upload
  unproved. The device says so, the entry stays owed, and it is uploaded
  again on the link's next coming-up. It is never sent again at the failure
  itself, never on a timer, and never by a flush that was already under way,
  even when that flush is running on the link that is up (James,
  2026-10-03). A build that throws before anything leaves is a failure too,
  said and recorded the same way (this section's rule, "On the sending
  device"). A build abandoned because the link went down is none: nothing
  is decided, and the entry goes when the link is next up.
- A STALE link replaced by a new one decides nothing (James, 2026-10-03).
  While its upload is open, no flush uploads that entry on any link, and a
  proof over the old link settles it: one upload, one stamp, one fan-out.
  If the old link's own close then decides it unproved while a newer
  propagation link is already up (ACTIVE), that close is the event: the
  entry goes once on the newer link at once. The loss of that upload (the
  web's loss report, the phones' receipt timeout) counts the same as that
  close (James, 2026-10-04). With no newer link up, it waits for the next
  coming-up. A failure of that upload waits for the next coming-up like any
  other. The app's stop sends nothing. If the loss of the old link's upload
  was the event and the node then proves that upload late, the proof
  settles the entry: it is owed no more and does not go again, and a
  sibling that gets it twice holds the second as a repeat (this section's
  rule).
- A flush uploads an entry only if the entry's last failure was decided
  before the coming-up that started the flush, whoever made the upload
  that failed. Knowing who is in flight is not enough, because once an
  upload is decided it is in flight no more. An upload made by the user's
  action, by an earlier flush, or on a link since replaced, if decided
  while a flush builds an earlier entry, would be found owed and uploaded
  by that flush at once. The web keeps the rule this way (74fbbcd,
  367b266, 9d45faa):
  - count the comings-up, and let each flush take the next count;
  - when an upload of a message, or its build, is decided unproved, record
    the count current at that moment, in the task of the event that
    decides it. The record is that exact message's, keyed by the entry's id
    and the message as packed (its bytes or its LXMF message hash), never
    by the id alone. It is made only while that message is the one owed
    under its id;
  - let a flush taken at count n upload a message only if that message has
    no record or a record below n, checked when its turn comes and again
    once its upload is built. The flush reads that message's own record
    and no other.

  The record must be the count current when the upload is decided, not the
  count of the flush that made it. Otherwise a later flush on the same link,
  building when an earlier flush's upload is reported lost, uploads it again
  at once (found in review of Retichat-js 74fbbcd).

  The record must also belong to the exact message, because a membership
  message's id is its channel and two actions on one channel can both have
  an upload undecided. A decision about the older message never writes,
  replaces or clears the newer message's record. That covers its proof or
  late proof, its loss report, its link's close and its build throwing. A
  message owed no more keeps no record: its record goes when it is proved,
  replaced by a later action or dropped with D, and only its own. Retichat-js
  367b266 kept one record per channel and wrote it whatever was owed. A join
  whose upload was open on a replaced link was decided by that link's close
  after the leave that replaced it was reported lost, and its record took
  the leave's. The flush under way then uploaded the leave again at once,
  on its own failure (the verifier's probe VR4-OW; on the chain, section
  10b at 367b266). The record need not outlive the process. After a
  restart, the first coming-up is after every failure decided before it.
- Each entry a flush listed is checked again before its upload is built and
  before it leaves: still owed, still the same message, and, for a
  membership message, still owed to the distro the device holds. A build
  yields, so another upload may have been proved meanwhile, a later action
  may have replaced the entry, or D may have been given up.
- Giving up D (forget, or taking another distro by generate or import)
  drops every membership message owed to D, with a log line. Start-up does
  the same for any membership message owed to a distro the device does not
  hold. An upload that has already left is not taken back, and the line
  says so. A sent copy is not dropped (James, 2026-10-03). It stays owed to
  the distro it was made for and is uploaded to that distro on later
  comings-up: the same packed message, encrypted with the key kept in the
  entry. It is never addressed to the distro held now, never sent under it
  and never packed again. Retichat-js 3411e19 and 145ca2f dropped sent
  copies too.
- Storage that refuses a write: the device keeps the entry in memory for
  this run, and takes the entry it replaced out of storage with a write no
  larger than what storage holds. The refusal is logged and raised as an
  error.

*Which phone event is "the packet reported lost"* (James, 2026-10-03;
DESIGN_PRINCIPLES §3). On the phones it is the RNS packet receipt's
timeout, as in Python LXMF. In the reference,
`LXMessage.__link_packet_timed_out` (LXMF-master/LXMF/LXMessage.py) tears
the propagation link down when the receipt of an upload's link packet
times out. The phones do the same, and do not copy the reference's re-send
(it sets the message back to OUTBOUND for the router to send again):
1. The receipt's timeout tears the propagation link down.
2. That close decides the upload unproved. The entry stays owed, and the
   device says so.
3. Nothing sends it again before the next establishment of the propagation
   link, which carries it once.

A proof that comes after the receipt has timed out is logged as a
DESIGN_PRINCIPLES §1 violation (a late success), and it settles the entry
all the same: it is owed no more and does not go again. The web's event is
the exchange's loss report (`_onPacketsLost`).

**Retichat-js** (as made, branch `distro-channels-web` at 90640bf, whose
code is 2683ea4's).

- Posting: `RnsClient.sendChannelMessage` decides the posting identity once,
  `sendingIdentity()` (D when held, else the device), and packs with it
  (`channelLxmPack`). The record's `srcHash`, the echo key and the §4.2 name
  state take that identity's `lxmf.delivery` hash, and the record's
  `timestamp` is the one the post is packed with, moved to the next free
  millisecond when `ChannelMsgStore.held` already holds that
  `(srcHash, timestamp)`. `_subscribeChannel`, `_unsubscribeChannel`, the
  stream and the link's identify stay with `IdMgr.id`, the device.
- Own posts and dedupe: `_handleChannelPacket` takes a post as the user's own
  when its source is `ownLxmfDestinationHash()` or
  `DistroManager.lxmfDeliveryHash`, and stores it `dir: "out"`,
  `status: "sent"`, with no `ContactStore.keep`, no
  `ChannelPostNamesStore.noteSender` and no notification.
  `ChannelMsgStore.add` drops a post whose `(srcHash, timestamp)` it already
  holds (`ChannelMsgStore.held`), so rfed's echo is dropped after a reload too.
- Name state: `ChannelPostNames` (`lib/name_ledger.js`), per channel and
  posting identity. `learn` records only the value this device would send
  itself, at the post's time (DISPLAY_NAMES.md §4.2). 9f058e9 clamped that
  time to this device's clock; 73a725d follows the spec text.
- Sending C: `joinChannel` and `leaveChannel`, the user's actions, call
  `_syncChannelMembership`. It stamps and records the action
  (`ChannelMembership.stampLocal` in `lib/channel_sync.js`, stored under
  `channel_membership_v1`), with or without a distro. With a distro it calls
  `_sendDistroChannelSync`, which builds the fields with `channelSyncFields`
  (`at_ms` as int 64) and packs and signs C with D once. `_oweDistro` then
  writes C to `DistroOutbox` (`lib/distro_outbox.js`, one entry per channel,
  id `channel:<channel hash>`, which also holds the §17.11 sent copies). Each
  entry carries its distro's public key (`distroKey`).
- Uploading: `_uploadOwed` uploads C at once when the propagation link is
  ACTIVE. `_sendDistroOutbox` uploads what is owed when the link comes up.
  It runs from the current link's `"recovered"` listener, and from the
  `"established"` listener through `_onPropagationLinkEstablished` (the
  work that runs once a link is established), and from nothing else. A
  `"recovered"` of a link that is no longer current runs no flush (this
  section's reading of the first and third rulings). The pin in
  `distro_sent_sync.test.mjs` fails if anything else in the page names
  either method, if either call leaves its listener, or if `app.js` or a
  script under `lib/` other than `lib/rns/link.js` fires `"established"`
  or `"recovered"`. 2683ea4 extended the pin to the `"established"` work
  and the two events: in review of 9d45faa, an announce that ran that work
  again while the link was up passed every earlier test. Each call is one
  coming-up, counted in `_propComingUps`, and the flush takes the new
  count. `_stillOwed` checks each entry again before and after its build,
  and for a membership message checks that it is owed to the distro held.
  `_uploadForDistro` and `DistroUploads` (`lib/distro_upload.js`) decide
  the upload: by the node's proof, by the exchange's loss report
  (`_onPacketsLost`), by `cut()` on a disconnect or the link's close, or,
  for a Resource, by its failure. `_uploadOwed`, the per-entry upload,
  reads no failure record when it is called without a coming-up, so it has
  three callers and no other: the coming-up pass, the user's own action
  (`_oweDistro`, with a message packed in that action) and the third
  ruling's send. b6c7f7f pinned them in `distro_sent_sync.test.mjs`, with
  `_oweDistro`'s two callers, every call of `DistroUploads.lost` and
  `cut`, the loss report's one listener, the page's closes (it closes a
  propagation link only in `disconnect()`, once it has let go of it), and
  the events that only the Link and the exchange fire. In the verifier of
  2683ea4's probe RX1, an announce that uploaded every owed entry through
  `_uploadOwed` passed every earlier test. That pin stopped at a DM's
  dispatch and the user's join and leave, and left `_uploadForDistro`
  open: in the verifier of b6c7f7f's probes, the window's `"online"`
  dispatching every failed DM again, or leaving and joining every channel
  again, or re-uploading every owed entry through a bound alias of
  `_uploadForDistro`, passed the whole suite. 90640bf pins what reaches
  each path up to where it begins: the user's own send (the composer's
  send button and Enter key, and the test harness's send), join (the
  channel form's Join button and Enter key, and the harness's
  `joinChannel`) and leave (the channel's Leave button, once confirmed,
  and the harness's `leaveChannel`), and a DM the user sent before the
  exchange first registered after a connect (`_dispatchQueued`). It pins
  `_uploadForDistro` to its one caller, `_uploadOwed`; the outbox, its
  attempts in flight and its failure records to the places that read
  them; and every place the page and `lib/` say close or lost (and `lib/`
  a link's coming-up or recovery), with the page firing one event of its
  own. So a new path is caught however it is written: by name, through an
  alias, as an optional or a computed call. What it cannot see is a name
  assembled at run time or found by reflection.
- A failure waits for the next coming-up. `DistroUploads` calls the upload's
  `onLost` in the task of the event that decides it. `_uploadOwed` then
  records the failure in `_distroUnproved`, an `UnprovedUploads`
  (`lib/distro_outbox.js`, 9d45faa), with the `_propComingUps` count
  current then. A build that throws is recorded the same way. The record
  is one message's, keyed by the entry's id and its packed bytes, and it is
  made only while that message is the one owed under its id
  (`DistroOutboxStore.get(entry.id)?.packed === entry.packed`). Recording,
  reading or forgetting one message's record never touches another's, the
  same channel's included. A flush skips a message whose own record is at
  its count or later (`_unprovedSince`), and checks again once the stamp is
  mined. So no flush already under way sends a failed upload again,
  whoever made it, and an older action's decision cannot take a newer
  action's record. 145ca2f's `_distroFlush`, which stopped an earlier flush
  once a newer one began, is gone, because this rule covers that case. Only
  a proof settles the entry (`DistroOutbox.settle`, a late proof through
  `upload.onLateProof` included). A message's record goes, and only its
  own, when it is proved (late too), when the user's action replaces it
  (`_oweDistro`) and when it is dropped with D. The record lives in the
  page's memory: a reload starts with none, and the reloaded page's first
  coming-up sends what is owed.
- A replaced link: `_establishPropagationLink` replaces a STALE link
  without deciding its uploads. When the old link's close (James,
  2026-10-03), or the loss report (James, 2026-10-04), decides one while a
  newer propagation link is up and current, `_uploadOwed` uploads the entry
  once on that link at once. A Resource's failure is taken the same way
  (James, 2026-10-04). A late proof of the first upload,
  coming after that, settles the entry (`upload.onLateProof`). `disconnect()` lets go of the newer link first,
  so a stopped connection sends nothing. The in-flight check
  (`_distroAttemptOpen`, over `_distroOutboxInFlight`) skips an entry being
  built for the same link, and one whose upload has left and is not
  decided, on any link. The comments of `lib/distro_outbox.js`,
  `lib/distro_upload.js`, `_oweDistro`, `_sendDistroOutbox` and
  `_uploadOwed` cite James's §3 exception and rulings.
- Reporting: `_distroOwedOutcome` says a failure, as a warning and a
  Harness error, only while the entry is still owed.
- A distro given up: `_dropMembershipOwedToOtherDistros`
  (`DistroOutbox.dropMembershipNotFor`) drops the membership messages owed
  to a distro not held, with a warning for each, and keeps the sent copies.
  It runs on every `DistroManager.onChange` (forget, generate, import), once
  at load, and before each flush. `_uploadOwed` encrypts every upload with
  the entry's `distroKey`, so a sent copy goes to its own distro whatever
  this device holds. An entry stored without the key (145ca2f and earlier,
  never released) is encrypted only to the distro held, when that is its
  own. Otherwise the device says so, and the entry stays owed.
- Storage: `DistroOutbox._write` reads every write back. After a refusal
  the page holds the outbox, and storage is cut down to what is still
  owed. `RetichatTest.distroOwed()` lists the outbox for staging.
- Receiving C: `_handleDistroBlob` reads the marker with
  `LXMF.distroChannelSyncFromPayload` (`lib/channel_sync.js`
  `readChannelSync`, from the payload's bytes, so a float `at_ms` is refused
  as rmpv refuses it, and one that is not `Number.isSafeInteger` is refused
  by rule 4), after the §17.11 copy and before
  `LXMF.isDeliveryNotification`. Its repeat key (`DistroSeen`) adds the LXMF
  message hash to the source and timestamp. Rules 1 and 2 use the
  `signedByDistro` check shared with §17.11, over the received bytes
  (`LXMessage.signedPayload`). `_handleDistroChannelSync` runs rules 1-5 in
  `channelSyncDisposition` (`joinNameAccepted` for a join's name in rule 4,
  `supersedes` for rule 5), and `_applyDistroChannelSync` runs rule 6. A join
  goes through `ChannelStore.join` and is subscribed by
  `_ensureChannelSubscribed` once `_initChannels` has re-subscribed the
  stored channels, or by that re-subscription. A leave goes through
  `_leaveChannelHere(ch, true)`: unsubscribe, the channel's posts,
  `ChannelSenderNamesStore.forget`, `ChannelPostNamesStore.forget` and the
  stream memo. No C is sent.

**Retichat-js departures.** None is known at 90640bf. 367b266 had one,
against James's second ruling, and 9d45faa fixed it with tests that fail
without the fix. It was shown by running 367b266's own code, and on the
staging chain:

- *A decision about an older action took the newer action's failure record*
  (367b266; the verifier of 367b266, probe VR4-OW, 2026-10-04; James's second
  ruling). `_distroUnproved` kept one record per entry id, which for a
  membership message is its channel, and `_uploadOwed` wrote it whatever was
  owed. The user joins CH, and the join's upload is left open, unproved, on a
  STALE link that a newer link replaces. The user leaves CH: the leave goes
  at once on the newer link. A coming-up's flush lists the leave behind an
  earlier entry and builds that entry. The leave's upload is reported lost,
  and its record is written. Then the old link's close decides the join (or
  the exchange reports the join's packet lost, or the join's build throws),
  and the join's record replaces the leave's. The flush finds no record of
  the leave and uploads it again at once, on its own failure, after the log
  has said it waits for the next coming-up. The probe was appended to a copy
  of `distro_channels.test.mjs` in a `git archive` of 367b266, with the
  shipped link handlers. The variant where the join is decided after the
  leave's loss failed; the variants where it is decided before, or never,
  passed. On the staging chain (2026-10-04, 15:27Z) 367b266 failed section
  10b and nothing else: the leave was lost at 32.426, the join was decided
  owed no more at 32.429, and the same pass uploaded the leave again at
  32.935, with no coming-up between ("The web on the staging chain" above). It cost one
  more upload, one more stamp and, had both reached the node, one more
  fan-out, which the siblings would hold as a repeat. Only membership
  messages were exposed: a sent copy is owed under its own id. Fixed in
  9d45faa (`UnprovedUploads`: one record per message, made only while that
  message is owed, forgotten when it is owed no more, and only its own).

145ca2f had three, each against a ruling James made on 2026-10-03
(DESIGN_PRINCIPLES §3, what a device owes its distro). 74fbbcd fixed all
three, each with tests that fail without the fix, and 367b266 added tests
for a case that 74fbbcd's tests missed. Each departure below was shown by
running 145ca2f's own code:

- *A flush already under way uploaded again an upload decided unproved
  while it built* (145ca2f; found by the review of this section's earlier
  text and by the verifier's probes, 2026-10-03; James's second ruling).
  `_sendDistroOutbox` checked each entry it listed for three things only:
  it was still owed (`_stillOwed`), it was not in flight
  (`_distroOutboxInFlight`), and no newer flush had begun (`_distroFlush`).
  The loss report or the close removed the in-flight record when it decided
  the upload. So an upload that the flush did not make, decided while the
  flush built an earlier entry (a stamp yields), was found owed and
  uploaded by that flush at once, with no link event after the failure. Two
  cases, each run against 145ca2f's own methods in the harness of its
  `distro_channels.test.mjs`:
  - Y is owed after a loss. The user joins CH with the link up, so CH's C
    goes at once. The link goes STALE and recovers, and the `"recovered"`
    flush lists Y and CH and builds Y. CH's packet is reported lost. The
    flush then uploads Y and CH.
  - Y is owed, and CH's C is uploaded on link 1. Link 1 goes STALE and is
    replaced by link 2, whose `"established"` flush lists Y and CH and
    builds Y. Link 1's close decides CH's upload. Link 2 then carries Y and
    CH, right after the close.

  In each case C goes a second time on its own failure: a second stamp is
  mined, and if both uploads reach the node, it fans C out twice. On the
  staging chain (2026-10-04, 15:29Z) 145ca2f sent the second upload: the
  "recovered" pass uploaded A's own join again 498 ms after its loss, with
  no coming-up between ("The web on the staging chain" above). Its section
  10b failed the same way, with the leave uploaded again while the pass
  ran. Fixed in 74fbbcd (`_propComingUps`, `_distroUnproved`,
  `_unprovedSince`; `_distroFlush` removed, as the rule covers its case).
  The review of 74fbbcd found that recording a failure at the coming-up of
  the flush that made the upload, instead of the coming-up current when the
  failure is decided, passed every test. Under that change, a later flush
  on the same link uploads again at once an upload that an earlier flush
  made. 367b266 adds the four tests that catch it, for a join and for a
  sent copy, with the earlier flush an `"established"` and a
  `"recovered"`.
- *A replaced link's close, with a newer link up, left the entry waiting*
  (145ca2f; James's third ruling). The upload was open on a STALE link
  that a newer link had replaced, and the old link's own close decided it
  unproved. 145ca2f kept the entry for the next coming-up, though the newer
  link was up. James ruled that the close is the event, and the entry goes
  once on the newer link at once. On the chain, the entry was not uploaded
  on the close, and rfed took 3 uploads in that section, not 4. Fixed in
  74fbbcd (`_uploadOwed`).
- *Sent copies were dropped with D* (3411e19 and 145ca2f, through
  `_dropOwedToOtherDistros` and `DistroOutbox.dropAllBut`; James's fifth
  ruling). Giving up D dropped every entry owed to D, the sent copies
  included, so the other devices never showed those sent messages. On the
  chain, the sent copy owed when A forgot D was dropped, and B never got
  the message. Fixed in 74fbbcd (`_dropMembershipOwedToOtherDistros`,
  `DistroOutbox.dropMembershipNotFor`, and the entry's `distroKey`).

Review on 2026-10-03 found these in a448e98 and in 3411e19, each shown by
running that commit's own code, and each is fixed with a test that fails
without the fix:

- *A replaced C could reach a later page* (a448e98). After storage refused a
  put, `DistroOutbox.put` wrote the entries the page held, less the replaced
  one. That write could be larger than what storage held, so a full storage
  refused it too and kept the replaced C for the next page. Case: owe a join
  (kept), storage fills, owe a §17.11 sent copy (refused), owe a leave of the
  same channel (refused). Fixed in 3411e19: `DistroOutbox._write` cuts what
  storage holds down to what is still owed.
- *A C owed when D was given up was kept, without a log line, and went if D
  came back* (a448e98). Case: join with the link down, give up D, leave the
  channel, import D again, bring the link up: the sibling joined a channel
  this device had left. Fixed in 3411e19: `_dropOwedToOtherDistros` on every
  change of the distro held, at load, and before each flush. 74fbbcd
  narrowed it to the membership messages (`_dropMembershipOwedToOtherDistros`):
  a sent copy stays owed to its distro (James's fifth ruling).
- *No bound on `at_ms`* (a448e98). `readHead` rounds a 64-bit integer above
  2^53 − 1, and such an `at_ms` was applied. Fixed in 3411e19: rule 4
  refuses a value that is not `Number.isSafeInteger`.
- *A C uploaded twice at once* (a448e98, and 3411e19 in another way). At
  a448e98, a STALE link replaced by a new one kept its upload open, and the
  new link's flush uploaded the same C again. 3411e19 decided the replaced
  link's uploads as lost, and the new link's `"established"` uploaded C
  again. When the node then proved the first upload over the old link, the
  same C went twice: two stamps and two fan-outs. Fixed in 145ca2f: a
  replacement decides nothing, and an upload that has left and is not
  decided blocks a second one on any link.
- *An earlier flush uploaded again what a newer one saw lost* (3411e19). An
  `"established"` flush still mining a stamp went on after a `"recovered"`
  flush had uploaded an entry whose packet was then reported lost. It
  uploaded the entry again on the same link with no link event between.
  Fixed in 145ca2f (`_distroFlush`). 74fbbcd replaced `_distroFlush` with
  the general rule (`_unprovedSince`), which covers this case.
- *The second upload* of a C that was not proved was unrecorded at a448e98.
  It is now the rule ("On the sending device"), and 3411e19 cites the
  exception where the code makes it.

**Tests every client makes for the sending device**, each with the mutation
it must catch:

- Storage that refuses a write larger than what it holds: owe a join (kept),
  fill storage, owe a §17.11 sent copy (refused), then owe a leave of the
  same channel (refused). What storage holds then does not hold the join.
  Mutation: writing, after the refusal, what this device holds in memory
  (Retichat-js a448e98) leaves the join for a later page.
- Owe a join and a §17.11 sent copy with the link down, give up D (a log
  line says the join was dropped), import D again and bring the link up:
  the join is not uploaded, and the sent copy is uploaded once. Mutations:
  keeping what is owed while no distro is held (Retichat-js a448e98) uploads
  the join, and the sibling joins a channel this device left; dropping the
  sent copies with D (Retichat-js 3411e19, 145ca2f) loses the copy.
- Owe a sent copy under D, then forget D or take D2, including while the
  copy's upload is being built, and bring the link up. The copy is uploaded
  once, as the same packed bytes, addressed and encrypted to D, and D's
  other devices show it. A sent copy made under D2 goes to D2. Mutations:
  dropping sent copies with D loses the copy. Encrypting it with the key of
  the distro held when the upload is built, not the entry's own key, either
  encrypts it to D2, which D's devices cannot read, or never sends it when
  no distro is held.
- Owe C with the link down, stop the app (in a browser, close the tab), start
  it again, and bring the link up: C is uploaded once. Mutation: holding C
  only in memory loses it.
- An upload whose packet is reported lost is said (a log line and an error).
  It is not sent again before the link next comes up, and then it goes once.
  The next coming-up is its next establishment, or a STALE link's recovery
  when the node is heard on it again, which may be on the same link.
  Mutations: settling C on the loss loses it; uploading it again at the
  failure itself sends it with no coming-up between.
- A STALE propagation link that recovers, because the node is heard on it
  again, is a coming-up: what is owed goes on it, once. Mutation: no flush
  on the recovery leaves it waiting for an establishment that may never
  come.
- A STALE link that a new attempt has replaced, and that then recovers,
  starts no flush: what is owed waits for the current link's coming-up
  (this section's reading of the first and third rulings). Mutation: a
  flush on the recovery of any link, current or not, sends on a link that
  is no longer the propagation link.
- Nothing but the link's coming-up starts a flush: not a resume of the app
  or page, not a timer, and not a failure. Mutation: a flush started on a
  resume sends a failed upload again with no coming-up between.
- A proof that comes after the loss report settles C, and it does not go
  again. Mutation: ignoring the late proof uploads it again on the next link.
- A build that throws: said, C still owed, and a flush under way that
  listed it does not build it again; it goes once on the next coming-up.
  Mutation: a build failure left unrecorded is built again by the flush
  under way, with no coming-up between.
- The link closing, or the connection stopping, before the proof decides the
  upload unproved, and C goes once on the next link. Mutation: a close that
  decides nothing leaves the upload open, and C never goes again.
- A STALE link replaced by a new one. The new link does not upload C while
  the first upload is open, and a proof over the old link settles C, with
  one upload. If the old link's own close, or the loss report for that
  upload, decides it unproved while the new link is up, C goes once on the
  new link at once, and a failure of that upload waits for the next
  coming-up. With no newer link up, C goes once when the next link comes
  up. Mutations:
  - an in-flight check that looks only at the same link uploads C twice at
    once;
  - a replacement that decides the old link's uploads sends C again before
    the late proof can settle it;
  - a close that leaves C for the next coming-up while the newer link is up
    (Retichat-js 145ca2f) does not send it.

  And when the loss report sent C on the new link, a late proof of the
  first upload over the old link settles C: a loss of the new link's upload
  then sends nothing, and C does not go on the next coming-up. Mutation:
  ignoring the late proof uploads C again on the next coming-up.
- Two flushes on one link, with a loss between them: the earlier flush does
  not upload again what the newer one saw lost. Mutation: a flush that goes
  on after a newer one began uploads it with no coming-up between.
- An upload decided unproved while a flush builds an earlier entry: the
  flush does not upload it, and it goes once on the link's next coming-up.
  Three cases:
  - the user's own upload, reported lost while a `"recovered"` flush builds;
  - an upload on a replaced link, decided by that link's close while the
    new link's `"established"` flush builds;
  - an upload that an earlier flush made, reported lost while a later flush
    on the same link builds.

  Mutations: a flush that checks only that the entry is owed and not in
  flight uploads it at once, with no coming-up after the failure
  (Retichat-js 145ca2f does, and fails the first two cases). Recording the
  failure at the coming-up of the flush that made the upload, not the one
  current when the failure is decided, fails the third.
- Two actions on one channel whose decisions overlap ("A failure belongs to
  the exact message"). The user joins CH, and the join's upload stays open,
  unproved, on a STALE link that a new one replaces. The user leaves CH,
  and the leave goes at once on the new link. A coming-up's flush lists the
  leave behind an earlier entry and builds that entry. The leave's upload
  is reported lost. Then the join is decided: by the old link's close, by
  its loss report, or by its build throwing. The flush neither uploads the
  leave nor mines a stamp for it, the leave goes once on the next coming-up,
  and the join, owed no more, keeps no record and never goes again. The
  same holds with the join decided before the leave's loss, proved after
  it, or reported lost before it and proved late after it. With two §17.11
  sent copies in place of the join and the leave, the older copy is still
  owed: decided lost while the new link is up, it goes once on that link
  at once (the third ruling). Mutations:
  - one record per channel, written whatever is owed (Retichat-js 367b266),
    uploads the leave again at once, on its own failure;
  - forgetting every record under the id when one message is owed no more
    (an older action's proof clearing the newer's record) does the same;
  - reading any record under the id, not the message's own, holds back or
    lets through the wrong message;
  - recording a failure for a message owed no more leaves a record behind.
- On the phones (James's ruling on "the packet reported lost", "The phones'
  outbox" above): the packet receipt of an upload times out. The
  propagation link is torn down, and the close decides the upload unproved,
  which the device says. Nothing is sent before the next establishment, and
  C goes once on it. A proof after the timeout is logged as a
  DESIGN_PRINCIPLES §1 violation, and it settles C, which does not go again.
  Mutations:
  - a timeout that decides nothing leaves C open, and it never goes again;
  - a timeout that does not tear the link down leaves C owed on a link that
    stays up, with no coming-up to carry it;
  - a re-send on the router's own timer (LXMF-rust 3e617aa) sends C with no
    coming-up;
  - ignoring the late proof sends C again on the next establishment.

Retichat-js 2683ea4 has a test for each case except two. The phones' case
covers the phones' event, not the web's. A late proof after the third
ruling's send is not a test of its own: a scratch probe in the harness of
`distro_channels.test.mjs` showed that 2683ea4 settles C and sends it no
more, and that ignoring the late proof fails the probe. The suites'
general late-proof tests catch that mutation too (below). Seventeen
mutations of 2683ea4 were run on 2026-10-04 against `distro_outbox`,
`distro_channels`, `distro_upload` and `distro_sent_sync`, each on a
scratch copy of a `git archive` of the commit. Unmutated, those suites pass
all 162 of their tests. Each mutation was caught; the number is how many
tests failed.

James's rulings:
- a flush that does not look at when an entry's upload failed
  (`_unprovedSince` always false): 24, among them the four "uploaded
  outside the flush that is running" cases and the replaced-link close
  during an `"established"` flush;
- a failure recorded at the coming-up of the flush that made the upload,
  not the one current when it is decided: 4, the four "uploaded by an
  earlier flush" cases;
- an upload sent again at its own failure, on the link that is up: 35;
- a replaced link's close or loss, with a newer link up, that does not send
  on it: 7, the two replaced-link tests, the close during an
  `"established"` flush, and four of the two-sent-copies cases;
- a replacement that decides the replaced link's uploads: 17, "a STALE
  propagation link replaced by a new one decides nothing … one upload, one
  stamp, one fan-out" among them;
- no flush on the current link's `"recovered"`: 17, "what the distro is
  owed goes when a STALE propagation link recovers" among them;
- sent copies dropped with D (`dropMembershipNotFor` dropping every entry
  owed to another distro): 6;
- a sent copy encrypted with the key of the distro held when it is built,
  not its own: 3;
- a third caller of `_sendDistroOutbox`, on a page resume: 1, the test that
  pins its callers.

The failure record (9d45faa):
- the record as at 367b266, one per id, written whatever is owed, and the
  replaced message's record not forgotten: 5. They are the join-and-leave
  cases decided by the close and by the loss report after the leave's loss,
  the older build that throws, "a failed join replaced by a leave leaves no
  record behind", and the unit test of `UnprovedUploads`;
- one record per id alone, the owed check kept: 1, the unit test (the owed
  check by itself also stops the overwrite);
- the owed check alone removed: 4;
- forgetting one message clearing every record under its id: 4, "the proof
  of an earlier action on a channel does not clear the failure of the later
  one" among them;
- the reader taking any record under the id: 7.

This section's readings and rules:
- a replaced link's recovery counted as a coming-up (the `"recovered"`
  listener without its "current link" check): 1, "a recovery of a link that
  is no longer the propagation link sends nothing";
- a build that throws left unrecorded: 1, "an upload whose build fails
  while a flush that listed it builds an earlier entry is not built again by
  that flush";
- the late proof ignored (`onLateProof` does nothing): 2, the two general
  late-proof tests.

With `RETICHAT_BOOT_TESTS=1`, the Chromium page test
(`distro_channels_page`) passes at 2683ea4. In it, the membership message
owed to a forgotten distro is dropped, and its sent copy still goes to that
distro.

b6c7f7f adds one test to `distro_sent_sync`: the pin of `_uploadOwed`'s
three callers, and of their callers up to a DM's dispatch and the user's
join and leave ("Retichat-js", as made).
Twenty-six mutations of b6c7f7f were run on 2026-10-04, each adding a stray
caller or path at one pinned place on a scratch copy, and the pin caught
every one. The full suite of 2683ea4 (968 tests) missed 14 of the same
mutations, among them the verifier of 2683ea4's probe RX1 (an announce
uploading every owed entry through `_uploadOwed`), the coming-up pass
calling it without its coming-up, `DistroUploads.lost` on an announce, and
the page closing a replaced STALE link itself. Comments naming every
pinned call change nothing. `git diff 2683ea4 b6c7f7f -- app.js lib/`
touches comment lines only, and with comments out the code of each file is
2683ea4's. In test-harnesses f24a451, every distro test's pin names
b6c7f7f, and a test fails unless those pins agree, the stage's header
names the same head, and that head serves the code the chain ran
(2683ea4), differing only in comments and the web's tests. Two lines of
`link_close.test.mjs`'s header still called 367b266, where its link tests
run, the branch's head; that test read only the pins, not the prose. The
harness's suites pass there: 390 tests, 337 pass and 53 skipped without
Chromium, and 390 of 390 with `RETICHAT_BOOT_TESTS=1`, the live tests at
b6c7f7f included.

90640bf answers the verifier of b6c7f7f ("Retichat-js", as made): a
second test in `distro_sent_sync` pins what reaches `_oweDistro`'s two
callers up to where each path begins, and the first now pins
`_uploadForDistro`, and every close, loss report and event the page and
`lib/` make. Sixty mutations were run on 2026-10-04 against
`distro_sent_sync`, each on a scratch copy: forty new ones, each a stray
caller or path at a newly pinned place, and the verifier of b6c7f7f's
twenty probes. Each was caught by the assertion meant for it. b6c7f7f's
full suite (969 tests) missed 35 of the same 60. Among them were the
verifier's R5, R12, R13, R14 and R17; a send from the page's own
`"online"`, `"focus"`, or a synthetic click or Enter key; uploads read
straight from the outbox, its storage or its attempts in flight, and a
new reader of its failure records; and the page closing a replaced STALE
link by an optional or a computed call. Seven negatives pass on the full suite (970
tests), among them log lines saying close, lost, emit and established.
`git diff 2683ea4 90640bf -- app.js lib/` touches comment lines only, and
acorn's tokens and AST of `app.js`, `lib/distro_upload.js` and
`lib/distro_outbox.js` are 2683ea4's. `npm test` passes, 970 tests with
24 skipped for Chromium, and `npm run test:full` passes 970 of 970.

In test-harnesses 7e18425, every distro test pins 90640bf.
`link_close.test.mjs`'s header says its runs at 367b266 are of the head's
link code. A new test fails unless every "head" a staging source names is
the pin, and unless the head serves 367b266's link code (`lib/rns/` and
`test_link_pair.mjs`) unchanged. On f24a451's tree it fails on exactly
those two lines. The harness's suites pass there: 391 tests, 338 pass
and 53 skipped without Chromium, and 391 of 391 with
`RETICHAT_BOOT_TESTS=1`, the live tests at 90640bf included.

Earlier, before James's rulings, ten mutations of Retichat-js 145ca2f were
run on 2026-10-03 against `distro_outbox`, `distro_channels`,
`distro_upload` and `distro_sent_sync`, and each was caught. The number is
how many tests failed:

- the outbox kept only in memory: 26, "the tab closes before the link comes
  up: the next page sends the C still owed, once" among them;
- in-flight check for the same link only: 2;
- no flush on `"established"`: 1;
- settle on the loss: 11;
- upload again at the failure itself: 4;
- the late proof ignored: 2;
- no `_distroFlush` check: 1;
- no drop on a change of distro: 1;
- the refused write keeps the replaced entry: 4;
- the link's close decides nothing: 1 in `distro_channels`, the
  replaced-link close test. In `distro_sent_sync`, "the propagation link's
  close decides the uploads made on it lost, and only those; a superseded
  link's too" fails another way: the outcome it awaits never settles, and
  node's test runner reports it and the 10 tests after it in that file as
  cancelled, not failed (11 cancelled, exit status 1).

**Tests every client makes for rules 4 and 5 and the repeat key** (in its
pure disposition function and the rule 6 code). Each case is listed with the mutation it must
catch:

- A `leave` of a stored channel whose name today's join refuses (for example
  `public.Test`) is applied, and a `join` of that name is dropped. Mutation:
  holding the leave to the join rules keeps the channel.
- A device that has received a sibling's leave, with its clock 10 minutes
  behind, stamps a later join after that leave, and every device ends
  joined. Mutation: stamping with the clock alone leaves the devices
  disagreeing.
- A join and a leave with one `at_ms`, delivered in either order, leave
  every device left. Mutation: letting an equal time replace the record
  makes the result depend on the order.
- Concurrent actions end in one state on every device, the one with the
  larger `at_ms`.
- A C whose `at_ms` is int 64 (`0xd3`, as the web writes it) and one whose
  `at_ms` is uint 64 (`0xcf`, as rmpv writes it), holding one value, read as
  the same action. Mutation: a reader that takes one of the two types only
  drops the other client's C, and the devices disagree. In Retichat-js at
  145ca2f, removing `readHead`'s `0xcf` case fails "readChannelSync: at_ms
  is an integer from 0 to 2^53 − 1 in any integer encoding …" and
  `lxmf_signature.test.mjs`'s byte-for-byte test (a448e98 had no
  `readChannelSync` test with a `0xcf` `at_ms`).
- Two Cs from two siblings with the same LXMF timestamp and different
  actions are both judged by rule 5. Mutation: a repeat key without the
  LXMF message hash ("Receiving") drops the second as a repeat. In
  Retichat-js at a448e98 and at 145ca2f that mutation fails "rule 5: a join
  and a leave at one time leave every device left, in either order".
- An `at_ms` of 2^53 − 1 is read, as uint 64 and as int 64; 2^53 and
  2^53 + 1 as uint 64, 2^53 as int 64, and 2^64 − 1 are unusable, and rule 4
  drops them. Mutation: a reader without the bound takes them (Retichat-js
  a448e98 rounded them; `as_u64()` alone keeps them exact), and the web and
  the phones order a join at 2^53 + 1 and a leave at 2^53 differently. In
  Retichat-js at 145ca2f, removing the `Number.isSafeInteger` check fails
  the `readChannelSync` bound test and "rule 4: a C whose at_ms is above
  2^53 − 1 is dropped, whatever its encoding, and never applied".

### 17.13 Distro sync proof

A device's own uploads to its distro, the §17.11 sent copy and the §17.12
membership message, are distro sync: every device of D gets them, and none
needs a wake for them. RFed cannot tell them from another sender's message to
D, because the source is inside the encryption to D. The sending device
therefore proves with D's key that an upload is its own sync, and RFed
delivers a proven upload without a wake (James, 2026-10-10; both kinds, the
membership message included).

**The upload.** The proof travels in the client upload to `lxmf.propagation`
that carries the message, as a third element of the envelope (with it, the
upload is larger than the link MDU and goes as a Resource):

    [ timebase f64, [ lxmf_data, ... ], { "rfed.distro.sync": [ claim, ... ] } ]
    claim = [ bin(16) id, bin(64) distro_pubkey, bin(64) sig ]

| Item | Value |
|---|---|
| `lxmf_data` | `sealed` followed by the PN stamp (32 bytes), as LXMF |
| `sealed` | `D_hash(16) | D.encrypt(packed[16:])`; `transient_id = SHA-256(sealed)` |
| `id` | `transient_id[0:16]`: the message of this upload the claim is for |
| `distro_pubkey` | D's 64-byte public key |
| `sig` | D's Ed25519 signature over `"rfed.distro.sync" (16 ASCII bytes) | 0x01 | D_hash(16) | transient_id(32)` |

Every value is native msgpack (bin for bytes, str for the key); nothing is
pre-encoded and wrapped (CHECK_THESE_THINGS_FIRST §11). A reader takes
`data[1]` as before, takes `data[2]` only as a map and only its key
`"rfed.distro.sync"`, and ignores anything else. It ignores the whole
extension when the claims are not an array of 1 to N elements, N being the
number of messages in `data[1]`, or when the map holds the key twice. A claim
that is not `[bin16, bin64, bin64]`, and two claims with one `id`, are
ignored. The PN stamp is required at the node's cost, as without a proof. The
claim names no device: a proof marks one sealed message as D's own sync and
nothing else. One implementation serves the device and RFed
(`lxmf_rust::distro`: `seal_for_sync`, `sealed_upload`,
`decode_sync_extension`, `verify_sync_claim`); the golden vector is
LXMF-rust `tests/distro_sync_vectors.json`, which RFed's tests also accept.

**On the sending device.** The device seals each message once, when it is
owed: packed and signed as D as before, then encrypted once to D, and the
signed bytes above signed with D's key. It keeps `sealed` and `sig` with the
owed entry. Every upload carries the same sealed bytes and proof; only the
stamp and timebase are made again. A sent copy owed to a distro the device
has given up is therefore still proven. An entry owed before the device
could seal is uploaded without a proof. The device sends the third element
only to the `lxmf.propagation` destination of the RFed identity it registered
D with; to any other node (a Settings override, an LXMF propagation node) it
sends LXMF's two-element envelope, because LXMF ignores a Resource whose
envelope is not exactly two elements
(`LXMRouter.propagation_resource_concluded`). It never also hands the message
to its LXMF router. A Resource upload whose first advertisement no interface
could carry never left the device (DESIGN_PRINCIPLES §3).

**At RFed.** RFed reads claims only from a client's upload (a batch not from
one of its LXMF peers; a peer's batch that carries an extension counts as
ignored). For each message whose stamp is valid and whose destination is a
distro registered here, RFed takes the claim with that message's `id` and
accepts it when `distro_pubkey`'s `lxmf.delivery` hash is the message's
destination and `sig` is valid over the signed bytes with the message's
`transient_id`. Ed25519 therefore runs only for a message that paid its
stamp. An accepted claim makes the message's fan-out (§17.3) a sync fan-out:
every registered device, the sender included, gets the live push as usual,
and one the push does not confirm is queued for `/distro/pull` and not woken,
unless that device then holds 64 or more queued blobs of D or the deferred
queue holds three quarters of its global limit or more, when it is woken as
without a proof (`handoff::distro_hand_off`, `Wake::QueueOnly`; both bounds
are counts read under the one queue lock that enqueues, never a clock). A
claim that fails, that matches no message of the upload, or that is for a
destination that is not a distro here changes nothing: the message is stored
and fanned out as without it, with a wake. RFed never refuses or drops a
message because of its claim. A message fans out once, on first sight; a
claim on a message already held does nothing. The claim is not stored or
forwarded. An RFed before this section reads `data[1]` alone and handles the
upload as an ordinary one, with a wake.

**What RFed logs.** Nothing per claim. For each stamp-valid distro message
that carried a claim, one verdict, after the usual `[distro] intercepted …`
line. A refused proof's is written before the fan-out it names:

    [distro-sync] <id> for <D>: proof refused (<reason>), fanning out with wake      (WARNING)
    [distro-sync] <id> for <D>: proof refused (<reason>), already held: no fan-out   (WARNING)

An accepted proof's is written after the fan-out, and counts what it did:

    [distro-sync] <id> for <D>: proof accepted: <l> pushed live, <q> queued, <w> woken (<why>; …)   (NOTICE)
    [distro-sync] <id> for <D>: proof accepted, already held: no fan-out                             (NOTICE)

Each count is true when the line is written. `<l>`: devices pushed on their
rfed.link session or propagation.stream, the proof still to come (pushed,
not delivered). `<q>`: devices with no live session whose blob was queued
for the pull. `<w>`: devices with no live session a wake left for, each with
why a bound woke it after all: `<n> un-pulled`, `queue at <t> of <limit>`,
or `deferred queue poisoned` (the parentheses only when one was woken).
Then, only when there are any, `, <s> NOT queued` for hand-offs whose blob
the queue refused, and `, <k> NOT delivered (invalid key)` for devices
whose registered key yields no identity. A live push that is never proven
is handed off after the line, which does not count it: that hand-off's own
`[handoff]` line says what it came to. The fan-out's own summary, written
after its hand-offs when it made any, counts them the same way:

    [distro] <h> of <n> device(s) with no live session for distro <D> — handed off with a push: <q> queued, <w> woken
    [distro] <h> of <n> device(s) with no live session for distro <D> — handed off as distro sync: <q> queued, <w> woken (<why>; …)

For an upload whose claims had any problem, one summary:

    [distro-sync] batch from <origin>: <a> accepted, <r> refused, <m> malformed, <d> duplicate, <c> not checked, <u> unmatched, <x> ignored

(not checked: a claim whose message RFed dropped, for an invalid stamp or as
too short for LXMF, so it was never verified; unmatched: a claim that names
a stamp-valid message that is not a distro message here, or no message of
the upload; ignored: a peer's batch, or an extension ignored as a whole).
The batch's `[lxmf.prop] processed …` line is unchanged. A sync hand-off
writes `[handoff] <device> unconfirmed for <D>: queued for pull, NOT woken
(distro sync, <n> of 64 un-pulled)`, or, at a bound, `[handoff] distro sync
for <device> of <D> woken anyway: <n> un-pulled | queue at <t> of <limit>`
followed by the usual `[handoff] … woken via …` line. Each device's
`[handoff]` line is the record of that device; the summaries only count
them.

**Not covered** (these still wake devices): sync from clients that do not
seal, and entries owed before sealing; uploads to any node but the
RFed-derived one; a copy that reaches D's home node by LXMF peer sync or by
FedSync; delivery notifications recipients send to D; anything not signed
by D.

**Without a wake.** A device that is neither opened nor woken for anything
for 7 days loses the sync it was not woken for, as an offline device does
(§7 "Limits", §17.12 "In RFed's queue"); the node logs it.

**Capabilities.** `/rfed/capabilities` reports `distro_sync` (§17).

### 17.9 Distro Identity Transfer

The distro identity (64-byte private key) is shared between devices
using a URI format or encrypted LXMF transfer.

**URI format:**

```
rfed-distro-id://<128_hex_chars>
```

The 128 hex characters encode the 64-byte private key
(X25519_priv(32) || Ed25519_priv(32)). The public key is derived from
the private key on import.

**LXMF transfer:**

The sender addresses an ordinary LXMF message to the recipient's
`lxmf.delivery` address (signed as the sending *device*, not as the distro,
so the recipient can judge the offer by who sent it) and carries the key in
LXMF's custom-payload pair:

```
fields[0xFB] (FIELD_CUSTOM_TYPE) = "rfed.distro.transfer"
fields[0xFC] (FIELD_CUSTOM_DATA) = <128 hex chars, the private key>
```

A receiver treats a message as a transfer only when `FIELD_CUSTOM_TYPE`
equals that string. Field `0x0D`, used before 2026-09-24, is LXMF 1.1.1's
`FIELD_EVENT` and is neither written nor read.

**User flow:**

1. Device A generates a new distro identity (button press in Retichat).
2. Device A shares via LXMF to Device B (or shows QR code with URI).
3. Device B receives the encrypted private key, prompts user to import.
4. Device B imports identity and registers with RFed.

**Security model:**

- The private key is never displayed to the user.
- The URI is only shown ephemerally (QR code) or sent encrypted (LXMF).
- The identity is stored in the platform's secure enclave
  (iOS Keychain / Android Keystore).
- Possession of the private key = full access to all distro traffic.
  There is no revocation mechanism — a compromised key requires
  generating a new distro identity and re-registering all devices.

---

## License

See [LICENSE](rfed/LICENSE).

---

*This specification and the rfed codebase were developed through human–AI
collaboration using Claude (Anthropic) and GitHub Copilot. Architecture
decisions, code review, security audits, and testing were conducted by the
human author with AI assistance throughout the development process.*
