# RFed — Reticulum Federation Node

A subscriber federation node for the [Reticulum](https://reticulum.network) network. RFed provides named **channel** messaging with deferred delivery, cross-node synchronisation, notify wake-ups, and subscriber backup failover — all running over Reticulum's encrypted transport layer.

> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models. Architecture, implementation, code review,
> and documentation were produced through iterative human–AI collaboration.

## Built on LXMF

RFed's core transport is modelled directly on the [LXMF](https://github.com/markqvist/LXMF) (Lightweight Extensible Message Format) store-and-forward architecture. The following mechanisms are carried over from LXMF and adapted for channel-based messaging:

| Mechanism | LXMF Origin | RFed Adaptation |
|-----------|-------------|-----------------|
| **Propagation node model** | Messages stored by destination hash, retrieved by recipients on demand | Blobs stored by channel hash, fanned out to subscribers |
| **OFFER / GET sync protocol** | Peer sends manifest of IDs → gap computed → missing blobs fetched | Identical wire protocol (`/rfed/offer`, `/rfed/get`), filtered to channels with local subscribers |
| **Proof-of-work stamps** | Sender stamps validated at configurable bit difficulty (msg / PN / peering tiers) | Reuses LXMF stamp validation via `lxmf_rust`; same cost/flexibility model |
| **Peering cost** | Propagation nodes advertise a PoW cost for incoming peers | Parsed from peer announces; used in sync backoff scheduling |
| **Destination hash routing** | First 16 bytes of wire format = recipient hash (plaintext, for routing) | Channel hash occupies the same position in the SEND packet |
| **Exponential backoff** | Sync retry with increasing delay on failure, reset on success | Same pattern: 10 s min → 1 hour max, reset on announce heard |
| **Announce metadata** | Msgpack array with node state, limits, stamp params, metadata map | Simplified 3-field announce; LXMF-format announce on optional `lxmf.propagation` destination (**notify trigger only — rfed is not an LXMF propagation node**) |

RFed extends beyond LXMF with **named channels**, **explicit subscriptions**, **double-envelope encryption**, **notify relays**, **deferred per-subscriber queuing**, and **backup failover with chain-of-custody** — none of which exist in LXMF.

## Features

- **Named channels** — derive a 16-byte channel hash from any plain-text name; no server registration needed
- **Subscriber delivery** — blobs are stored on disk and delivered to subscribers when they come online
- **Federation sync** — manifest-based gap-pull protocol between peer nodes (LXMF OFFER/GET)
- **Deferred delivery** — offline subscribers receive queued blobs on reconnect or explicit pull
- **Notify relays** — lightweight wake packets to registered relays; can be used for mobile push notifications (APNs, FCM, UnifiedPush) without exposing message content
- **Backup failover** — chain-of-custody handoff when a primary node goes silent
- **LXMF notify trigger** — when enabled, rfed announces an `lxmf.propagation` destination and accepts inbound LXMF messages **only** to trigger notify wake-ups; messages are never stored, forwarded, or made available for download.
- **Proof-of-work stamps** — configurable PoW difficulty per subscriber tier (default / VIP)
- **Double-envelope encryption** — node never sees inner blob content; encrypted end-to-end

## Quick Start

### Prerequisites

- Rust 1.70+ toolchain
- [reticulum_rust](https://github.com/your-org/reticulum-rust) and [lxmf_rust](https://github.com/your-org/lxmf-rust) cloned alongside this repo (see [Dependencies](#dependencies))

### Build

```bash
cargo build --release
```

The binary is at `target/release/rfed`.

### Run

```bash
# Minimal — uses defaults, stores data in ~/.rfed/
rfed

# With a config file
rfed --config /path/to/config/dir

# Override settings via CLI
rfed --name "my-node" --stamp-cost 12 --storage-limit 5000
```

On first run, rfed writes a commented sample config to `<config_dir>/rfed.toml` if none exists.

### Configuration

Copy `rfed.toml.example` to your config directory and edit:

```bash
cp rfed.toml.example ~/.rfed/rfed.toml
```

See the [Specification](SPEC.md#13-configuration) for all options.

## Channels Are Reticulum Destinations

A channel is derived using the same cryptographic primitives as a Reticulum identity — X25519 for encryption and Ed25519 for signing — but it is **not** a registered or announced identity on the network. The keypair is deterministically computed from the channel name, so anyone who knows the name independently derives the same keys and the same 16-byte destination hash:

```
"public.news.tech"
        │
        ▼
  seed = SHA-256("public.news.tech")            → 32 bytes
        │
        ├─► X25519 public key (from seed)       → 32 bytes  (encryption)
        └─► Ed25519 public key (from seed)      → 32 bytes  (signing)
                │
                ▼
  bundle = X25519_pub ‖ Ed25519_pub             → 64 bytes
        │
        ▼
  channel_hash = SHA-256(bundle)[0..16]         → 16 bytes  (destination hash)
```

**Possession of the channel name = possession of the private keys = ability to decrypt.**

RFed nodes only ever see the 16-byte `channel_hash`. They store and route opaque blobs encrypted to the channel's public key. The nodes are **cryptographically blind** — they cannot decrypt any message content.

### Channels Are Virtual — Not Announced, Not Routed

Although a channel hash is derived using the same cryptographic primitives as a Reticulum identity (X25519 + Ed25519 → destination hash), **channels are never announced or routed on the Reticulum network**. No Reticulum destination is registered for a channel, and no packets are addressed *to* the channel hash as a transport destination.

Instead, a channel only comes into existence when a sender publishes a blob to the rfed node's `rfed.channel` destination with the channel hash embedded in the payload. The node treats the hash as an opaque storage key — it has no awareness that the hash corresponds to a keypair, only that blobs should be filed under it and fanned out to matching subscribers.

This is directly analogous to how LXMF propagation works: an LXMF propagation node stores messages keyed by the recipient's destination hash without that recipient being registered or announced on the node itself. The node is a mailbox, not a router. RFed applies the same principle to channels.

### Channel Hash Utilities

Utilities for computing channel hashes are provided in both Rust and Python:

```python
# Python
from channel_hash import compute_channel_hash
h = compute_channel_hash("public.news.tech")
print(h.hex())
```

```rust
// Rust
let kp = ChannelKeypair::from_name("public.news.tech");
let hash: Vec<u8> = kp.hash();
```

### Naming Conventions

| Pattern | Visibility | Example |
|---------|-----------|--------|
| `public.<segments>` | Discoverable by name | `public.news.tech` |
| `<hash>.<segments>` | Private; hash acts as access control | `a1b2c3d4e5f6.team.ops` |

For **public** channels the first segment is the literal string `"public"`. Anyone who learns the name can subscribe and decrypt.

For **private** channels, use a cryptographically random hex string (e.g. 32+ characters from a CSPRNG) as the first segment. Possession of the full channel name equals membership — the random prefix makes it computationally infeasible to guess. Distribute the name out-of-band to intended members only.

See [SPEC.md §1](SPEC.md#1-channel-hash-derivation) for the full derivation algorithm.

## Architecture: Message Journey

### Step-by-Step: Sender to Subscriber

```
 ┌──────────┐         ┌──────────────┐         ┌─────────────┐
 │  Sender  │────1───►│  rfed node A │────4───►│ Subscriber  │
 └──────────┘         └──────┬───────┘         └─────────────┘
                             │
                          2  │  3
                             ▼
                      ┌──────────────┐
                      │  rfed node B │────4───► (other subscribers)
                      └──────────────┘
```

#### Step 1 — Sender publishes to rfed node

The sender derives the channel's X25519 public key from the channel name and encrypts the message content to it (ephemeral ECDH + HKDF + AES-CBC-HMAC — the same scheme Reticulum uses for `Identity.encrypt()`). This produces an **inner blob** — opaque to anyone who doesn't know the channel name.

> **Note:** The current channel wire format does not include sender authentication.
> Any party that knows the channel name can publish. Sender identity verification
> is planned by adopting LXMF as the inner payload format, which provides Ed25519
> signatures, source identity, timestamps, and structured fields — identical to
> how LXMF propagation authenticates senders without the propagation node seeing
> message content.

The sender transmits to the node's `rfed.channel` destination:

```
[ channel_hash (16 bytes) | inner_blob (encrypted) | PoW stamp ]
```

| Data | Encrypted? | Visible to rfed node? |
|------|-----------|----------------------|
| Channel hash | No (routing label) | **Yes** — used for storage and fanout lookup |
| Inner blob content | Yes (to channel pubkey) | **No** — opaque ciphertext |
| Sender identity | Not in wire format | **No** — not included in current protocol (planned via LXMF inner format) |
| PoW stamp | No | **Yes** — validated then stripped before storage |

#### Step 2 — Node stores the blob

The node validates the PoW stamp, strips it, and writes the raw inner blob to disk under `blobs/<channel_hash_hex>/<message_id_hex>`. The `message_id` is randomly generated by the node. The node never modifies the inner blob.

| Data at rest | Visible to node operator? |
|-------------|--------------------------|
| Channel hash | **Yes** — directory name |
| Message ID | **Yes** — filename (random, reveals nothing) |
| Blob content | **No** — still encrypted to channel pubkey |
| Sender identity | **No** — not stored anywhere |

#### Step 3 — Federation sync (OFFER / GET)

Peer nodes exchange manifests and gap-pull missing blobs. Only blobs for channels that have **local subscribers** are requested — preventing unbounded storage growth.

| Data on the wire | Visible to either peer? |
|-----------------|------------------------|
| Message IDs | **Yes** — used for gap computation |
| Channel hashes | **Yes** — used to filter relevant blobs |
| Blob content | **No** — still encrypted to channel pubkey |
| Subscriber list | **No** — never shared between peers |

#### Step 4 — Fanout to subscribers (double envelope)

The node wraps each inner blob in a second Reticulum envelope addressed to the subscriber's `rfed.delivery` destination:

```
┌─── Outer Envelope (rfed node → subscriber) ──────────────────┐
│  Reticulum Single packet (encrypted to subscriber's pubkey)  │
│                                                              │
│  ┌─── Inner Blob (sender → channel) ─────────────────────┐  │
│  │  Encrypted to channel's X25519 pubkey                  │  │
│  │  Content: opaque to rfed node                          │  │
│  │  (sender auth planned via LXMF inner format)           │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

| Data | Visible to rfed node? | Visible to subscriber? |
|------|----------------------|----------------------|
| Outer envelope (routing) | **Yes** — the node created it | Decrypted by subscriber |
| Inner blob ciphertext | **Yes** — but cannot decrypt | **Yes** — then decrypts with channel privkey |
| Inner blob plaintext | **No** — lacks channel privkey | **Yes** — knows channel name |

If the subscriber is offline, the blob enters the **deferred queue** and is delivered on reconnect or explicit pull.

### Encryption Summary

| Party | Knows | Can decrypt content? | Sees |
|-------|-------|---------------------|------|
| **Sender** | Channel name, own keys | Yes | Only what they send |
| **rfed node** | Channel hash only | **No** | Opaque blobs, routing hashes |
| **Subscriber** | Channel name | **Yes** | Decrypted content |
| **Federation peer** | Channel hash only | **No** | Opaque blobs during sync |
| **Network observer** | Nothing | **No** | Reticulum-encrypted packets |

The rfed node is a **courier, not a reader**. It repackages and propagates channel messages in a fanout manner without ever accessing the content.

## Documentation

- **[SPEC.md](SPEC.md)** — Full protocol and operational specification
- **[rfed.toml.example](rfed.toml.example)** — Annotated configuration template

## Dependencies

RFed depends on two local Rust crates that must be cloned as siblings:

```
parent/
├── Reticulum-rust/    ← reticulum_rust crate
├── LXMF-rust/         ← lxmf_rust crate
└── RFed-rust/  ← this repo (RFed)
    ├── Cargo.toml
    ├── rfed/
    │   ├── Cargo.toml
    │   └── src/
    ├── SPEC.md
    └── rfed.toml.example
```

| Crate | Purpose |
|-------|---------|
| `reticulum_rust` | Rust Reticulum transport layer |
| `lxmf_rust` | LXMF message handling & PN stamps |

All other dependencies are pulled from crates.io automatically by Cargo.

## License

See [LICENSE](rfed/LICENSE).

---

*Built with Rust, Reticulum, and a healthy dose of AI-assisted engineering.*
