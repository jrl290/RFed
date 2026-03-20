# RFed — Reticulum Federation Node

A subscriber federation node for the [Reticulum](https://reticulum.network) network. RFed provides named **channel** messaging with offline delivery, cross-node synchronisation, mobile push wake-ups, and subscriber backup failover — all running over Reticulum's encrypted transport layer.

> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models. Architecture, implementation, code review,
> and documentation were produced through iterative human–AI collaboration.

## Built on LXMF

RFed's core transport is modelled directly on the [LXMF](https://github.com/markqvist/LXMF) (Lightweight Extensible Message Format) store-and-forward architecture. The following mechanisms are carried over from LXMF and adapted for channel-based messaging:

| Mechanism | LXMF Origin | RFed Adaptation |
|-----------|------------|-----------------|
| **Propagation node model** | Messages stored by destination hash, retrieved by recipients on demand | Blobs stored by channel hash, fanned out to subscribers |
| **OFFER / GET sync protocol** | Peer sends manifest of IDs → gap computed → missing blobs fetched | Identical wire protocol (`/rfed/offer`, `/rfed/get`), filtered to channels with local subscribers |
| **Proof-of-work stamps** | Sender stamps validated at configurable bit difficulty (msg / PN / peering tiers) | Reuses LXMF stamp validation via `lxmf_rust`; same cost/flexibility model |
| **Peering cost** | Propagation nodes advertise a PoW cost for incoming peers | Parsed from peer announces; used in sync backoff scheduling |
| **Destination hash routing** | First 16 bytes of wire format = recipient hash (plaintext, for routing) | Channel hash occupies the same position in the SEND packet |
| **Exponential backoff** | Sync retry with increasing delay on failure, reset on success | Same pattern: 10 s min → 1 hour max, reset on announce heard |
| **Announce metadata** | Msgpack array with node state, limits, stamp params, metadata map | Simplified 3-field announce; LXMF-format announce on optional `lxmf.propagation` destination |

RFed extends beyond LXMF with **named channels**, **explicit subscriptions**, **double-envelope encryption**, **notify relays**, **deferred per-subscriber queuing**, and **backup failover with chain-of-custody** — none of which exist in LXMF.

## Features

- **Named channels** — derive a 16-byte channel hash from any plain-text name; no server registration needed
- **Subscriber delivery** — blobs are stored on disk and delivered to subscribers when they come online
- **Federation sync** — manifest-based gap-pull protocol between peer nodes (LXMF OFFER/GET)
- **Deferred delivery** — offline subscribers receive queued blobs on reconnect or explicit pull
- **Notify relays** — lightweight wake packets enable mobile push without exposing message content
- **Backup failover** — chain-of-custody handoff when a primary node goes silent
- **LXMF propagation** — optional inbound LXMF acceptance for push-notification wake-ups
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

A channel is not just a name — it is a **full Reticulum identity** with its own X25519 encryption key and Ed25519 signing key, deterministically derived from the channel name. Anyone who knows the name independently derives the same keypair and the same 16-byte destination hash:

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

See [SPEC.md §1](SPEC.md#1-channel-hash-derivation) for the full algorithm and naming conventions.

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

The sender derives the channel's X25519 public key from the channel name and encrypts the message content to it. The sender also signs the ciphertext with their own Ed25519 key. This produces an **inner blob** — opaque to anyone who doesn't know the channel name.

The sender transmits to the node's `rfed.channel` destination:

```
[ channel_hash (16 bytes) | inner_blob (encrypted) | PoW stamp ]
```

| Data | Encrypted? | Visible to rfed node? |
|------|-----------|----------------------|
| Channel hash | No (routing label) | **Yes** — used for storage and fanout lookup |
| Inner blob content | Yes (to channel pubkey) | **No** — opaque ciphertext |
| Sender identity | Not in wire header | **No** — Reticulum Single destinations carry no sender |
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
│  │  Signed by sender's Ed25519 key                        │  │
│  │  Content: opaque to rfed node                          │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

| Data | Visible to rfed node? | Visible to subscriber? |
|------|----------------------|----------------------|
| Outer envelope (routing) | **Yes** — the node created it | Decrypted by subscriber |
| Inner blob ciphertext | **Yes** — but cannot decrypt | **Yes** — then decrypts with channel privkey |
| Inner blob plaintext | **No** — lacks channel privkey | **Yes** — knows channel name |
| Sender signature | Verifiable but anonymous | Verified with sender's pubkey |

If the subscriber is offline, the blob enters the **deferred queue** and is delivered on reconnect or explicit pull.

### Encryption Summary

| Party | Knows | Can decrypt content? | Sees |
|-------|-------|---------------------|------|
| **Sender** | Channel name, own keys | Yes | Only what they send |
| **rfed node** | Channel hash only | **No** | Opaque blobs, routing hashes |
| **Subscriber** | Channel name | **Yes** | Decrypted content + sender signature |
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
└── ReticulumFederation/  ← this repo (RFed)
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
