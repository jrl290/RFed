//! Channel key derivation — client-side helper.
//!
//! This module is used by clients (and future tooling) to derive channel
//! destination hashes from a channel name.  It is intentionally unused by
//! the server binary.
#![allow(dead_code)]
//!
//! # Channel addressing
//!
//! Each named channel has a deterministic 16-byte hash derived from the
//! channel name alone.  Any party that knows the name can independently
//! compute the same hash — no server configuration required.
//!
//! ```text
//! seed          = sha256(channel_name)
//! channel_hash  = sha256(x25519_pub(seed) || ed25519_pub(seed))[..16]
//! ```
//!
//! Senders embed the 16-byte channel hash at the start of every SEND packet.
//! The node is a **dumb store** — it accepts SEND packets for any channel hash
//! without needing to know the channel names up front.  Channels come into
//! existence simply by virtue of blobs being stored for their hash.
//!
//! # Channel naming convention
//!
//! Channel names are dot-separated path segments, mirroring Reticulum's own
//! destination aspect notation:
//!
//! ```text
//! public.news.tech     → a "public" channel anyone can find by name
//! public.announcements → another public channel
//! <opaque-secret>      → a private channel; only distributed out-of-band
//! ```
//!
//! For **public** channels the first segment is literally the string
//! `"public"`.  Any peer that knows the path can independently derive the
//! same hash — no server-side registration required.
//!
//! For **private** channels the name (or first segment) is an unguessable
//! secret.  Possession of the name = channel membership.
//!
//! Clients should use [`ChannelKeypair::from_path`] when constructing a
//! channel from segments, or [`ChannelKeypair::from_name`] when the full
//! dot-joined name is already known.

use sha2::{Digest, Sha256};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519Public};
use ed25519_dalek::{SecretKey as Ed25519Secret, PublicKey as Ed25519Public};

use reticulum_rust::identity::Identity;

// ── ChannelKeypair ───────────────────────────────────────────────────────────

/// A channel's full keypair.  Used by clients and nodes to derive the
/// canonical Reticulum destination hash for a named channel.
///
/// Construct with [`ChannelKeypair::from_name`] or the convenience wrapper
/// [`ChannelKeypair::from_path`].
pub struct ChannelKeypair {
    pub name: String,
    /// X25519 keys — used for encryption in inner blobs.
    pub x25519_secret: X25519Secret,
    pub x25519_public: X25519Public,
    /// Ed25519 keys — used for signing and RNS destination hash derivation.
    pub ed25519_secret: Ed25519Secret,
    pub ed25519_public: Ed25519Public,
}

impl ChannelKeypair {
    /// Derive a deterministic channel keypair from a channel name.
    ///
    /// `seed = sha256(channel_name)` is used as the 32-byte private key
    /// material for both X25519 and Ed25519.  Any two parties that know the
    /// name will independently arrive at the same destination hash.
    ///
    /// For public channels the name should follow the `public.<segments...>`
    /// convention.  Use [`from_path`](Self::from_path) to construct the name
    /// from individual segments automatically.
    pub fn from_name(name: &str) -> Self {
        let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();

        let x25519_secret = X25519Secret::from(seed);
        let x25519_public = X25519Public::from(&x25519_secret);

        let ed25519_secret = Ed25519Secret::from_bytes(&seed)
            .expect("sha256 output is always a valid Ed25519 key");
        let ed25519_public = Ed25519Public::from(&ed25519_secret);

        ChannelKeypair {
            name: name.to_string(),
            x25519_secret,
            x25519_public,
            ed25519_secret,
            ed25519_public,
        }
    }

    /// Derive a channel keypair from an ordered list of path segments.
    ///
    /// Segments are joined with `'.'` and passed to [`from_name`](Self::from_name).
    ///
    /// # Public channels
    ///
    /// Pass `"public"` as the first segment:
    ///
    /// ```rust,ignore
    /// let kp = ChannelKeypair::from_path(&["public", "news", "tech"]);
    /// // equivalent to ChannelKeypair::from_name("public.news.tech")
    /// ```
    ///
    /// # Private channels
    ///
    /// Pass a single unguessable secret as the only segment:
    ///
    /// ```rust,ignore
    /// let kp = ChannelKeypair::from_path(&["s3cr3t-invite-token"]);
    /// ```
    pub fn from_path(segments: &[&str]) -> Self {
        Self::from_name(&segments.join("."))
    }

    /// The 64-byte public key bundle (X25519 || Ed25519) that Reticulum's
    /// Identity uses to derive destination hashes.
    pub fn public_key_bundle(&self) -> Vec<u8> {
        let mut bundle = Vec::with_capacity(64);
        bundle.extend_from_slice(self.x25519_public.as_bytes());
        bundle.extend_from_slice(self.ed25519_public.as_bytes());
        bundle
    }

    /// The 16-byte truncated destination hash for this channel.
    ///
    /// Clients embed this in the first 16 bytes of every SEND packet.
    pub fn hash(&self) -> Vec<u8> {
        // Reticulum destination hash: SHA-256 over the full public key bundle,
        // truncated to the first 16 bytes (TRUNCATED_HASHLENGTH / 8).
        let bundle = self.public_key_bundle();
        let full = Sha256::digest(&bundle);
        full[..16].to_vec()
    }

    /// Construct a Reticulum `Identity` representing the channel's keys.
    /// Used when registering the channel as a Reticulum destination.
    pub fn to_identity(&self) -> Result<Identity, String> {
        let mut prv_bundle = Vec::with_capacity(64);
        prv_bundle.extend_from_slice(&self.x25519_secret.to_bytes());
        prv_bundle.extend_from_slice(self.ed25519_secret.as_bytes());
        Identity::from_bytes(&prv_bundle)
    }
}

