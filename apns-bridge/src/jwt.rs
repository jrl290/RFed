//! ES256 JWT generator for APNs token-based authentication.
//!
//! Apple requires a signed HS256 JWT in the `Authorization` header of every
//! APNs HTTP/2 request.  The key is a P-256 ECDSA private key downloaded from
//! the Apple Developer Portal as a `.p8` file (PKCS#8 PEM format).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub struct ApnsJwt {
    signing_key: SigningKey,
    key_id:      String,
    team_id:     String,
    token_ttl:   u64,
    cached_token: Option<String>,
    cached_iat:   u64,
}

impl ApnsJwt {
    /// Load the P-256 private key from a `.p8` PEM file and prepare the JWT generator.
    pub fn from_file(
        key_file: &Path,
        key_id:   &str,
        team_id:  &str,
        token_ttl: u64,
    ) -> Result<Self, String> {
        let pem = std::fs::read_to_string(key_file)
            .map_err(|e| format!("cannot read key file {}: {e}", key_file.display()))?;
        let signing_key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("cannot parse p8 key: {e}"))?;
        Ok(ApnsJwt {
            signing_key,
            key_id: key_id.to_string(),
            team_id: team_id.to_string(),
            token_ttl,
            cached_token: None,
            cached_iat: 0,
        })
    }

    /// Return a valid JWT, regenerating it if older than `token_ttl` seconds.
    pub fn get(&mut self) -> &str {
        let now = now_secs();
        if self.cached_token.is_some() && (now - self.cached_iat) < self.token_ttl {
            return self.cached_token.as_deref().unwrap();
        }
        self.cached_iat = now;
        self.cached_token = Some(self.generate(now));
        self.cached_token.as_deref().unwrap()
    }

    fn generate(&self, iat: u64) -> String {
        // Header: {"alg":"ES256","kid":"<key_id>"}
        let header_json = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id);
        let header = b64url(header_json.as_bytes());

        // Payload: {"iss":"<team_id>","iat":<unix_timestamp>}
        let payload_json = format!(r#"{{"iss":"{}","iat":{}}}"#, self.team_id, iat);
        let payload = b64url(payload_json.as_bytes());

        // Signing input: "<header>.<payload>"
        let signing_input = format!("{header}.{payload}");

        // Sign — `p256::ecdsa::Signature::to_bytes()` returns 64-byte fixed-size R‖S
        let sig: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let raw_sig: Vec<u8> = sig.to_bytes().to_vec();

        format!("{signing_input}.{}", b64url(&raw_sig))
    }
}
