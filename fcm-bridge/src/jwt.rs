//! RS256 JWT generator for Google service-account OAuth assertions.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::json;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub struct GoogleJwt {
    private_key: PKey<Private>,
    client_email: String,
    token_uri: String,
    scope: String,
    token_ttl: u64,
}

impl GoogleJwt {
    pub fn new(
        private_key_pem: &str,
        client_email: &str,
        token_uri: &str,
        scope: &str,
        token_ttl: u64,
    ) -> Result<Self, String> {
        let private_key = PKey::private_key_from_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("cannot parse service account private key: {e}"))?;
        Ok(GoogleJwt {
            private_key,
            client_email: client_email.to_string(),
            token_uri: token_uri.to_string(),
            scope: scope.to_string(),
            token_ttl: token_ttl.clamp(60, 3600),
        })
    }

    pub fn generate_assertion(&self) -> Result<String, String> {
        let iat = now_secs();
        let exp = iat + self.token_ttl;

        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = b64url(
            json!({
                "iss": self.client_email,
                "sub": self.client_email,
                "aud": self.token_uri,
                "scope": self.scope,
                "iat": iat,
                "exp": exp,
            })
            .to_string()
            .as_bytes(),
        );

        let signing_input = format!("{header}.{payload}");
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)
            .map_err(|e| format!("cannot create JWT signer: {e}"))?;
        signer
            .update(signing_input.as_bytes())
            .map_err(|e| format!("cannot sign JWT payload: {e}"))?;
        let signature = signer
            .sign_to_vec()
            .map_err(|e| format!("cannot finalise JWT signature: {e}"))?;

        Ok(format!("{signing_input}.{}", b64url(&signature)))
    }
}