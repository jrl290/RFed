//! APNs HTTP/2 push notification sender.
//!
//! Uses `reqwest` blocking client with rustls (no system OpenSSL required)
//! and HTTP/2 prior knowledge to talk to Apple's push notification servers.

use std::path::Path;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::config::ApnsConfig;
use crate::jwt::ApnsJwt;

const PROD_HOST:    &str = "https://api.push.apple.com";
const SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";

pub struct ApnsSender {
    jwt:         Mutex<ApnsJwt>,
    bundle_id:   String,
    host:        String,
    push_type:   String,
    alert_title: String,
    alert_body:  String,
    client:      reqwest::blocking::Client,
}

pub struct SendResult {
    pub success:   bool,
    pub http_code: u16,
    pub reason:    Option<String>,
}

impl ApnsSender {
    pub fn new(cfg: &ApnsConfig, key_file: &Path) -> Result<Self, String> {
        let jwt = ApnsJwt::from_file(key_file, &cfg.key_id, &cfg.team_id, cfg.token_ttl)?;
        let host = if cfg.sandbox {
            SANDBOX_HOST.to_string()
        } else {
            PROD_HOST.to_string()
        };
        let client = reqwest::blocking::ClientBuilder::new()
            .use_rustls_tls()
            .http2_prior_knowledge()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        Ok(ApnsSender {
            jwt: Mutex::new(jwt),
            bundle_id: cfg.bundle_id.clone(),
            host,
            push_type: cfg.push_type.clone(),
            alert_title: cfg.alert_title.clone(),
            alert_body: cfg.alert_body.clone(),
            client,
        })
    }

    /// Send a push notification.  Returns success flag, HTTP status code, and optional reason.
    pub fn send(
        &self,
        apns_token:   &str,
        receiver_hex: &str,
        sender_hex:   Option<&str>,
        channel_hex:  Option<&str>,
    ) -> SendResult {
        let url = format!("{}/3/device/{}", self.host, apns_token);
        let body = self.build_payload(receiver_hex, sender_hex, channel_hex);

        let token = {
            let mut jwt = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
            jwt.get().to_string()
        };

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("bearer {token}"))
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", &self.push_type)
            .header("apns-priority", "10")
            .header("Content-Type", "application/json")
            .body(body)
            .send();

        match resp {
            Err(e) => SendResult { success: false, http_code: 0, reason: Some(e.to_string()) },
            Ok(r) => {
                let code = r.status().as_u16();
                if code == 200 {
                    SendResult { success: true, http_code: 200, reason: None }
                } else {
                    let reason = r
                        .json::<Value>()
                        .ok()
                        .and_then(|v| v["reason"].as_str().map(|s: &str| s.to_string()));
                    SendResult { success: false, http_code: code, reason }
                }
            }
        }
    }

    /// True when APNs indicates the token is permanently invalid and should be purged.
    pub fn should_invalidate(http_code: u16, reason: Option<&str>) -> bool {
        http_code == 410 || (http_code == 400 && reason == Some("BadDeviceToken"))
    }

    fn build_payload(
        &self,
        receiver: &str,
        sender:   Option<&str>,
        channel:  Option<&str>,
    ) -> String {
        let mut rfed = json!({ "receiver": receiver });
        if let Some(s) = sender  { rfed["sender"]  = json!(s); }
        if let Some(c) = channel { rfed["channel"] = json!(c); }

        json!({
            "aps": {
                "alert": { "title": self.alert_title, "body": self.alert_body },
                "sound": "default",
                "mutable-content": 1
            },
            "rfed": rfed
        })
        .to_string()
    }
}
