//! FCM HTTP v1 data-only push sender.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::FcmConfig;
use crate::jwt::GoogleJwt;

const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize)]
struct ServiceAccountFile {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default)]
    token_uri: Option<String>,
}

#[derive(Default)]
struct AccessTokenCache {
    token: Option<String>,
    expires_at: u64,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
}

pub struct FcmSender {
    project_id: String,
    app_package_name: String,
    token_uri: String,
    client: Client,
    jwt: Mutex<GoogleJwt>,
    token_cache: Mutex<AccessTokenCache>,
}

pub struct SendResult {
    pub success: bool,
    pub http_code: u16,
    pub reason: Option<String>,
}

impl FcmSender {
    pub fn new(cfg: &FcmConfig, service_account_key: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(service_account_key)
            .map_err(|e| format!("cannot read service account file {}: {e}", service_account_key.display()))?;
        let account: ServiceAccountFile = serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse service account JSON: {e}"))?;
        if cfg.app_package_name.trim().is_empty() {
            return Err("fcm.app_package_name must not be empty".to_string());
        }

        let token_uri = account
            .token_uri
            .clone()
            .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_string());

        let client = reqwest::blocking::ClientBuilder::new()
            .use_rustls_tls()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let jwt = GoogleJwt::new(
            &account.private_key,
            &account.client_email,
            &token_uri,
            OAUTH_SCOPE,
            cfg.token_ttl,
        )?;

        Ok(FcmSender {
            project_id: account.project_id,
            app_package_name: cfg.app_package_name.clone(),
            token_uri,
            client,
            jwt: Mutex::new(jwt),
            token_cache: Mutex::new(AccessTokenCache::default()),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn send(
        &self,
        fcm_token: &str,
        receiver_hex: &str,
        sender_hex: Option<&str>,
        channel_hex: Option<&str>,
    ) -> SendResult {
        let access_token = match self.access_token() {
            Ok(token) => token,
            Err(e) => {
                return SendResult {
                    success: false,
                    http_code: 0,
                    reason: Some(e),
                };
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );
        let body = self.build_payload(fcm_token, receiver_hex, sender_hex, channel_hex);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send();

        match resp {
            Err(e) => SendResult {
                success: false,
                http_code: 0,
                reason: Some(e.to_string()),
            },
            Ok(r) => {
                let code = r.status().as_u16();
                let text = r.text().unwrap_or_default();
                if code == 200 {
                    SendResult {
                        success: true,
                        http_code: 200,
                        reason: None,
                    }
                } else {
                    SendResult {
                        success: false,
                        http_code: code,
                        reason: extract_fcm_error(&text).or_else(|| {
                            let trimmed = text.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        }),
                    }
                }
            }
        }
    }

    pub fn should_invalidate(http_code: u16, reason: Option<&str>) -> bool {
        match (http_code, reason) {
            (400 | 404, Some(reason)) => {
                let reason = reason.to_ascii_uppercase();
                reason.contains("UNREGISTERED")
                    || reason.contains("REGISTRATION_TOKEN_NOT_REGISTERED")
            }
            _ => false,
        }
    }

    fn access_token(&self) -> Result<String, String> {
        let now = now_secs();
        if let Some(token) = {
            let cache = self.token_cache.lock().unwrap_or_else(|e| e.into_inner());
            if cache.token.is_some() && (now + 60) < cache.expires_at {
                cache.token.clone()
            } else {
                None
            }
        } {
            return Ok(token);
        }

        let assertion = self
            .jwt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generate_assertion()?;

        let response = self
            .client
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .map_err(|e| format!("oauth token exchange failed: {e}"))?;

        let code = response.status().as_u16();
        let text = response.text().unwrap_or_default();
        if code != 200 {
            let reason = extract_fcm_error(&text).unwrap_or_else(|| text.trim().to_string());
            return Err(format!("oauth token exchange failed: HTTP {code} {reason}"));
        }

        let parsed: AccessTokenResponse = serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse oauth token response: {e}"))?;
        let expires_at = now + parsed.expires_in;

        let mut cache = self.token_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.token = Some(parsed.access_token.clone());
        cache.expires_at = expires_at;
        Ok(parsed.access_token)
    }

    fn build_payload(
        &self,
        fcm_token: &str,
        receiver_hex: &str,
        sender_hex: Option<&str>,
        channel_hex: Option<&str>,
    ) -> Value {
        let mut data = Map::new();
        data.insert("receiver".to_string(), Value::String(receiver_hex.to_string()));
        if let Some(sender) = sender_hex {
            data.insert("sender".to_string(), Value::String(sender.to_string()));
        }
        if let Some(channel) = channel_hex {
            data.insert("channel".to_string(), Value::String(channel.to_string()));
        }

        json!({
            "message": {
                "token": fcm_token,
                "data": data,
                "android": {
                    "priority": "HIGH",
                    "restricted_package_name": self.app_package_name,
                    "ttl": "30s"
                }
            }
        })
    }
}

fn extract_fcm_error(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    if let Some(details) = value
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.as_array())
    {
        for detail in details {
            if let Some(error_code) = detail.get("errorCode").and_then(|c| c.as_str()) {
                return Some(error_code.to_string());
            }
        }
    }

    value
        .get("error")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(|m| m.to_string())
        })
}