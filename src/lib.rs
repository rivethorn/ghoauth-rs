use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    thread::sleep,
    time::{Duration, Instant},
};

const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Debug)]
pub struct GitHubOAuth {
    client_id: String,
    scopes: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
pub struct DevicePrompt {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

#[derive(Debug)]
pub enum OAuthError {
    Expired,
    SlowDown,
    Pending,
    Other(String),
    Http(reqwest::Error),
}

impl GitHubOAuth {
    pub fn new(client_id: impl Into<String>, scopes: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            scopes: scopes.into(),
            client: Client::new(),
        }
    }

    pub fn request_device_code(&self) -> Result<DevicePrompt, OAuthError> {
        self.client
            .post(DEVICE_CODE_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", self.scopes.as_str()),
            ])
            .send()
            .map_err(OAuthError::Http)?
            .json()
            .map_err(OAuthError::Http)
    }

    pub fn poll_token(&self, prompt: &DevicePrompt) -> Result<Token, OAuthError> {
        let start = Instant::now();
        let mut interval = prompt.interval;

        loop {
            if start.elapsed().as_secs() > prompt.expires_in {
                return Err(OAuthError::Expired);
            }

            let resp = self
                .client
                .post(TOKEN_URL)
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("device_code", prompt.device_code.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ])
                .send()
                .map_err(OAuthError::Http)?;

            let text = resp.text().map_err(OAuthError::Http)?;

            if let Ok(token) = serde_json::from_str::<Token>(&text) {
                return Ok(token);
            }

            let err: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| OAuthError::Other(e.to_string()))?;

            match err["error"].as_str() {
                Some("authorization_pending") => {
                    sleep(Duration::from_secs(interval));
                }
                Some("slow_down") => {
                    interval += 5;
                    sleep(Duration::from_secs(interval));
                }
                Some(other) => {
                    return Err(OAuthError::Other(other.to_string()));
                }
                None => {
                    return Err(OAuthError::Other("unknown response".into()));
                }
            }
        }
    }
}
