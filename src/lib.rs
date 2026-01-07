/// A library for performing GitHub OAuth device flow authentication.
/// This allows applications to authenticate users via GitHub's device authorization flow,
/// which is suitable for CLI tools and headless applications.
///
/// # Example
/// ```
/// use gh_oauth::GitHubOAuth;
///
/// let oauth = GitHubOAuth::new("your_client_id", "repo user:email");
/// let prompt = oauth.request_device_code().unwrap();
/// // Display prompt.verification_uri and prompt.user_code to user
/// let token = oauth.poll_token(&prompt).unwrap();
/// // Use token.access_token for authenticated requests
/// ```
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    thread::sleep,
    time::{Duration, Instant},
};

/// GitHub's device code endpoint URL
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
/// GitHub's access token endpoint URL
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// GitHub OAuth client for device flow authentication.
/// Manages the OAuth process including requesting device codes and polling for tokens.
#[derive(Debug)]
pub struct GitHubOAuth {
    client_id: String,
    scopes: String,
    client: Client,
}

/// Response from GitHub when requesting a device code.
/// Contains the information needed to prompt the user for authorization.
#[derive(Debug, Deserialize)]
pub struct DevicePrompt {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// OAuth access token response from GitHub.
/// Contains the access token and associated metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

/// Errors that can occur during OAuth device flow.
/// Includes GitHub API errors and HTTP client errors.
#[derive(Debug)]
pub enum OAuthError {
    Expired,
    SlowDown,
    Pending,
    Other(String),
    Http(reqwest::Error),
}

impl GitHubOAuth {
    /// Creates a new GitHub OAuth client.
    ///
    /// # Arguments
    /// * `client_id` - Your GitHub OAuth app client ID
    /// * `scopes` - Space-separated list of OAuth scopes (e.g., "repo user:email")
    pub fn new(client_id: impl Into<String>, scopes: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            scopes: scopes.into(),
            client: Client::new(),
        }
    }

    /// Requests a device code from GitHub.
    /// This initiates the OAuth device flow by sending the client ID and scopes to GitHub.
    ///
    /// # Returns
    /// A `DevicePrompt` containing the user code, verification URI, and polling parameters.
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

    /// Polls GitHub for an access token using the device code.
    /// Continuously polls until the user authorizes or the code expires.
    ///
    /// # Arguments
    /// * `prompt` - The device prompt obtained from `request_device_code`
    ///
    /// # Returns
    /// An access token once the user completes authorization.
    pub fn poll_token(&self, prompt: &DevicePrompt) -> Result<Token, OAuthError> {
        let start = Instant::now();
        let mut interval = prompt.interval;

        loop {
            // Check if the device code has expired
            if start.elapsed().as_secs() > prompt.expires_in {
                return Err(OAuthError::Expired);
            }

            // Send polling request to GitHub
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

            // If successful, parse the token response
            if let Ok(token) = serde_json::from_str::<Token>(&text) {
                return Ok(token);
            }

            // Parse error response
            let err: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| OAuthError::Other(e.to_string()))?;

            // Handle different error types from GitHub
            match err["error"].as_str() {
                Some("authorization_pending") => {
                    // User hasn't authorized yet, wait and retry
                    sleep(Duration::from_secs(interval));
                }
                Some("slow_down") => {
                    // GitHub asking to slow down polling
                    interval += 5;
                    sleep(Duration::from_secs(interval));
                }
                Some(other) => {
                    // Other error, return it
                    return Err(OAuthError::Other(other.to_string()));
                }
                None => {
                    // Unexpected response format
                    return Err(OAuthError::Other("unknown response".into()));
                }
            }
        }
    }
}
