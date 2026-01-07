# GitHub OAuth for Rust

[![Crates.io Version](https://img.shields.io/crates/v/gh-oauth?style=for-the-badge&logo=rust&color=black)](https://crates.io/crates/gh-oauth)

A very simple library for Rust client applications that need to perform OAuth authorization against GitHub.

Based on https://github.com/cli/oauth

### Usage

- [Register your application](https://github.com/settings/applications/new) on GitHub to get your Client ID.
- Use your Client ID to perform the authorization:

```rust
use gh_oauth::*;

fn main() {
    let oauth = GitHubOAuth::new("OAUTH_CLIENT_ID", "repo read:user gist");

    let prompt = oauth.request_device_code().unwrap();

    println!("Visit: {}", prompt.verification_uri);
    println!("Code: {}", prompt.user_code);

    let token = oauth.poll_token(&prompt).unwrap();

    println!("Access token: {}", token.access_token);
}
```
