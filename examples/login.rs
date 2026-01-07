/// Example demonstrating GitHub OAuth device flow authentication.
/// This program requests a device code, prompts the user to authorize,
/// and then polls for the access token.
use gh_oauth::*;

fn main() {
    // Replace "OAUTH_CLIENT_ID" with your actual GitHub OAuth app client ID
    let oauth = GitHubOAuth::new("OAUTH_CLIENT_ID", "repo read:user gist");

    // Step 1: Request device code from GitHub
    let prompt = oauth.request_device_code().unwrap();

    // Step 2: Display instructions to user
    println!("Visit: {}", prompt.verification_uri);
    println!("Code: {}", prompt.user_code);
    println!("Enter the code at the URL above to authorize this application.");

    // Step 3: Poll for access token until user authorizes
    let token = oauth.poll_token(&prompt).unwrap();

    // Step 4: Use the access token (in a real app, save it securely)
    println!("Access token: {}", token.access_token);
}
