use gh_oauth::*;

fn main() {
    let oauth = GitHubOAuth::new("OAUTH_CLIENT_ID", "repo read:user gist");

    let prompt = oauth.request_device_code().unwrap();

    println!("Visit: {}", prompt.verification_uri);
    println!("Code: {}", prompt.user_code);

    let token = oauth.poll_token(&prompt).unwrap();

    println!("Access token: {}", token.access_token);
}
