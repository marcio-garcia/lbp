use crate::helpers::{get_random_email, TestApp};
use auth_service::{domain::Email, utils::auth::generate_auth_cookie};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let input = serde_json::json!({
        "tok": "token_string",
    });
    let response = app.post_verify_token(&input).await;
    assert_eq!(
        response.status().as_u16(),
        422,
        "Failed for input: {:?}",
        input
    );
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    let email_str = get_random_email();
    let Ok(email) = Email::parse(email_str) else {
        panic!("invalid email");
    };
    let Ok(token) = generate_auth_cookie(&email) else {
        panic!("could not generate token");
    };
    let input = serde_json::json!({
        "token": token.value().to_owned(),
    });
    let response = app.post_verify_token(&input).await;
    assert_eq!(response.status().as_u16(), 200, "Valid token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let input = serde_json::json!({
        "token": "invalid_token",
    });
    let response = app.post_verify_token(&input).await;
    assert_eq!(response.status().as_u16(), 401, "Failed for invalid token")
}
