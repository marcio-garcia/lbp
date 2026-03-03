use crate::helpers::{create_user, TestApp};
use auth_service::{domain::Token, utils::constants::JWT_COOKIE_NAME};
use reqwest::Url;
use secrecy::SecretString;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400, "Failed for missing cookie")
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    let login_resp = create_user(&app, false).await;
    let auth_cookie = login_resp
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    let token_str = auth_cookie.value().to_owned();
    assert!(!token_str.is_empty());
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200, "Valid Token");
    let token_store = app.banned_token_store.read().await;
    let Ok(token) = Token::parse(token_str) else {
        panic!("Invalid token")
    };
    let token_secret = SecretString::new(token.as_str().to_owned().into_boxed_str());
    let contains = token_store.contains_token(&token_secret).await;
    assert!(contains.ok().unwrap())
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401, "Failed for invalid token")
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;
    let login_resp = create_user(&app, false).await;
    let auth_cookie = login_resp
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
    let _ = app.post_logout().await;
    let response2 = app.post_logout().await;
    assert_eq!(
        response2.status().as_u16(),
        400,
        "Failed for calling logout twice"
    )
}
