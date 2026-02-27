use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use uuid::Uuid;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "loginAttemptId": Uuid::new_v4().to_string(),
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "user@example.com",
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "user@example.com",
            "loginAttemptId": Uuid::new_v4().to_string(),
        }),
    ];

    for body in test_cases {
        let response = app.post_verify_2fa(&body).await;
        assert_eq!(response.status().as_u16(), 422, "Failed for input {}", body);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "not-an-email",
            "loginAttemptId": Uuid::new_v4().to_string(),
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "user@example.com",
            "loginAttemptId": "not-a-uuid",
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "user@example.com",
            "loginAttemptId": Uuid::new_v4().to_string(),
            "2FACode": "abc123",
        }),
    ];

    for body in test_cases {
        let response = app.post_verify_2fa(&body).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input {}", body);
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": Uuid::new_v4().to_string(),
        "2FACode": "123456",
    });

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 401, "Failed for input {}", body);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
    let email = get_random_email();

    let signup_body = serde_json::json!({
        "email": email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });

    let first_login_response = app.post_login(&login_body).await;
    assert_eq!(first_login_response.status().as_u16(), 206);
    let first_login_json = first_login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize first login response body");

    let parsed_email = Email::parse(email.to_string()).expect("valid email");
    let store = app.two_fa_code_store.read().await;
    let Ok((_, first_code)) = store.get_code(&parsed_email).await else {
        panic!("Could not fetch 2FA code for first login")
    };
    drop(store);

    let second_login_response = app.post_login(&login_body).await;
    assert_eq!(second_login_response.status().as_u16(), 206);

    let verify_body = serde_json::json!({
        "email": email,
        "loginAttemptId": first_login_json.login_attempt_id,
        "2FACode": first_code.as_ref(),
    });
    let response = app.post_verify_2fa(&verify_body).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input {}",
        verify_body
    );
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    let email = get_random_email();

    let signup_body = serde_json::json!({
        "email": email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 206);
    let login_json = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response body");

    let parsed_email = Email::parse(email.to_string()).expect("valid email");
    let store = app.two_fa_code_store.read().await;
    let Ok((_, code)) = store.get_code(&parsed_email).await else {
        panic!("Could not fetch 2FA code")
    };
    let code = code.as_ref().to_owned();
    drop(store);

    let verify_body = serde_json::json!({
        "email": email,
        "loginAttemptId": login_json.login_attempt_id,
        "2FACode": code,
    });
    let response = app.post_verify_2fa(&verify_body).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input {}",
        verify_body
    );

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    let email = get_random_email();

    let signup_body = serde_json::json!({
        "email": email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 206);
    let login_json = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response body");

    let parsed_email = Email::parse(email.to_string()).expect("valid email");
    let store = app.two_fa_code_store.read().await;
    let Ok((_, code)) = store.get_code(&parsed_email).await else {
        panic!("Could not fetch 2FA code")
    };
    let code = code.as_ref().to_owned();
    drop(store);

    let verify_body = serde_json::json!({
        "email": email,
        "loginAttemptId": login_json.login_attempt_id,
        "2FACode": code,
    });
    let response = app.post_verify_2fa(&verify_body).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input {}",
        verify_body
    );

    let response2 = app.post_verify_2fa(&verify_body).await;

    assert_eq!(
        response2.status().as_u16(),
        401,
        "Failed for input {}",
        verify_body
    );
}
