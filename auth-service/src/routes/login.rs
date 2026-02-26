use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode, UserStoreError},
    utils::auth::generate_auth_cookie,
};
use axum::{extract::State, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Ok(email) = Email::parse(request.email) else {
        return (CookieJar::new(), Err(AuthAPIError::InvalidCredentials));
    };

    let Ok(password) = Password::parse(request.password) else {
        return (CookieJar::new(), Err(AuthAPIError::InvalidCredentials));
    };

    let user_store = &state.user_store.read().await;

    if let Err(e) = user_store.validate_user(&email, &password).await {
        match e {
            UserStoreError::InvalidCredentials => {
                return (CookieJar::new(), Err(AuthAPIError::IncorrectCredentials))
            }
            _ => {}
        }
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    match user.requires_2fa {
        // We are now passing `&user.email` and `&state` to `handle_2fa`
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
    // Handle request based on user's 2FA configuration
    // match user.requires_2fa {
    //     true => handle_2fa(jar).await,
    //     false => handle_no_2fa(&user.email, jar).await,
    // }
}

async fn handle_2fa(
    email: &Email,    // New!
    state: &AppState, // New!
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let mut store = state.two_fa_code_store.write().await;
    if let Err(_) = store
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code)
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Return a TwoFactorAuthResponse. The message should be "2FA required".
    let resp = TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(),
    };

    let response = LoginResponse::TwoFactorAuth(resp);

    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::PARTIAL_CONTENT, Json(response))),
    )
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}
