use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStoreError},
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

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

async fn handle_2fa(
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Return a TwoFactorAuthResponse. The message should be "2FA required".
    // The login attempt ID should be "123456". We will replace this hard-coded login attempt ID soon!
    let resp = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: "123456".to_string(),
    };
    let response = LoginResponse::TwoFactorAuth(resp);
    (jar, Ok((StatusCode::PARTIAL_CONTENT, Json(response))))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}
