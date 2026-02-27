use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[derive(Serialize)]
pub struct Verify2FAResponse {
    pub message: String,
}

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Ok(email) = Email::parse(request.email) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let Ok(login_attempt_id) = LoginAttemptId::parse(request.login_attempt_id) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let Ok(two_fa_code) = TwoFACode::parse(request.two_fa_code) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    // Call `two_fa_code_store.get_code`. If the call fails
    // return a `AuthAPIError::IncorrectCredentials`.
    let Ok(code_tuple) = two_fa_code_store.get_code(&email).await else {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };

    // Validate that the `login_attempt_id` and `two_fa_code`
    // in the request body matches values in the `code_tuple`.
    // If not, return a `AuthAPIError::IncorrectCredentials`.
    if login_attempt_id != code_tuple.0 || two_fa_code != code_tuple.1 {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    if let Err(_) = two_fa_code_store.remove_code(&email).await {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    }

    (updated_jar, Ok(StatusCode::OK.into_response()))
}
