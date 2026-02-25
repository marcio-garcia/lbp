use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, UserStoreError}, utils::auth::generate_auth_cookie};

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
            UserStoreError::InvalidCredentials => return (CookieJar::new(), Err(AuthAPIError::IncorrectCredentials)),
            _ => {}
        }
    }

    let result = user_store.get_user(&email).await;
    if let Err(_) = result {
        return (CookieJar::new(), Err(AuthAPIError::IncorrectCredentials));
    }

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (CookieJar::new(), Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))

}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub message: String,
}
