use axum::{Json, extract::State, response::IntoResponse};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, UserStoreError}};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let Ok(email) = Email::parse(request.email) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    let Ok(password) = Password::parse(request.password) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    let user_store = &state.user_store.read().await;

    if let Err(e) = user_store.validate_user(&email, &password).await {
        match e {
            UserStoreError::InvalidCredentials => return Err(AuthAPIError::IncorrectCredentials),
            _ => {}
        }
    }

    let _ = user_store.get_user(&email).await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok(StatusCode::OK.into_response())

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
