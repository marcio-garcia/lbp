use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Token},
};
use axum::{extract::State, response::IntoResponse, Json};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let Ok(token) = Token::parse(request.token) else {
        return Err(AuthAPIError::InvalidToken);
    };
    let store = state.banned_token_store.read().await;
    if store.contains(&token).await {
        return Err(AuthAPIError::InvalidToken);
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    pub message: String,
}
