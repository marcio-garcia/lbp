use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Token},
};
use axum::{extract::State, response::IntoResponse, Json};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

pub async fn verify_token(
    State(_state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    println!("********verify_token, token {}", request.token.clone());
    let Ok(_) = Token::parse(request.token).await else {
        return Err(AuthAPIError::InvalidToken);
    };
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
