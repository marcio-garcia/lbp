use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Token},
};
use axum::{extract::State, response::IntoResponse, Json};
use reqwest::StatusCode;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[tracing::instrument(name = "verify_token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = request.token;
    let Ok(_) = Token::parse(token.clone()) else {
        return Err(AuthAPIError::InvalidToken);
    };
    let token_secret = SecretString::new(token.into_boxed_str());
    let store = state.banned_token_store.read().await;
    let result = store.contains_token(&token_secret).await;
    match result {
        Ok(is_banned) => {
            if is_banned {
                Err(AuthAPIError::InvalidToken)
            } else {
                Ok(StatusCode::OK)
            }
        }
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    pub message: String,
}
