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
    println!("parsing token: {}", request.token);
    let Ok(token) = Token::parse(request.token) else {
        return Err(AuthAPIError::InvalidToken);
    };
    let store = state.banned_token_store.read().await;
    let result = store.contains(&token).await;
    println!("result: {:?}", result);
    match result {
        Ok(is_banned) => {
            if is_banned {
                println!("InvalidToken");
                Err(AuthAPIError::InvalidToken)
            } else {
                println!("Ok");
                Ok(StatusCode::OK)
            }
        }
        Err(_) => {
            println!("InvalidToken");
            Err(AuthAPIError::InvalidToken)
        }
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
