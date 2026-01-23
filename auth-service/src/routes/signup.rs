use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, User, UserStoreError}};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {

    let Ok(email) = Email::parse(request.email) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    let Ok(password) = Password::parse(request.password) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    // Create a new `User` instance using data in the `request`
    let user = User {
        email,
        password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    let result = user_store.add_user(user).await;

    match result {
        Ok(_) => {},
        Err(e) => {
            match e {
                UserStoreError::UserAlreadyExists => return Err(AuthAPIError::UserAlreadyExists),
                UserStoreError::UnexpectedError => return Err(AuthAPIError::UnexpectedError),
                _ => {}
            }
         },
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}
