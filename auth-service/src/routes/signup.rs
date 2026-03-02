use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, HashedPassword, User, UserStoreError},
};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let Ok(email) = Email::parse(request.email) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    let password = HashedPassword::parse(request.password)
        .await
        .map_err(|err| {
            if matches!(
                err.downcast_ref::<AuthAPIError>(),
                Some(AuthAPIError::InvalidCredentials)
            ) {
                AuthAPIError::InvalidCredentials
            } else {
                AuthAPIError::UnexpectedError(err)
            }
        })?;

    // Create a new `User` instance using data in the `request`
    let user = User {
        email,
        password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;
    let result = user_store.add_user(user).await;
    match result {
        Ok(_) => {}
        Err(e) => match e {
            UserStoreError::UserAlreadyExists => return Err(AuthAPIError::UserAlreadyExists),
            UserStoreError::UnexpectedError(err) => {
                return Err(AuthAPIError::UnexpectedError(err.into()))
            }
            _ => {}
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
