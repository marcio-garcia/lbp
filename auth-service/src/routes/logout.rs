use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Token},
    utils::{auth::validate_structure, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token_str = cookie.value().to_owned();

    let mut banned_token_store = state.banned_token_store.write().await;

    if let Err(_) = validate_structure(&token_str) {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let Ok(token) = Token::parse(token_str) else {
        return (jar, Err(AuthAPIError::InvalidToken));
    };

    if let Err(e) = banned_token_store.add_token(token).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let jar = jar.remove(JWT_COOKIE_NAME);

    (jar, Ok(StatusCode::OK))
}
