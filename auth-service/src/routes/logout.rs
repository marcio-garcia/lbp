use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token = cookie.value().to_owned();

    if let Err(_) = validate_token(&token).await {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let jar = jar.remove(JWT_COOKIE_NAME);

    (jar, Ok(StatusCode::OK))
}
