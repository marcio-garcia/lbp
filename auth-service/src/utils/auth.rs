use super::constants::JWT_COOKIE_NAME;
use crate::domain::{email::Email, BannedTokenStore, Token};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{eyre, Context, ContextCompat};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// This is definitely NOT a good secret. We will update it soon!
const JWT_SECRET: &str = "secret";

// Create cookie with a new JWT auth token
#[tracing::instrument(name = "generate_auth_cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> color_eyre::Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
#[tracing::instrument(name = "create_auth_cookie", skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
#[tracing::instrument(name = "generate_auth_token", skip_all)]
fn generate_auth_token(email: &Email) -> color_eyre::Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
        "failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().to_owned();

    let claims = Claims {
        sub,
        exp,
        jti: Some(Uuid::new_v4().to_string()),
    };

    create_token(&claims)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
#[tracing::instrument(name = "validate_token", skip_all)]
pub async fn validate_token<T: BannedTokenStore>(
    token: &String,
    banned_tokens: T,
) -> color_eyre::Result<Claims> {
    let claims = validate_structure(token)?;
    let tok = Token::parse(token.clone())?;

    if check_banned(&tok, banned_tokens).await {
        return Err(eyre!("token is banned"));
    }
    Ok(claims)
}

#[tracing::instrument(name = "validate_structure", skip_all)]
pub fn validate_structure(token: &String) -> color_eyre::Result<Claims> {
    let c = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;

    Ok(c.claims)
}

#[tracing::instrument(name = "check_banned", skip_all)]
async fn check_banned<T: BannedTokenStore>(token: &Token, banned_tokens: T) -> bool {
    if let Ok(val) = banned_tokens.contains(token).await {
        val
    } else {
        false
    }
}

// Create JWT auth token by encoding claims using the JWT secret
#[tracing::instrument(name = "create_token", skip_all)]
fn create_token(claims: &Claims) -> color_eyre::Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(default)]
    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::services::data_stores::HashsetBannedTokenStore;

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token_str = generate_auth_token(&email).unwrap();
        let Ok(token) = Token::parse(token_str) else {
            panic!("Invalid token")
        };
        let token_store = HashsetBannedTokenStore::new();
        let result = validate_token(&token.as_str().to_string(), token_store)
            .await
            .unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token_str = "invalid_token".to_owned();
        let token_store = HashsetBannedTokenStore::new();
        let result = validate_token(&token_str, token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token_str = generate_auth_token(&email).unwrap();
        let Ok(token) = Token::parse(token_str) else {
            panic!("Invalid token")
        };

        let mut token_store = HashsetBannedTokenStore::new();
        if let Err(e) = token_store.add_token(token.clone()).await {
            panic!("Could not add token to banned list. {:?}", e)
        }

        let result = validate_token(&token.as_str().to_string(), token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_auth_token_is_unique_for_same_user() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token1 = generate_auth_token(&email).unwrap();
        let token2 = generate_auth_token(&email).unwrap();
        assert_ne!(token1, token2);
    }
}
