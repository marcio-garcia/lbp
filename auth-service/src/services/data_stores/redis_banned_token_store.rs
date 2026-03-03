use async_trait::async_trait;
use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    domain::{
        data_stores::{BannedTokenStore, BannedTokenStoreError},
    },
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        let key = get_key(token.expose_secret());
        let mut connection = self.conn.write().await;
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        let _: () = connection
            .set_ex(key, true, ttl)
            .wrap_err("failed to set banned token in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        let mut connection = self.conn.write().await;
        let key = get_key(token.expose_secret());
        let is_banned: bool = connection
            .exists(key)
            .wrap_err("failed to check if token exists in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        Ok(is_banned)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::{Email, Token},
        get_redis_client,
        utils::{auth::generate_auth_cookie, constants::REDIS_HOST_NAME},
    };
    use secrecy::SecretString;

    use super::*;

    fn configure_redis() -> Result<redis::Connection, String> {
        let client = get_redis_client(REDIS_HOST_NAME.to_owned())
            .map_err(|e| format!("Failed to get Redis client: {e}"))?;
        client
            .get_connection()
            .map_err(|e| format!("Failed to get Redis connection: {e}"))
    }

    #[tokio::test]
    async fn test_add_token() {
        let redis_conn = match configure_redis() {
            Ok(conn) => Arc::new(RwLock::new(conn)),
            Err(e) => {
                eprintln!("WARN: skipping test_add_token because Redis is unavailable: {e}");
                return;
            }
        };
        let mut store = RedisBannedTokenStore::new(redis_conn);

        let Ok(email) = Email::parse("test@example.com".to_string().into()) else {
            panic!("Invalid email");
        };

        let Ok(cookie) = generate_auth_cookie(&email) else {
            panic!("could not generate token")
        };

        let token_str = cookie.value().to_owned();

        let Ok(token) = Token::parse(token_str) else {
            panic!("could not create token")
        };

        let token_secret = SecretString::new(token.as_str().to_owned().into_boxed_str());
        let result = store.add_token(token_secret).await;
        assert_eq!((), result.ok().unwrap());
    }

    #[tokio::test]
    async fn test_contain_token() {
        let redis_conn = match configure_redis() {
            Ok(conn) => Arc::new(RwLock::new(conn)),
            Err(e) => {
                eprintln!("WARN: skipping test_contain_token because Redis is unavailable: {e}");
                return;
            }
        };
        let mut store = RedisBannedTokenStore::new(redis_conn);

        let Ok(email) = Email::parse("test@example.com".to_string().into()) else {
            panic!("Invalid email");
        };
        let Ok(cookie) = generate_auth_cookie(&email) else {
            panic!("could not generate token")
        };
        let token_str = cookie.value().to_owned();
        let Ok(token) = Token::parse(token_str) else {
            panic!("could not create token")
        };
        let token_secret = SecretString::new(token.as_str().to_owned().into_boxed_str());
        let result = store.add_token(token_secret.clone()).await;
        assert_eq!((), result.ok().unwrap());

        let exists = store.contains_token(&token_secret).await;
        assert!(exists.ok().unwrap());
    }
}
