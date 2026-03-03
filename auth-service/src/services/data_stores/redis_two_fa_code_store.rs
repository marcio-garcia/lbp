use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Commands, Connection, RedisError};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "add_code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let data = TwoFATuple(
            login_attempt_id.as_ref().expose_secret().to_string(),
            code.as_ref().expose_secret().to_string(),
        );

        let serialized_data = serde_json::to_string(&data)
            .wrap_err("failed to serialize 2FA tuple") // New!
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        let mut connection = self.conn.write().await;
        let sec = match u64::try_from(TEN_MINUTES_IN_SECONDS) {
            Ok(v) => v,
            Err(e) => return Err(TwoFACodeStoreError::UnexpectedError(e.into())),
        };

        let _: () = connection
            .set_ex(key, serialized_data, sec)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "remove_code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut connection = self.conn.write().await;
        let _: () = connection
            .del(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "get_code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut c = self.conn.write().await;
        let result: Result<String, RedisError> = c.get(key);
        match result {
            Ok(json_str) => {
                let data: TwoFATuple = serde_json::from_str(&json_str)
                    .wrap_err("failed to deserialize 2FA tuple")
                    .map_err(TwoFACodeStoreError::UnexpectedError)?;

                let login_attempt_id =
                    LoginAttemptId::parse(data.0.into()).map_err(TwoFACodeStoreError::UnexpectedError)?;
                let two_fa_code =
                    TwoFACode::parse(data.1.into()).map_err(TwoFACodeStoreError::UnexpectedError)?;
                Ok((login_attempt_id, two_fa_code))
            }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::TwoFACodeStoreError, get_redis_client, utils::constants::REDIS_HOST_NAME};
    use uuid::Uuid;

    fn configure_redis() -> Result<redis::Connection, String> {
        let client = get_redis_client(REDIS_HOST_NAME.to_owned())
            .map_err(|e| format!("Failed to get Redis client: {e}"))?;
        client
            .get_connection()
            .map_err(|e| format!("Failed to get Redis connection: {e}"))
    }

    fn test_email(prefix: &str) -> Email {
        Email::parse(format!("{prefix}.{}@example.com", Uuid::new_v4()).into()).expect("valid email")
    }

    #[tokio::test]
    async fn test_add_and_get_code() {
        let redis_conn = match configure_redis() {
            Ok(conn) => Arc::new(RwLock::new(conn)),
            Err(e) => {
                eprintln!("WARN: skipping test_add_and_get_code because Redis is unavailable: {e}");
                return;
            }
        };
        let mut store = RedisTwoFACodeStore::new(redis_conn);

        let email = test_email("add_get");
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let add_result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert_eq!(Ok(()), add_result);

        let fetched = store.get_code(&email).await;
        assert_eq!(Ok((login_attempt_id, code)), fetched);
    }

    #[tokio::test]
    async fn test_remove_code() {
        let redis_conn = match configure_redis() {
            Ok(conn) => Arc::new(RwLock::new(conn)),
            Err(e) => {
                eprintln!("WARN: skipping test_remove_code because Redis is unavailable: {e}");
                return;
            }
        };
        let mut store = RedisTwoFACodeStore::new(redis_conn);

        let email = test_email("remove");

        let add_result = store
            .add_code(
                email.clone(),
                LoginAttemptId::default(),
                TwoFACode::default(),
            )
            .await;
        assert_eq!(Ok(()), add_result);

        let remove_result = store.remove_code(&email).await;
        assert_eq!(Ok(()), remove_result);

        let fetched = store.get_code(&email).await;
        assert_eq!(Err(TwoFACodeStoreError::LoginAttemptIdNotFound), fetched);
    }

    #[tokio::test]
    async fn test_get_code_missing_email() {
        let redis_conn = match configure_redis() {
            Ok(conn) => Arc::new(RwLock::new(conn)),
            Err(e) => {
                eprintln!(
                    "WARN: skipping test_get_code_missing_email because Redis is unavailable: {e}"
                );
                return;
            }
        };
        let store = RedisTwoFACodeStore::new(redis_conn);
        let email = test_email("missing");

        let result = store.get_code(&email).await;
        assert_eq!(Err(TwoFACodeStoreError::LoginAttemptIdNotFound), result);
    }
}
