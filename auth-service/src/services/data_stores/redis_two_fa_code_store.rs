use std::sync::Arc;

use redis::{Commands, Connection, RedisError};
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
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let fa = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );

        let Ok(json_str) = serde_json::to_string(&fa) else {
            return Err(TwoFACodeStoreError::UnexpectedError);
        };

        let mut c = self.conn.write().await;
        let sec = match u64::try_from(TEN_MINUTES_IN_SECONDS) {
            Ok(v) => v,
            Err(_) => return Err(TwoFACodeStoreError::UnexpectedError),
        };

        let result: Result<(), RedisError> = c.set_ex(key, json_str, sec);
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut c = self.conn.write().await;
        let result: Result<(), RedisError> = c.del(key);
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut c = self.conn.write().await;
        let result: Result<String, RedisError> = c.get(key);
        match result {
            Ok(json_str) => {
                let dec: Result<TwoFATuple, serde_json::Error> = serde_json::from_str(&json_str);
                let two_fa_tuple = match dec {
                    Ok(t) => t,
                    Err(_) => return Err(TwoFACodeStoreError::UnexpectedError),
                };
                let login_attempt_id = LoginAttemptId::parse(two_fa_tuple.0)
                    .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
                let two_fa_code = TwoFACode::parse(two_fa_tuple.1)
                    .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
                Ok((login_attempt_id, two_fa_code))
            }
            Err(_) => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
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
        Email::parse(format!("{prefix}.{}@example.com", Uuid::new_v4())).expect("valid email")
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
        assert_eq!(Err(TwoFACodeStoreError::UnexpectedError), fetched);
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
        assert_eq!(Err(TwoFACodeStoreError::UnexpectedError), result);
    }
}
