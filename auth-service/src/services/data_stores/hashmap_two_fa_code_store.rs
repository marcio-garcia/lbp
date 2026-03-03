use async_trait::async_trait;
use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        if let Some(code) = self.codes.get(email) {
            return Ok(code.clone());
        } else {
            Err(TwoFACodeStoreError::LoginAttemptIdNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn email(value: &str) -> Email {
        Email::parse(value.to_string().into()).expect("valid email")
    }

    fn login_attempt_id(value: &str) -> LoginAttemptId {
        LoginAttemptId::parse(value.to_string().into()).expect("valid login attempt id")
    }

    fn two_fa_code(value: &str) -> TwoFACode {
        TwoFACode::parse(value.to_string().into()).expect("valid 2FA code")
    }

    #[tokio::test]
    async fn add_and_get_code_returns_stored_values() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = email("test@example.com");
        let login_attempt_id = login_attempt_id(&Uuid::new_v4().to_string());
        let code = two_fa_code("123456");

        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert_eq!(Ok(()), result);

        let fetched = store.get_code(&email).await;
        assert_eq!(Ok((login_attempt_id, code)), fetched);
    }

    #[tokio::test]
    async fn get_code_for_missing_email_returns_not_found() {
        let store = HashmapTwoFACodeStore::default();
        let email = email("missing@example.com");

        let result = store.get_code(&email).await;
        assert_eq!(Err(TwoFACodeStoreError::LoginAttemptIdNotFound), result);
    }

    #[tokio::test]
    async fn remove_code_deletes_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = email("remove@example.com");

        store
            .add_code(
                email.clone(),
                login_attempt_id(&Uuid::new_v4().to_string()),
                two_fa_code("111111"),
            )
            .await
            .expect("add_code should succeed");

        let remove_result = store.remove_code(&email).await;
        assert_eq!(Ok(()), remove_result);

        let fetched = store.get_code(&email).await;
        assert_eq!(Err(TwoFACodeStoreError::LoginAttemptIdNotFound), fetched);
    }

    #[tokio::test]
    async fn add_code_overwrites_existing_value_for_same_email() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = email("overwrite@example.com");

        store
            .add_code(
                email.clone(),
                login_attempt_id(&Uuid::new_v4().to_string()),
                two_fa_code("222222"),
            )
            .await
            .expect("first add_code should succeed");

        let second_login_attempt_id = login_attempt_id(&Uuid::new_v4().to_string());
        let second_code = two_fa_code("333333");

        store
            .add_code(
                email.clone(),
                second_login_attempt_id.clone(),
                second_code.clone(),
            )
            .await
            .expect("second add_code should succeed");

        let fetched = store.get_code(&email).await;
        assert_eq!(Ok((second_login_attempt_id, second_code)), fetched);
    }
}
