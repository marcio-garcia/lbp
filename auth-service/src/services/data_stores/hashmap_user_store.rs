use crate::domain::{Email, User, UserStore, UserStoreError};
use async_trait::async_trait;
use secrecy::SecretString;
use std::collections::HashMap;

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

impl HashmapUserStore {}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> color_eyre::Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> color_eyre::Result<User, UserStoreError> {
        if let Some(user) = self.users.get(email) {
            return Ok(user.clone());
        }
        return Err(UserStoreError::UserNotFound);
    }

    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> color_eyre::Result<(), UserStoreError> {
        let user: &User = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;
        user.password // updated password verification
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use crate::domain::HashedPassword;

    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();

        let Ok(email) = Email::parse("test@example.com".to_string().into()) else {
            panic!("Invalid email");
        };
        let raw_password = "secretpass";
        let secret_str = SecretString::new(raw_password.to_owned().into_boxed_str());
        let Ok(password) = HashedPassword::parse(secret_str).await else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), false);

        let result = store.add_user(user).await;
        assert!(result.is_ok());

        let duplicate = User::new(email, password, false);
        let result = store.add_user(duplicate).await;
        assert_eq!(result.err().unwrap(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();

        let Ok(email) = Email::parse("test@example.com".to_string().into()) else {
            panic!("Invalid email");
        };
        let raw_password = "secretpass";
        let secret_str = SecretString::new(raw_password.to_owned().into_boxed_str());
        let Ok(password) = HashedPassword::parse(secret_str).await else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), true);

        let result = store.add_user(user).await;
        assert!(result.is_ok());

        let result = store.get_user(&email).await;
        assert!(result.is_ok());
        let fetched = result.unwrap();
        assert_eq!(email, fetched.email);
        assert_eq!(password, fetched.password);
        assert!(fetched.requires_2fa);

        let Ok(email) = Email::parse("missing@example.com".to_string().into()) else {
            panic!("Invalid email");
        };

        let result = store.get_user(&email).await;
        assert_eq!(result.err().unwrap(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let raw_password = "secretpass";
        let wrong_raw_password = "wrongpass";
        let Ok(email) = Email::parse("test@example.com".to_string().into()) else {
            panic!("Invalid email");
        };
        let secret_str = SecretString::new(raw_password.to_owned().into_boxed_str());
        let Ok(password) = HashedPassword::parse(secret_str).await else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), false);
        let result = store.add_user(user).await;
        assert!(result.is_ok());

        let Ok(email2) = Email::parse("missing@example.com".to_string().into()) else {
            panic!("Invalid email");
        };

        let raw_password = SecretString::new(raw_password.to_owned().into_boxed_str());
        let wrong_raw_password = SecretString::new(wrong_raw_password.to_owned().into_boxed_str());

        let result = store.validate_user(&email, &raw_password).await;
        assert!(result.is_ok());

        let valid1 = store.validate_user(&email, &wrong_raw_password).await;
        assert_eq!(valid1.err().unwrap(), UserStoreError::InvalidCredentials);

        let valid2 = store.validate_user(&email2, &raw_password).await;
        assert_eq!(valid2.err().unwrap(), UserStoreError::UserNotFound);
    }
}
