use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::{User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let result = self.get_user(&user.email).await;
        match result {
            Ok(_) => return Err(UserStoreError::UserAlreadyExists),
            Err(e) => {
                if e == UserStoreError::UserNotFound {
                    self.users.insert(user.email.clone(), user);
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        }
    }

    async fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        if let Some(user) = self.users.get(email) {
            return Ok(user);
        }
        return Err(UserStoreError::UserNotFound);
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(email) {
            if user.password == password {
                return Ok(());
            } else {
                return Err(UserStoreError::InvalidCredentials);
            }
        }
        return Err(UserStoreError::UserNotFound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "secret".to_string(), false);

        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let duplicate = User::new("test@example.com".to_string(), "secret".to_string(), false);
        let result = store.add_user(duplicate).await;
        assert_eq!(Err(UserStoreError::UserAlreadyExists), result);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "secret".to_string(), true);
        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let result = store.get_user("test@example.com").await;
        assert!(result.is_ok());
        let fetched = result.unwrap();
        assert_eq!("test@example.com", fetched.email);
        assert_eq!("secret", fetched.password);
        assert!(fetched.requires_2fa);

        let result = store.get_user("missing@example.com").await;
        assert_eq!(Err(UserStoreError::UserNotFound), result);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "secret".to_string(), false);
        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let result = store.validate_user("test@example.com", "secret").await;
        assert_eq!(Ok(()), result);

        let result = store.validate_user("test@example.com", "wrong").await;
        assert_eq!(Err(UserStoreError::InvalidCredentials), result);

        let result = store.validate_user("missing@example.com", "secret").await;
        assert_eq!(Err(UserStoreError::UserNotFound), result);
    }
}
