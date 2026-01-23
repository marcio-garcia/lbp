use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
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

    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError> {
        if let Some(user) = self.users.get(email) {
            return Ok(user);
        }
        return Err(UserStoreError::UserNotFound);
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(email) {
            if &user.password == password {
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

        let Ok(email) = Email::parse("test@example.com".to_string()) else {
            panic!("Invalid email");
        };
        let Ok(password) = Password::parse("secretpass".to_string()) else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), false);

        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let duplicate = User::new(email, password, false);
        let result = store.add_user(duplicate).await;
        assert_eq!(Err(UserStoreError::UserAlreadyExists), result);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();

        let Ok(email) = Email::parse("test@example.com".to_string()) else {
            panic!("Invalid email");
        };
        let Ok(password) = Password::parse("secretpass".to_string()) else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), true);

        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let result = store.get_user(&email).await;
        assert!(result.is_ok());
        let fetched = result.unwrap();
        assert_eq!(email, fetched.email);
        assert_eq!(password, fetched.password);
        assert!(fetched.requires_2fa);

        let Ok(email) = Email::parse("missing@example.com".to_string()) else {
            panic!("Invalid email");
        };

        let result = store.get_user(&email).await;
        assert_eq!(Err(UserStoreError::UserNotFound), result);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let Ok(email) = Email::parse("test@example.com".to_string()) else {
            panic!("Invalid email");
        };
        let Ok(password) = Password::parse("secretpass".to_string()) else {
            panic!("Invalid password");
        };

        let user = User::new(email.clone(), password.clone(), false);
        let result = store.add_user(user).await;
        assert_eq!(Ok(()), result);

        let Ok(email2) = Email::parse("missing@example.com".to_string()) else {
            panic!("Invalid email");
        };
        let Ok(password2) = Password::parse("wrongpass".to_string()) else {
            panic!("Invalid password");
        };

        let result = store.validate_user(&email, &password).await;
        assert_eq!(Ok(()), result);

        let result = store.validate_user(&email, &password2).await;
        assert_eq!(Err(UserStoreError::InvalidCredentials), result);

        let result = store.validate_user(&email2, &password).await;
        assert_eq!(Err(UserStoreError::UserNotFound), result);
    }
}
