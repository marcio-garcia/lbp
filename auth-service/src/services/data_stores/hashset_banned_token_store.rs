use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;

pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

impl HashsetBannedTokenStore {
    pub fn new() -> Self {
        HashsetBannedTokenStore {
            tokens: HashSet::new(),
        }
    }
}

#[async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::{Email, Token},
        utils::auth::generate_auth_cookie,
    };
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashsetBannedTokenStore::new();

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
        let mut store = HashsetBannedTokenStore::new();
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
