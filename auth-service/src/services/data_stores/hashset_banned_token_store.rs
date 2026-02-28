use crate::domain::{BannedTokenStore, BannedTokenStoreError, Token};
use async_trait::async_trait;
use std::collections::HashSet;

pub struct HashsetBannedTokenStore {
    tokens: HashSet<Token>,
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
    async fn add_token(&mut self, token: Token) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn contains(&self, token: &Token) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use crate::{domain::Email, utils::auth::generate_auth_cookie};

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashsetBannedTokenStore::new();

        let Ok(email) = Email::parse("test@example.com".to_string()) else {
            panic!("Invalid email");
        };

        let Ok(cookie) = generate_auth_cookie(&email) else {
            panic!("could not generate token")
        };

        let token_str = cookie.value().to_owned();

        let Ok(token) = Token::parse(token_str) else {
            panic!("could not create token")
        };

        let result = store.add_token(token).await;
        assert_eq!((), result.ok().unwrap());
    }

    #[tokio::test]
    async fn test_contain_token() {
        let mut store = HashsetBannedTokenStore::new();
        let Ok(email) = Email::parse("test@example.com".to_string()) else {
            panic!("Invalid email");
        };
        let Ok(cookie) = generate_auth_cookie(&email) else {
            panic!("could not generate token")
        };
        let token_str = cookie.value().to_owned();
        let Ok(token) = Token::parse(token_str) else {
            panic!("could not create token")
        };
        let result = store.add_token(token.clone()).await;
        assert_eq!((), result.ok().unwrap());

        let exists = store.contains(&token).await;
        assert!(exists.ok().unwrap());
    }
}
