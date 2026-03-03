use color_eyre::eyre::eyre;

use crate::{domain::AuthAPIError, utils::auth::validate_structure};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl Token {
    pub fn parse(token: String) -> color_eyre::Result<Self> {
        if !token.is_empty() {
            let Ok(_) = validate_structure(&token) else {
                return Err(eyre!(AuthAPIError::InvalidToken));
            };
            Ok(Self(token))
        } else {
            Err(eyre!(AuthAPIError::InvalidToken))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum TokenError {
    InvalidToken,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::email::Email;
    use crate::utils::auth::generate_auth_cookie;

    #[tokio::test]
    async fn parse_valid_token_succeeds() {
        let email = Email::parse("test@example.com".to_owned().into()).unwrap();
        let token = generate_auth_cookie(&email).unwrap().value().to_string();
        let result = Token::parse(token);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn parse_missing_at_symbol_fails() {
        let token = "invalid".to_string();
        let result = Token::parse(token);
        let err = result.expect_err("expected invalid token");
        let actual = err
            .downcast_ref::<AuthAPIError>()
            .expect("expected AuthAPIError");
        assert!(matches!(actual, AuthAPIError::InvalidToken));
    }
}
