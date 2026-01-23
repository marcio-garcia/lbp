#[derive(Debug, Clone, PartialEq, Eq)   ]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, PasswordError> {
        if password.len() >= 8 {
            Ok(Self(password))
        } else {
            Err(PasswordError::InvalidPassword)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum PasswordError {
    InvalidPassword,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_password_succeeds() {
        let password = "validpassword".to_string();

        let result = Password::parse(password.clone());

        assert_eq!(result, Ok(Password(password)));
    }

    #[test]
    fn parse_less_than_8_chars() {
        let password = "pass".to_string();

        let result = Password::parse(password);

        assert_eq!(result, Err(PasswordError::InvalidPassword));
    }

    #[test]
    fn parse_empty_string_fails() {
        let password = "".to_string();

        let result = Password::parse(password);

        assert!(matches!(result, Err(PasswordError::InvalidPassword)));
    }

    #[test]
    fn parsed_password_exposes_inner_str() {
        let password = Password::parse("password123".to_string()).unwrap();

        assert_eq!(password.as_str(), "password123");
    }
}
