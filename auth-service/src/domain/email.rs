#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, EmailError> {
        if !email.is_empty() && email.contains("@") {
            Ok(Self(email))
        } else {
            Err(EmailError::InvalidEmail)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum EmailError {
    InvalidEmail,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_email_succeeds() {
        let email = "user@example.com".to_string();

        let result = Email::parse(email.clone());

        assert_eq!(result, Ok(Email(email)));
    }

    #[test]
    fn parse_missing_at_symbol_fails() {
        let email = "userexample.com".to_string();

        let result = Email::parse(email);

        assert_eq!(result, Err(EmailError::InvalidEmail));
    }

    #[test]
    fn parse_empty_string_fails() {
        let email = "".to_string();

        let result = Email::parse(email);

        assert!(matches!(result, Err(EmailError::InvalidEmail)));
    }

    #[test]
    fn parsed_email_exposes_inner_str() {
        let email = Email::parse("user@example.com".to_string()).unwrap();

        assert_eq!(email.as_str(), "user@example.com");
    }
}
