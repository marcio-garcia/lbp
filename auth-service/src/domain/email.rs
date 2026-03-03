use color_eyre::eyre::eyre;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use std::hash::Hash;
use thiserror::Error;
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct Email(SecretString);

impl Email {
    pub fn parse(s: SecretString) -> color_eyre::Result<Email> {
        if s.expose_secret().validate_email() {
            Ok(Self(s))
        } else {
            Err(eyre!(format!(
                "{} is not a valid email.",
                s.expose_secret()
            )))
        }
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

#[derive(Debug, PartialEq, Error)]
pub enum EmailError {
    #[error("Invalid email")]
    InvalidEmail,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_email_succeeds() {
        let email = SecretString::new("user@example.com".to_owned().into_boxed_str());

        let result = Email::parse(email.clone());

        assert_eq!(result.ok().unwrap(), Email(email));
    }

    #[test]
    fn parse_missing_at_symbol_fails() {
        let email = SecretString::new("userexample.com".to_owned().into_boxed_str());

        let result = Email::parse(email);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_string_fails() {
        let email = SecretString::new("".to_owned().into_boxed_str());
        let result = Email::parse(email);
        assert!(result.is_err());
    }

    #[test]
    fn parsed_email_exposes_inner_str() {
        let email_str = SecretString::new("user@example.com".to_owned().into_boxed_str());
        let result = Email::parse(email_str);
        assert_eq!(
            result.ok().unwrap().as_ref().expose_secret(),
            "user@example.com"
        );
    }
}
