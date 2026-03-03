use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::domain::UserStoreError;

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "HashedPassword Parse", skip_all)]
    pub async fn parse(s: SecretString) -> color_eyre::Result<Self> {
        if validate_password(&s) {
            let result = compute_password_hash(&s)
                .await
                .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

            Ok(Self(result))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword Parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> color_eyre::Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.expose_secret().as_ref()) {
            Ok(Self(SecretString::new(
                hashed_string.to_string().into_boxed_str(),
            )))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword Verify raw password", skip_all)]
    pub async fn verify_raw_password(
        &self,
        password_candidate: &SecretString,
    ) -> color_eyre::Result<()> {
        // This line retrieves the current span from the tracing context.
        // The span represents the execution context for the compute_password_hash function.
        let current_span: tracing::Span = tracing::Span::current();

        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        let res = tokio::task::spawn_blocking(move || -> color_eyre::Result<()> {
            // This code block ensures that the operations within the closure are executed within the context of the current span.
            // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
            current_span.in_scope(|| {
                let expected_password_hash = PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .map_err(|e| e.into())
            })
        })
        .await?;
        res
    }

    // pub fn as_str(&self) -> &str {
    //     &self.0
    // }
}

fn validate_password(s: &SecretString) -> bool {
    // Updated!
    s.expose_secret().len() >= 8
}

// Helper function to hash passwords before persisting them in storage.
// Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, perform hashing on a
// separate thread pool using tokio::task::spawn_blocking.
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> color_eyre::Result<SecretString> {
    // This line retrieves the current span from the tracing context.
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.expose_secret().to_owned();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?;

    result
}

#[derive(Debug, PartialEq, Error)]
pub enum PasswordError {
    #[error("Invalid password")]
    InvalidPassword,
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;
    use secrecy::{ExposeSecret, SecretString};

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_string().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new("1234567".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password =
            HashedPassword::parse_password_hash(SecretString::new(hash_string.clone().into()))
                .unwrap();

        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password =
            HashedPassword::parse_password_hash(SecretString::new(hash_string.clone().into()))
                .unwrap();

        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));

        let candidate = SecretString::new("TestPassword123".to_owned().into_boxed_str());
        let Ok(result) = hash_password.verify_raw_password(&candidate).await else {
            panic!("Passwords do not match");
        };

        assert_eq!(result, ());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password: String = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(SecretString::new(password.into_boxed_str()))
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
        runtime
            .block_on(HashedPassword::parse(valid_password.0))
            .is_ok()
    }
}
