use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::eyre;
use thiserror::Error;

use crate::domain::AuthAPIError;

#[derive(Debug, Clone, PartialEq)]
pub struct HashedPassword(String);

impl HashedPassword {
    pub async fn parse(s: String) -> color_eyre::Result<Self> {
        if s.len() >= 8 {
            let pass = compute_password_hash(&s).await?;
            Ok(Self(pass))
        } else {
            return Err(eyre!(AuthAPIError::InvalidCredentials));
        }
    }

    pub fn parse_password_hash(hash: String) -> Result<HashedPassword, String> {
        let result = PasswordHash::new(&hash);
        match result {
            Ok(h) => Ok(Self(h.to_string())),
            Err(e) => Err(e.to_string()),
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &str) -> color_eyre::Result<()> {
        // This line retrieves the current span from the tracing context.
        // The span represents the execution context for the compute_password_hash function.
        let current_span: tracing::Span = tracing::Span::current();

        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();

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

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Helper function to hash passwords before persisting them in storage.
// Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, perform hashing on a
// separate thread pool using tokio::task::spawn_blocking.
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &str) -> color_eyre::Result<String> {
    // This line retrieves the current span from the tracing context.
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current();

    let password = password.to_owned();

    let result = tokio::task::spawn_blocking(move || -> color_eyre::Result<String> {
        // This code block ensures that the operations within the closure are executed within the context of the current span.
        // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
        current_span.in_scope(|| -> color_eyre::Result<String> {
            // New!
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
        })
    })
    .await;

    result?
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
    use quickcheck::{Gen, QuickCheck};
    use rand::SeedableRng;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = "".to_owned();
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_owned();
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

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
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

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));

        let Ok(result) = hash_password.verify_raw_password("TestPassword123").await else {
            panic!("Passwords do not match");
        };

        assert_eq!(result, ());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }

    #[test]
    fn valid_passwords_are_parsed_successfully() {
        fn property(valid_password: ValidPasswordFixture) -> bool {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            runtime
                .block_on(HashedPassword::parse(valid_password.0))
                .is_ok()
        }

        QuickCheck::new()
            .tests(10)
            .quickcheck(property as fn(ValidPasswordFixture) -> bool);
    }
}
