use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, HashedPassword, User,
};
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> color_eyre::Result<(), UserStoreError> {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(user.email.as_ref().expose_secret())
                .fetch_one(&self.pool)
                .await
                .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        if exists {
            return Err(UserStoreError::UserAlreadyExists);
        }

        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
            .bind(user.email.as_ref().expose_secret())
            .bind(user.password.as_ref().expose_secret())
            .bind(user.requires_2fa)
            .execute(&self.pool)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> color_eyre::Result<User, UserStoreError> {
        let row = sqlx::query_as::<_, (String, String, bool)>(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
        )
        .bind(email.as_ref().expose_secret())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        let Some((email_str, password_hash, requires_2fa)) = row else {
            return Err(UserStoreError::UserNotFound);
        };

        let email =
            Email::parse(email_str.into()).map_err(|e| UserStoreError::UnexpectedError(e.into()))?;
        let secret_str = SecretString::new(password_hash.to_owned().into_boxed_str());
        let password = HashedPassword::parse_password_hash(secret_str)
            .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        Ok(User::new(email, password, requires_2fa))
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> color_eyre::Result<(), UserStoreError> {
        let password_hash =
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE email = $1")
                .bind(email.as_ref().expose_secret())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        let Some(password_hash) = password_hash else {
            return Err(UserStoreError::UserNotFound);
        };

        let secret_str = SecretString::new(password_hash.to_owned().into_boxed_str());

        let hashed_password = HashedPassword::parse_password_hash(secret_str)
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        hashed_password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
