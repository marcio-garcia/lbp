use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, HashedPassword, User,
};

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
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(user.email.as_ref())
                .fetch_one(&self.pool)
                .await
                .map_err(|_| UserStoreError::UnexpectedError)?;

        if exists {
            return Err(UserStoreError::UserAlreadyExists);
        }

        match sqlx::query(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
        )
        .bind(user.email.as_ref())
        .bind(user.password.as_ref())
        .bind(user.requires_2fa)
        .execute(&self.pool)
        .await
        {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(UserStoreError::UserAlreadyExists)
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let row = sqlx::query_as::<_, (String, String, bool)>(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
        )
        .bind(email.as_ref())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        let Some((email_str, password_hash, requires_2fa)) = row else {
            return Err(UserStoreError::UserNotFound);
        };

        let email = Email::parse(email_str).map_err(|_| UserStoreError::UnexpectedError)?;
        let password = HashedPassword::parse_password_hash(password_hash)
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(User::new(email, password, requires_2fa))
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let password_hash =
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE email = $1")
                .bind(email.as_ref())
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| UserStoreError::UnexpectedError)?;

        let Some(password_hash) = password_hash else {
            return Err(UserStoreError::UserNotFound);
        };

        let hashed_password = HashedPassword::parse_password_hash(password_hash)
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        hashed_password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
