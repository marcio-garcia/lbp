use auth_service::{
    app_state::AppState,
    get_postgres_pool, get_redis_client,
    services::{MockEmailClient, PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore},
    utils::{
        constants::{prod, DATABASE_URL, REDIS_HOST_NAME},
        tracing::init_tracing,
    },
    Application,
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    init_tracing();
    let pg_pool = configure_postgresql().await;
    let redis_conn = Arc::new(RwLock::new(configure_redis()));

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn.clone())));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_conn)));
    let email_client = Arc::new(RwLock::new(MockEmailClient));

    let app_state = AppState {
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    };

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
