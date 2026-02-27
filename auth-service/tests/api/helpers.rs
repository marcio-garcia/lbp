use auth_service::app_state::app_state::{BannedTokenStoreType, TwoFACodeStoreType, UserStoreType};
use auth_service::services::{
    HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore, MockEmailClient,
    PostgresUserStore,
};
use auth_service::utils::constants::DATABASE_URL;
use auth_service::{app_state::AppState, utils::constants::test, Application};
use reqwest::cookie::Jar;
use reqwest::Response;
use serde::Serialize;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{env, sync::Arc, time::Duration};
use tokio::sync::{Mutex, OnceCell, RwLock};
use uuid::Uuid;

#[allow(dead_code)]
static TEMPLATE_DB: OnceCell<String> = OnceCell::const_new();
#[allow(dead_code)]
static DB_PROVISION_LOCK: Mutex<()> = Mutex::const_new(());

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store: UserStoreType = Arc::new(RwLock::new(HashmapUserStore::default()));
        Self::build(user_store).await
    }

    #[allow(dead_code)]
    pub async fn new_postgres() -> Self {
        let pg_pool = configure_postgresql().await;
        let user_store: UserStoreType = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        Self::build(user_store).await
    }

    async fn build(user_store: UserStoreType) -> Self {
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::new()));
        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(RwLock::new(MockEmailClient));

        let app_state = AppState {
            user_store,
            banned_token_store: banned_token_store.clone(),
            two_fa_code_store: two_fa_code_store.clone(),
            email_client: email_client.clone(),
        };

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        // Create new `TestApp` instance and return it
        Self {
            address,
            cookie_jar,
            http_client,
            banned_token_store: banned_token_store,
            two_fa_code_store: two_fa_code_store,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<T: Serialize>(&self, body: &T) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body: Serialize>(&self, body: &Body) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

pub async fn create_user(app: &TestApp, requires_2fa: bool) -> Response {
    let random_email = get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": requires_2fa
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    response
}

#[allow(dead_code)]
async fn configure_postgresql() -> PgPool {
    let template_db = ensure_template_database().await;
    let postgresql_conn_url = test_database_url();
    let db_name = format!("test_{}", Uuid::new_v4().simple());

    {
        // Serialize clone operations to avoid Postgres template-database lock contention.
        let _guard = DB_PROVISION_LOCK.lock().await;
        clone_database_from_template(&postgresql_conn_url, &template_db, &db_name).await;
    }

    let options: PgConnectOptions = postgresql_conn_url
        .parse()
        .expect("Failed to parse DATABASE_URL.");
    let options = options.database(&db_name);

    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .expect("Failed to create Postgres connection pool!")
}

#[allow(dead_code)]
async fn ensure_template_database() -> String {
    TEMPLATE_DB
        .get_or_init(|| async {
            let postgresql_conn_url = test_database_url();
            let template_db = format!("test_template_{}", std::process::id());
            let admin_pool = connect_admin_pool(&postgresql_conn_url).await;

            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
            )
            .bind(&template_db)
            .fetch_one(&admin_pool)
            .await
            .expect("Failed to check template database existence.");

            if !exists {
                sqlx::query(format!(r#"CREATE DATABASE "{}";"#, template_db).as_str())
                    .execute(&admin_pool)
                    .await
                    .expect("Failed to create template database.");

                let options: PgConnectOptions = postgresql_conn_url
                    .parse()
                    .expect("Failed to parse DATABASE_URL.");
                let options = options.database(&template_db);

                let template_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(5))
                    .connect_with(options)
                    .await
                    .expect("Failed to connect to template database.");

                sqlx::migrate!()
                    .run(&template_pool)
                    .await
                    .expect("Failed to migrate template database.");
            }

            template_db
        })
        .await
        .clone()
}

#[allow(dead_code)]
fn test_database_url() -> String {
    env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DATABASE_URL.to_owned())
}

#[allow(dead_code)]
async fn connect_admin_pool(db_conn_string: &str) -> PgPool {
    let admin_options: PgConnectOptions = db_conn_string
        .parse()
        .expect("Failed to parse DATABASE_URL.");
    let admin_options = admin_options.database("postgres");

    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(admin_options)
        .await
        .expect("Failed to create Postgres admin connection pool.")
}

#[allow(dead_code)]
async fn clone_database_from_template(db_conn_string: &str, template_db: &str, db_name: &str) {
    let admin_pool = connect_admin_pool(db_conn_string).await;

    // Clone a migrated database instead of rerunning migrations for every test.
    sqlx::query(
        format!(
            r#"CREATE DATABASE "{}" TEMPLATE "{}";"#,
            db_name, template_db
        )
        .as_str(),
    )
    .execute(&admin_pool)
    .await
    .expect("Failed to create test database from template.");

    let options: PgConnectOptions = db_conn_string
        .parse()
        .expect("Failed to parse DATABASE_URL.");
    let options = options.database(db_name);

    let connection = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Light sanity check: cloned database must already contain migrated schema.
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'users'
        )",
    )
        .fetch_one(&connection)
        .await
        .expect("Failed to verify users table in cloned database.");
}
