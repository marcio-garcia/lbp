use auth_service::{
    app_state::AppState,
    services::{hashmap_user_store::HashmapUserStore, HashsetBannedTokenStore},
    utils::constants::prod,
    Application,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::new()));
    let app_state = AppState {
        user_store,
        banned_token_store,
    };

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
