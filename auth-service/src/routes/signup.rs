use axum::response::IntoResponse;
use reqwest::StatusCode;

pub async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
