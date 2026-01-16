use axum::response::IntoResponse;
use reqwest::StatusCode;

pub async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
