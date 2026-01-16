use axum::response::IntoResponse;
use reqwest::StatusCode;

pub async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
