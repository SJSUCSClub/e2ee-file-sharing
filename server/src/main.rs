mod api;
mod page;

use axum::{
    routing::{get, post},
    Router,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let app = Router::new()
        .route("/api/v1/register", post(api::register))
        .route("/api/v1/login", post(api::login))
        .route("/", get(page::index_html));

    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.0:8091".to_string());

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
