mod api;
mod db;
mod page;

use std::sync::Arc;
use tokio::sync::Mutex;

use api::HandlerState;
use axum::{
    Router,
    routing::{get, post},
};

use rusqlite::Connection;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let conn = Connection::open(db::DB_NAME).expect("Failed to open db");
    db::init_db(&conn).expect("Failed to init db");

    let app = Router::new()
        .route("/api/v1/list-files", get(api::list_files))
        .route("/api/v1/file", get(api::get_file))
        .route("/api/v1/file", post(api::upload_file))
        .route("/", get(page::index_html))
        .with_state(HandlerState {
            conn: Arc::new(Mutex::new(conn)),
        });

    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.0:8091".to_string());

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
