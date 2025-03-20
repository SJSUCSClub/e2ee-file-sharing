mod api;
mod db;
mod page;

use std::sync::Arc;
use tokio::sync::Mutex;

use api::HandlerState;
use axum::{
    Router, middleware,
    routing::{get, post},
};

use rusqlite::Connection;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let conn = Connection::open(db::DB_NAME).expect("Failed to open db");
    db::init_db(&conn).expect("Failed to init db");
    let state = HandlerState {
        conn: Arc::new(Mutex::new(conn)),
    };

    let app = Router::new()
        .route("/api/v1/list-files", get(api::list_files))
        .route("/api/v1/file", get(api::get_file))
        .route("/api/v1/file", post(api::upload_file))
        .route("/", get(page::index_html))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::user_auth,
        ))
        .with_state(state);

    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.0:8091".to_string());

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
