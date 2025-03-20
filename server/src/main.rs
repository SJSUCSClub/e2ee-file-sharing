mod api;
mod db;

use std::env;

use api::{HandlerState, authenticated, connection_task};
use axum::{
    Router,
    routing::{get, post},
};

use rusqlite::Connection;

#[tokio::main]
async fn main() {
    let conn = Connection::open(db::DB_NAME).expect("Failed to open db");
    db::init_db(&conn).expect("Failed to init db");
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let state = HandlerState {
        tx,
        upload_directory: env::var("UPLOAD_DIRECTORY").unwrap_or("/tmp/e2ee-fs".to_string()),
    };
    let _ = tokio::spawn(connection_task(conn, rx));
    let auth = |a| authenticated(&state, a);

    let app = Router::new()
        .route("/api/v1/list-files", auth(get(api::list_files)))
        .route("/api/v1/file", auth(get(api::get_file)))
        .route("/api/v1/file", auth(post(api::upload_file)))
        .route("/", get(api::hello))
        .with_state(state);

    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.0:8091".to_string());

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
