mod api;
mod db;

use std::env;

use api::{HandlerState, authenticated, connection_task, get_group_by_id};
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
        .route("/api/v1/file/{file_id}/info", auth(get(api::get_file_info)))
        .route("/api/v1/user/info", auth(get(api::get_user_info)))
        .route("/api/v1/user/key", auth(get(api::get_user_key)))
        .route("/api/v1/user", post(api::register_user))
        .route("/api/v1/group/{group_id}", auth(get(get_group_by_id)))
        .route(
            "/api/v1/group/{group_id}/key",
            auth(get(api::get_group_key_by_id)),
        )
        .route("/api/v1/group", auth(get(api::get_group_by_members)))
        .route("/api/v1/group", auth(post(api::create_group)))
        .route("/api/v1/list-groups", auth(get(api::list_groups)))
        .route("/", get(api::hello))
        .with_state(state);

    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.1:8091".to_string());

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
