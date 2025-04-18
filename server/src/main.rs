mod api;
mod db;

use api::{HandlerState, connection_task};
use axum::middleware;
use std::env;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::Level;

use crate::db::Database;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

#[derive(OpenApi)]
#[openapi(info(
    title = "E2EE File Sharing API",
    description = "API for E2EE file sharing",
    version = "0.1.0",
))]
struct ApiDoc;

#[tokio::main]
async fn main() {
    // make db
    let db_filename = env::var("DATABASE").unwrap_or("e2ee-file-sharing.db".to_string());
    let mut db = Database::open(&db_filename).expect("Failed to open db");
    db::init_db(&mut db).expect("Failed to init db");

    // make upload directory if necessary
    let upload_directory = env::var("UPLOAD_DIRECTORY").unwrap_or("/tmp/e2ee-fs".to_string());
    tokio::fs::create_dir_all(&upload_directory).await.unwrap();

    // initialize state
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let state = HandlerState {
        tx,
        upload_directory,
        new_db: Arc::new(Box::new(move || {
            Database::open(&db_filename).expect("Failed to open database")
        })),
    };
    let _ = tokio::spawn(connection_task(db, rx));

    // make app
    // but in two parts, one for endpoints requiring auth
    // and one for those that don't
    let (auth_app, auth_openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(api::list_files))
        .routes(routes!(api::get_file))
        .routes(routes!(api::upload_file))
        .routes(routes!(api::get_file_info))
        .routes(routes!(api::get_user_info))
        .routes(routes!(api::get_user_key))
        .routes(routes!(api::get_group_by_id))
        .routes(routes!(api::get_group_key_by_id))
        .routes(routes!(api::get_group_by_members))
        .routes(routes!(api::create_group))
        .routes(routes!(api::list_groups))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::user_auth,
        ))
        .with_state(state.clone())
        .split_for_parts();
    let (unauth_app, unauth_openapi) = OpenApiRouter::new()
        .routes(routes!(api::register_user))
        .with_state(state)
        .split_for_parts();

    // merge apps together and add swagger
    let app = auth_app.merge(unauth_app);
    let openapi = auth_openapi.merge_from(unauth_openapi);
    let app = app.merge(
        utoipa_swagger_ui::SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", openapi),
    );

    tracing_subscriber::fmt().init();

    let app = app.layer(
        TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
            .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::INFO)),
    );

    // start server
    let bind_addr = std::env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.1:8091".to_string());
    println!("server starting on port {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
