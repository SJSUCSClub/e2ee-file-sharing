use axum::{
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use rusqlite::Connection;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;

use crate::db::{get_file_path, get_user_id};

#[derive(Clone)]
pub(crate) struct HandlerState {
    // TODO - differentiate between the fact that we have
    // readers and writers, and there can be multiple readers
    // at the same time, but only one writer at a time
    pub conn: Arc<Mutex<Connection>>,
}

// ==============================
// FILES endpoints
// ==============================

#[derive(Deserialize, Debug)]
pub(crate) struct ListFilesQueryParams {
    user_email: String,
    user_password_hash: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct ListFilesItem {
    file_name: String,
    file_id: i64,
    group_name: String,
    group_id: i64,
}

#[derive(Deserialize, Debug)]
pub(crate) struct ListFilesResponse {
    files: Vec<ListFilesItem>,
}

// TODO - ideally upload and download
// would stream data instead of just using
// multipart/form-data because this would
// allow easy handling of large files.
pub(crate) async fn list_files(
    Query(params): Query<ListFilesQueryParams>,
    State(st): State<HandlerState>,
) -> impl IntoResponse {
    println!("Params are {params:?}");
    // so now return query
    // TODO - make connection, get user id, get files
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetFileQueryParams {
    file_id: i64,
    group_id: i64,
    user_email: String,
    user_password_hash: String,
}

#[axum::debug_handler]
pub(crate) async fn get_file(
    Query(params): Query<GetFileQueryParams>,
    State(st): State<HandlerState>,
) -> Response {
    let conn = &st.conn.lock().await;

    // authenticate the user
    if let Err(e) = get_user_id(conn, &params.user_email, &params.user_password_hash) {
        println!("Bad user: {e:?}");
        return (StatusCode::BAD_REQUEST, "User email and password mismatch").into_response();
    }

    // authentication succeeded, proceed to get the file storage location
    let path = match get_file_path(conn, params.file_id) {
        Ok(path) => path,

        Err(e) => {
            println!("Error getting file path: {e:?}!");
            return (StatusCode::BAD_REQUEST, "Invalid file ID").into_response();
        }
    };

    // open file
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening file: {e:?}!");
            return (StatusCode::BAD_REQUEST, "Failed to open file!").into_response();
        }
    };

    // stream file back
    let body = Body::from_stream(ReaderStream::new(file));
    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream"),
        // TODO - does writing somefile.txt actually matter?
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"somefile.txt\"",
        ),
    ];

    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize, Debug)]
struct UploadFileQueryParams {
    file_id: i64,
    group_id: i64,
    user_email: String,
    user_password_hash: String,
}

/*
pub(crate) async fn upload_file(
    Query(params): Query<UploadFileQueryParams>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let (mut field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let file_name = field.file_name().unwrap().to_string();
        let content_type = field.content_type().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        // TODO
    }
}*/
