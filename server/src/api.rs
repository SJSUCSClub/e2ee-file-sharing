use axum::{
    Extension, Json,
    body::Body,
    extract::{Multipart, Query, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};
use tokio_util::io::ReaderStream;

use crate::db::{get_filename, get_files_for_user_id, get_user_id, insert_file};

// ==============================
// Upload Directory
// ==============================
const UPLOAD_DIRECTORY: &str = "/uploads";

fn to_path(file_id: i64) -> String {
    format!("{UPLOAD_DIRECTORY}/{file_id}")
}

// ==============================
// State / Connection Thread
// ==============================
#[derive(Clone)]
pub(crate) struct HandlerState {
    // TODO - differentiate between the fact that we have
    // readers and writers, and there can be multiple readers
    // at the same time, but only one writer at a time
    pub tx: Sender<DatabaseCommand>,
}

// task thread that manages a connection
pub(crate) enum DatabaseCommand {
    GetUserId {
        user_email: String,
        user_password_hash: String,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    GetFilesForUserId {
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<(String, i64, String, i64)>>>,
    },
    GetFilename {
        file_id: i64,
        responder: oneshot::Sender<rusqlite::Result<String>>,
    },
    InsertFile {
        group_id: i64,
        filename: String,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
}
pub(crate) async fn connection_task(conn: Connection, mut rx: mpsc::Receiver<DatabaseCommand>) {
    use DatabaseCommand::*;
    while let Some(cmd) = rx.recv().await {
        match cmd {
            GetUserId {
                user_email,
                user_password_hash,
                responder,
            } => {
                responder
                    .send(get_user_id(&conn, &user_email, &user_password_hash))
                    .unwrap();
            }
            GetFilesForUserId { user_id, responder } => {
                responder
                    .send(get_files_for_user_id(&conn, user_id))
                    .unwrap();
            }
            GetFilename { file_id, responder } => {
                responder.send(get_filename(&conn, file_id)).unwrap();
            }
            InsertFile {
                group_id,
                filename,
                responder,
            } => {
                responder
                    .send(insert_file(&conn, group_id, &filename))
                    .unwrap();
            }
        }
    }
}

// ==============================
// Middleware
// ==============================
#[derive(Deserialize, Debug)]
pub(crate) struct UserAuth {
    user_email: String,
    user_password_hash: String,
}
#[derive(Clone, Debug)]
pub(crate) struct UserAuthExtension {
    user_id: i64,
}
pub(crate) async fn user_auth(
    State(st): State<HandlerState>,
    Query(params): Query<UserAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    // send request
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetUserId {
            user_email: params.user_email,
            user_password_hash: params.user_password_hash,
            responder: tx,
        })
        .await
        .unwrap();
    // and double check
    let user_id = match rx.await.unwrap() {
        Ok(user_id) => user_id,
        Err(e) => {
            println!("Failed to authenticate user with {e:?}");
            return (StatusCode::UNAUTHORIZED, "User email and password mismatch").into_response();
        }
    };

    request
        .extensions_mut()
        .insert(UserAuthExtension { user_id });
    next.run(request).await
}

// ==============================
// FILES endpoints
// ==============================

#[derive(Serialize, Debug)]
pub(crate) struct ListFilesItem {
    file_name: String,
    file_id: i64,
    group_name: String,
    group_id: i64,
}

#[derive(Serialize, Debug)]
pub(crate) struct ListFilesResponse {
    files: Vec<ListFilesItem>,
}

// TODO - ideally upload and download
// would stream data instead of just using
// multipart/form-data because this would
// allow easy handling of large files.
// curl http://127.0.0.0:8091/api/v1/list-files?user_email=email@test.org&user_password_hash=0033FF -X GET
pub(crate) async fn list_files(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // initialize/send request
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetFilesForUserId {
            user_id: user_id,
            responder: tx,
        })
        .await
        .unwrap();
    // get all files that match this user id
    let files_vec = match rx.await.unwrap() {
        Ok(files) => files,
        Err(e) => {
            println!("Error getting files: {e:?}!");
            return (StatusCode::BAD_REQUEST, "Failed to get files!").into_response();
        }
    };

    // return the files, as proper response
    let files = files_vec
        .iter()
        .map(|(file_name, file_id, group_name, group_id)| ListFilesItem {
            file_name: file_name.clone(),
            file_id: *file_id,
            group_name: group_name.clone(),
            group_id: *group_id,
        })
        .collect();
    let response = ListFilesResponse { files };
    (StatusCode::OK, Json(response)).into_response()
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetFileQueryParams {
    file_id: i64,
}

// example curl command
// curl http://127.0.0.0:8091/api/v1/file?file_id=4&user_email=user@test.org&user_password_hash=02FA3B -X GET
pub(crate) async fn get_file(
    Query(params): Query<GetFileQueryParams>,
    State(st): State<HandlerState>,
) -> Response {
    // authentication succeeded, proceed to get the file storage location
    // first, initialize request to the connection thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetFilename {
            file_id: params.file_id,
            responder: tx,
        })
        .await
        .unwrap();

    // and the file name
    let file_name = match rx.await.unwrap() {
        Ok(file_name) => file_name,
        Err(e) => {
            println!("Failed to get filename {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get filename").into_response();
        }
    };
    let path = to_path(params.file_id);

    // open file
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening file: {e:?}!");
            return (StatusCode::BAD_REQUEST, "Failed to open file").into_response();
        }
    };

    // stream file back
    let body = Body::from_stream(ReaderStream::new(file));
    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream"),
        (
            header::CONTENT_DISPOSITION,
            &format!("attachment; filename={file_name}"),
        ),
    ];

    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize, Debug)]
pub(crate) struct UploadFileQueryParams {
    group_id: i64,
}
#[derive(Serialize, Debug)]
pub(crate) struct UploadFileResponse {
    file_id: i64,
}

// example curl command
// curl http://127.0.0.0:8091/api/v1/file?group_id=1&user_email=email@test.org&user_password_hash=0033FF -X POST -H "Content-Type: multipart/form-data" -F fi=@file.txt
pub(crate) async fn upload_file(
    Query(params): Query<UploadFileQueryParams>,
    State(st): State<HandlerState>,
    mut multipart: Multipart,
) -> Response {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let file_name = field.file_name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        // insert into DB
        // first, initialize channel to connection thread
        let (tx, rx) = oneshot::channel();
        st.tx
            .send(DatabaseCommand::InsertFile {
                group_id: params.group_id,
                filename: file_name,
                responder: tx,
            })
            .await
            .unwrap();
        // then match result
        let file_id = match rx.await.unwrap() {
            Ok(file_id) => file_id,
            Err(e) => {
                println!("Failed to insert file with {e:?}");
                return (StatusCode::BAD_REQUEST, "Failed to insert file").into_response();
            }
        };

        // write that to a file
        // since files are uniquely identified by their file id, then we
        // can simply save as the file id
        // and later fetch files by their file_id
        let path = format!("{UPLOAD_DIRECTORY}/{file_id}");
        if let Err(e) = tokio::fs::write(path, data).await {
            println!("Failed to save file with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to save file").into_response();
        } else {
            return (StatusCode::OK, Json(UploadFileResponse { file_id })).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "No file body provided").into_response()
}
