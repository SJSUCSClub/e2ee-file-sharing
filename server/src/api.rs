use axum::{
    Extension, Json,
    body::Body,
    extract::{Multipart, Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE, Engine as _};
use corelib::server::{make_salt, salt_password};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};
use tokio_util::io::ReaderStream;

use crate::db;
use crate::db::{
    create_group as create_group_db, get_existing_users, get_files_for_user_id, get_group,
    get_group_id, get_group_key, get_groups_for_user_id, get_user_id, insert_file,
};

// ==============================
// Misc
// ==============================
fn to_path(upload_directory: &str, file_id: i64) -> String {
    format!("{upload_directory}/{file_id}")
}

pub(crate) async fn hello() -> &'static str {
    "This is the ACM E2E file sharing server instance."
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
    pub upload_directory: String,
}

// task thread that manages a connection
pub(crate) enum DatabaseCommand {
    GetUserId {
        user_email: String,
        user_password_hash: Vec<u8>,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    GetUserKey {
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<u8>>>,
    },
    GetFilesForUserId {
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<(String, i64, String, i64)>>>,
    },
    InsertFile {
        group_id: i64,
        filename: String,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    GetFileInfo {
        file_id: i64,
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<(String, String, i64)>>,
    },
    GetGroupById {
        group_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<(String, i64)>>>,
    },
    GetGroupKey {
        group_id: i64,
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<u8>>>,
    },
    GetGroupByMembers {
        members: Vec<i64>,
        responder: oneshot::Sender<rusqlite::Result<Option<i64>>>,
    },
    CreateGroup {
        members: Vec<(i64, Vec<u8>)>,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    ListGroups {
        user_id: i64,
        responder: oneshot::Sender<rusqlite::Result<Vec<(i64, String)>>>,
    },
    GetExistingUsers {
        users: Vec<(i64, String)>,
        responder: oneshot::Sender<rusqlite::Result<Vec<(i64, String)>>>,
    },
    RegisterUser {
        user_email: String,
        user_password_hash: Vec<u8>,
        salt: [u8; 8],
        pub_key: Vec<u8>,
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
                    .send(get_user_id(
                        &conn,
                        &user_email,
                        user_password_hash.as_slice(),
                    ))
                    .unwrap();
            }
            GetFilesForUserId { user_id, responder } => {
                responder
                    .send(get_files_for_user_id(&conn, user_id))
                    .unwrap();
            }
            GetFileInfo {
                file_id,
                user_id,
                responder,
            } => {
                responder
                    .send(db::get_file_info(&conn, user_id, file_id))
                    .unwrap();
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
            GetGroupById {
                group_id,
                responder,
            } => {
                responder.send(get_group(&conn, group_id)).unwrap();
            }
            GetGroupKey {
                group_id,
                user_id,
                responder,
            } => {
                responder
                    .send(get_group_key(&conn, group_id, user_id))
                    .unwrap();
            }
            GetGroupByMembers { members, responder } => {
                responder.send(get_group_id(&conn, &members)).unwrap();
            }
            CreateGroup { members, responder } => {
                responder.send(create_group_db(&conn, members)).unwrap();
            }
            ListGroups { user_id, responder } => {
                responder
                    .send(get_groups_for_user_id(&conn, user_id))
                    .unwrap();
            }
            GetExistingUsers { users, responder } => {
                responder.send(get_existing_users(&conn, users)).unwrap();
            }
            GetUserKey { user_id, responder } => {
                responder.send(db::get_user_key(&conn, user_id)).unwrap();
            }
            RegisterUser {
                user_email,
                user_password_hash,
                salt,
                pub_key,
                responder,
            } => {
                responder
                    .send(db::register_user(
                        &conn,
                        &user_email,
                        user_password_hash,
                        salt,
                        pub_key,
                    ))
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
    let decoded_password = BASE64_URL_SAFE
        .decode(params.user_password_hash)
        .expect("Failed to decode user password hash");
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetUserId {
            user_email: params.user_email,
            user_password_hash: decoded_password,
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
// helper function that way we don't have to write .layer
// on every authenticated endpoint
pub(crate) fn authenticated(
    state: &HandlerState,
    a: axum::routing::MethodRouter<HandlerState>,
) -> axum::routing::MethodRouter<HandlerState> {
    a.layer(middleware::from_fn_with_state(state.clone(), user_auth))
}

// ==============================
// FILES endpoints
// ==============================

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct ListFilesItem {
    file_name: String,
    file_id: i64,
    group_name: String,
    group_id: i64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> Response {
    // authentication succeeded, proceed to get the file storage location
    // first, initialize request to the connection thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetFileInfo {
            file_id: params.file_id,
            user_id,
            responder: tx,
        })
        .await
        .unwrap();

    // and the file name
    let info = match rx.await.unwrap() {
        Ok(info) => info,
        Err(e) => {
            println!("Nonexistent file or permission denied {e:?}");
            return (
                StatusCode::BAD_REQUEST,
                "Nonexistent file or permission denied",
            )
                .into_response();
        }
    };
    let path = to_path(&st.upload_directory, params.file_id);

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
            &format!("attachment; filename={}", info.0),
        ),
    ];

    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize, Debug)]
pub(crate) struct UploadFileQueryParams {
    group_id: i64,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UploadFileResponse {
    file_id: i64,
}

// example curl command
// curl http://127.0.0.0:8091/api/v1/file?group_id=1&user_email=email@test.org&user_password_hash=0033FF -X POST -H "Content-Type: multipart/form-data" -F fi=@file.txt
pub(crate) async fn upload_file(
    Query(params): Query<UploadFileQueryParams>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    mut multipart: Multipart,
) -> Response {
    // check if user is in the group
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetGroupById {
            group_id: params.group_id,
            responder: tx,
        })
        .await
        .unwrap();
    let group = match rx.await.unwrap() {
        Ok(group) => group,
        Err(e) => {
            println!("Failed to get group {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group").into_response();
        }
    };
    if !group.iter().any(|user| user.1 == user_id) {
        return (StatusCode::BAD_REQUEST, "User not in group").into_response();
    }

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
        let path = to_path(&st.upload_directory, file_id);
        if let Err(e) = tokio::fs::write(path, data).await {
            println!("Failed to save file with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to save file").into_response();
        } else {
            return (StatusCode::OK, Json(UploadFileResponse { file_id })).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "No file body provided").into_response()
}

pub(crate) async fn get_file_info(
    Path(file_id): Path<i64>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    State(st): State<HandlerState>,
) -> Response {
    // send request to db thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetFileInfo {
            file_id: file_id,
            user_id: user_id,
            responder: tx,
        })
        .await
        .unwrap();
    match rx.await.unwrap() {
        Ok(info) => (
            StatusCode::OK,
            Json(ListFilesItem {
                file_name: info.0,
                file_id,
                group_name: info.1,
                group_id: info.2,
            }),
        )
            .into_response(),
        Err(e) => {
            println!("Failed to get file info with err {e:?}");
            (StatusCode::BAD_REQUEST, "No such file or user not in group").into_response()
        }
    }
}

// ==============================
// USERS endpoints
// ==============================

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetUserInfoResponse {
    user_id: i64,
}

pub(crate) async fn get_user_info(
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(GetUserInfoResponse { user_id: user_id }),
    )
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetUserKeyQueryParams {
    target_user_id: i64,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetUserKeyResponse {
    key: Vec<u8>,
}

pub(crate) async fn get_user_key(
    Query(params): Query<GetUserKeyQueryParams>,
    Extension(_): Extension<UserAuthExtension>,
    State(st): State<HandlerState>,
) -> Response {
    // send request to db thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetUserKey {
            user_id: params.target_user_id,
            responder: tx,
        })
        .await
        .unwrap();
    let key = match rx.await.unwrap() {
        Ok(key) => key,
        Err(e) => {
            println!("Failed to get user key with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get user key").into_response();
        }
    };
    (StatusCode::OK, Json(GetUserKeyResponse { key })).into_response()
}

#[derive(Deserialize)]
pub struct RegisterUser {
    user_email: String,
    user_password_hash: String,
    key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RegisterUserResponse {
    id: i64,
}

pub(crate) async fn register_user(
    State(st): State<HandlerState>,
    Json(params): Json<RegisterUser>,
) -> Response {
    // first, convert password and key into bytes
    let password_bytes = BASE64_STANDARD.decode(&params.user_password_hash).unwrap();
    let key_bytes = BASE64_STANDARD.decode(&params.key).unwrap();

    // then, salt and hash the password
    let salt = make_salt();
    let hashed_password2: Vec<u8> = salt_password(password_bytes.as_slice(), &salt);

    // send request to db thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::RegisterUser {
            user_email: params.user_email,
            user_password_hash: hashed_password2,
            salt: salt,
            pub_key: key_bytes,
            responder: tx,
        })
        .await
        .unwrap();
    let id = match rx.await.unwrap() {
        Ok(id) => id,
        Err(e) => {
            println!("Failed to register user with {e:?}");
            return (StatusCode::CONFLICT, "Email is already taken").into_response();
        }
    };
    (StatusCode::OK, Json(RegisterUserResponse { id })).into_response()
}

// ==============================
// GROUPS endpoints
// ==============================

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct GetGroupItem {
    email: String,
    user_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupResponse {
    members: Vec<GetGroupItem>,
}

pub(crate) async fn get_group_by_id(
    Path(group_id): Path<i64>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // make database request
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetGroupById {
            group_id,
            responder: tx,
        })
        .await
        .unwrap();
    let group_members = match rx.await.unwrap() {
        Ok(group_members) => group_members,
        Err(e) => {
            println!("Failed to get group members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group members").into_response();
        }
    };

    // collect into proper format
    let mut members = Vec::new();
    for (email, user_id) in group_members {
        members.push(GetGroupItem { email, user_id });
    }

    // validate that the user is in the group before returning
    if !members.iter().any(|member| member.user_id == user_id) {
        return (StatusCode::UNAUTHORIZED, "User not present in group").into_response();
    }
    (StatusCode::OK, Json(GetGroupResponse { members })).into_response()
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupKeyResponse {
    encrypted_key: Vec<u8>,
}
pub(crate) async fn get_group_key_by_id(
    Path(group_id): Path<i64>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetGroupKey {
            group_id: group_id,
            user_id: user_id,
            responder: tx,
        })
        .await
        .unwrap();
    let encrypted_key = match rx.await.unwrap() {
        Ok(encrypted_key) => encrypted_key,
        Err(e) => {
            println!("Failed to get group key with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group key").into_response();
        }
    };

    (StatusCode::OK, Json(GetGroupKeyResponse { encrypted_key })).into_response()
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupsByMembersResponse {
    group_id: i64,
}
pub(crate) async fn get_group_by_members(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    Json(body): Json<GetGroupResponse>,
) -> impl IntoResponse {
    // validate that all users exist
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetExistingUsers {
            users: body
                .members
                .iter()
                .map(|m| (m.user_id, m.email.clone()))
                .collect(),
            responder: tx,
        })
        .await
        .unwrap();
    let existing_users = match rx.await.unwrap() {
        Ok(existing_users) => existing_users,
        Err(e) => {
            println!("Failed to get existing users with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get existing users").into_response();
        }
    };
    if existing_users.len() != body.members.len() {
        return (StatusCode::BAD_REQUEST, "Not all users exist").into_response();
    }
    // and that current user is present
    if !existing_users.iter().any(|user| user.0 == user_id) {
        return (StatusCode::UNAUTHORIZED, "User not present in group").into_response();
    }

    // send request to see if such a group exists
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetGroupByMembers {
            members: body.members.iter().map(|m| m.user_id).collect(),
            responder: tx,
        })
        .await
        .unwrap();
    let group_id = match rx.await.unwrap() {
        Ok(group_id) => group_id,
        Err(e) => {
            println!("Failed to get group by members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group by members").into_response();
        }
    };

    // return either the group id or a 404
    match group_id {
        Some(group_id) => (
            StatusCode::OK,
            Json(GetGroupsByMembersResponse { group_id }),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "No such group exists").into_response(),
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct CreateGroupItem {
    user_id: i64,
    email: String,
    encrypted_key: Vec<u8>,
}
#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct CreateGroupBody {
    members: Vec<CreateGroupItem>,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateGroupResponse {
    group_id: i64,
}
pub(crate) async fn create_group(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    Json(body): Json<CreateGroupBody>,
) -> impl IntoResponse {
    // validate that all users exist
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetExistingUsers {
            users: body
                .members
                .iter()
                .map(|m| (m.user_id, m.email.clone()))
                .collect(),
            responder: tx,
        })
        .await
        .unwrap();
    let existing_users = match rx.await.unwrap() {
        Ok(existing_users) => existing_users,
        Err(e) => {
            println!("Failed to get existing users with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get existing users").into_response();
        }
    };
    if existing_users.len() != body.members.len() {
        return (StatusCode::BAD_REQUEST, "Not all users exist").into_response();
    }
    // and that current user is present
    if !existing_users.iter().any(|user| user.0 == user_id) {
        return (StatusCode::UNAUTHORIZED, "User not present in group").into_response();
    }

    // first, check if such a group exists
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::GetGroupByMembers {
            members: body.members.iter().map(|m| m.user_id).collect(),
            responder: tx,
        })
        .await
        .unwrap();
    let group_id = match rx.await.unwrap() {
        Ok(group_id) => group_id,
        Err(e) => {
            println!("Failed to get group by members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group by members").into_response();
        }
    };
    if let Some(group_id) = group_id {
        // then return 409 and the group id
        return (StatusCode::CONFLICT, Json(CreateGroupResponse { group_id })).into_response();
    }
    // so now actually create group
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::CreateGroup {
            members: body
                .members
                .into_iter()
                .map(|m| (m.user_id, m.encrypted_key))
                .collect(),
            responder: tx,
        })
        .await
        .unwrap();
    let group_id = match rx.await.unwrap() {
        Ok(group_id) => group_id,
        Err(e) => {
            println!("Failed to create group with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to create group").into_response();
        }
    };
    (StatusCode::OK, Json(CreateGroupResponse { group_id })).into_response()
}

#[derive(Serialize, Debug)]
pub(crate) struct ListGroupsItem {
    group_id: i64,
    name: String,
}
#[derive(Serialize, Debug)]
pub(crate) struct ListGroupsResponse {
    groups: Vec<ListGroupsItem>,
}
pub(crate) async fn list_groups(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // query db
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::ListGroups {
            user_id: user_id,
            responder: tx,
        })
        .await
        .unwrap();
    // extract and convert to response type
    let groups = match rx.await.unwrap() {
        Ok(groups) => groups,
        Err(e) => {
            println!("Failed to list groups with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to list groups").into_response();
        }
    };
    let groups = groups
        .into_iter()
        .map(|g| ListGroupsItem {
            group_id: g.0,
            name: g.1,
        })
        .collect();
    // send response
    (StatusCode::OK, Json(ListGroupsResponse { groups })).into_response()
}

// ==============================
// Tests
// ==============================

#[cfg(test)]
mod tests {
    use std::{fs, vec};

    use axum::{
        Router,
        http::Request,
        routing::{get, post},
    };
    use http_body_util::BodyExt;
    use rusqlite::params;
    use serde_json::{from_slice, json};
    // for .collect() for the response
    use tower::{Service, ServiceExt}; // for .oneshot

    use crate::db;

    use super::*;
    use corelib::server::{make_salt, salt_password};

    // ==============================
    // AUTH endpoints
    // ==============================

    #[tokio::test]
    async fn test_hello() {
        let app = Router::new().route("/", get(hello));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &body[..],
            b"This is the ACM E2E file sharing server instance."
        );
    }

    #[tokio::test]
    async fn test_auth() {
        // setup
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // and add an initial user
        let salt = make_salt();
        let user_password_hash = vec![1u8, 22u8, 33u8, 7u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(hello)))
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &body[..],
            b"This is the ACM E2E file sharing server instance."
        );

        // Note: for some reason, trying a request with no user_email and no user_password_hash
        // gets by in the authentication middleware in the tests
        // but not in the real server
        // so, not testing for that

        // and try improperly authenticated requests
        let request = Request::builder()
            .uri(format!(
                "/?user_email=wrongemail@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"User email and password mismatch");

        let wrong_password_hash = vec![2u8, 22u8, 33u8, 7u8];
        let wrong_encoded_password_hash = BASE64_URL_SAFE.encode(&wrong_password_hash);
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={wrong_encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"User email and password mismatch");
    }

    // ==============================
    // FILES endpoints
    // ==============================

    #[tokio::test]
    async fn test_list_files() {
        // setup
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // and add an initial user and such
        let salt = make_salt();
        let user_password_hash = b"3F2A33".to_vec();
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00');", []).unwrap();
        conn.execute(
            "INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt');",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO files (group_id, filename) VALUES (1, 'test_file2.txt');",
            [],
        )
        .unwrap();
        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(list_files)))
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: ListFilesResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body.files,
            vec![
                ListFilesItem {
                    file_id: 1,
                    file_name: "test_file.txt".to_string(),
                    group_name: "group_name".to_string(),
                    group_id: 1
                },
                ListFilesItem {
                    file_id: 2,
                    file_name: "test_file2.txt".to_string(),
                    group_name: "group_name".to_string(),
                    group_id: 1
                }
            ]
        );
    }

    struct TestGetFileCleaner {}
    impl Drop for TestGetFileCleaner {
        fn drop(&mut self) {
            fs::remove_dir_all("/tmp/upload-e2e-test").unwrap();
        }
    }

    #[tokio::test]
    async fn test_get_file() {
        // setup
        let _cleaner = TestGetFileCleaner {};
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        let upload_directory = "/tmp/upload-e2e-test";
        tokio::fs::create_dir_all(upload_directory).await.unwrap();
        // and add an initial user and such
        let salt = make_salt();
        let user_password_hash = vec![1u8, 128u8, 77u8, 14u8, 33u8];
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        let server_password_hash = salt_password(&user_password_hash, &salt);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        conn.execute_batch("
            INSERT INTO groups (id) VALUES (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00');
            INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt');
        ").unwrap();
        // and make another user and group
        let salt = make_salt();
        let user_password_hash = vec![22u8, 32u8, 218u8, 25u8, 99u8];
        let encoded_password_hash2 = BASE64_URL_SAFE.encode(&user_password_hash);
        let server_password_hash = salt_password(&user_password_hash, &salt);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        conn.execute_batch("
            INSERT INTO groups (id) VALUES (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 2, 'second', X'00');
            INSERT INTO files (group_id, filename) VALUES (2, 'test_file2.txt');
        ").unwrap();

        tokio::fs::write(to_path(upload_directory, 1), "HI THERE")
            .await
            .unwrap();
        tokio::fs::write(to_path(upload_directory, 2), "SECOND FILE")
            .await
            .unwrap();
        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: upload_directory.to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(get_file)))
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}&file_id=1"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(&body[..], b"HI THERE");

        // try request for file that user shouldn't have access to
        // should be bad request
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}&file_id=2"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // and finally request for the file with user2
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test2@test.com&user_password_hash={encoded_password_hash2}&file_id=2"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"SECOND FILE");
    }

    struct TestUploadFileCleaner {}
    impl Drop for TestUploadFileCleaner {
        fn drop(&mut self) {
            fs::remove_dir_all("/tmp/upload-e2e-test-upload").unwrap();
        }
    }

    #[tokio::test]
    async fn test_upload_file() {
        // setup
        let _cleaner = TestUploadFileCleaner {};
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        let upload_directory = "/tmp/upload-e2e-test-upload";
        tokio::fs::create_dir_all(upload_directory).await.unwrap();
        // and add an initial user and such
        let salt = make_salt();
        let user_password_hash = vec![3u8, 15u8, 2u8, 10u8, 3u8, 3u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        // add group and add dummy user
        conn.execute_batch("
            INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');
            INSERT INTO groups (id) VALUES (NULL), (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (2, 2, 'second', X'00');
        ").unwrap();
        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: upload_directory.to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, post(upload_file)))
            .with_state(state);

        // try properly authenticated request
        // make request body
        let data = "--MYBOUNDARY\r\nContent-Disposition: form-data; name=\"test\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nHELLO WORLD\r\n--MYBOUNDARY\r\n";
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}&group_id=1"
            ))
            .method("POST")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={}", "MYBOUNDARY"),
            )
            .body(Body::from(data))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: UploadFileResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.file_id, 1);
        let contents = tokio::fs::read_to_string(to_path(upload_directory, 1))
            .await
            .unwrap();
        assert_eq!(contents, "HELLO WORLD");

        // and try request to group id that user is not a part of
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}&group_id=2"
            ))
            .method("POST")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={}", "MYBOUNDARY"),
            )
            .body(Body::from(data))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_file_info() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // add user
        let salt = make_salt();
        let user_password_hash = vec![11u8, 10u8, 12u8, 11u8, 10u8, 12u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        conn.execute_batch("
            INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');
            INSERT INTO groups (id) VALUES (NULL), (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (2, 2, 'second', X'00');
            INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt'), (2, 'test_file2.txt');
        ").unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/{file_id}", authenticated(&state, get(get_file_info)))
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/1?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: ListFilesItem = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.file_name, "test_file.txt");

        // and try request to file id that user is not a part of
        let request = Request::builder()
            .uri(format!(
                "/2?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ==============================
    // USERS endpoints
    // ==============================

    #[tokio::test]
    async fn test_get_user_info() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // add user
        let salt = make_salt();
        let user_password_hash = vec![12u8, 8u8, 4u8, 13u8, 7u8, 2u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // initialize app
        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(get_user_info)))
            .with_state(state);

        // try request
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetUserInfoResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.user_id, 1);
    }

    #[tokio::test]
    async fn test_get_user_key() {
        // setup
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // add user
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'e0'), ('test2@test.com', X'00', X'00', X'ef'), ('test3@test.com', X'00', X'00', X'ed');", params![password_hash, salt]).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // initialize app
        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(get_user_key)))
            .with_state(state);

        // try request
        let request = Request::builder()
            .uri(format!("/?target_user_id=1&user_email=test@test.com&user_password_hash={encoded_password_hash}"))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetUserKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.key, vec![0xe0]);
    }

    // ==============================
    // GROUP endpoints
    // ==============================

    #[tokio::test]
    async fn test_get_group_by_id() {
        // setup
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        // add several users and a group
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (1, 2, 'group_name', X'00'), (1, 3, 'group_name', X'00');", []).unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00');", []).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/{group_id}", authenticated(&state, get(get_group_by_id)))
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/1?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetGroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.members.len(), 3);
        assert_eq!(
            body.members,
            vec![
                GetGroupItem {
                    user_id: 1,
                    email: "test@test.com".to_string()
                },
                GetGroupItem {
                    user_id: 2,
                    email: "test2@test.com".to_string()
                },
                GetGroupItem {
                    user_id: 3,
                    email: "test3@test.com".to_string()
                }
            ]
        );

        // try unauthenticated request
        let request = Request::builder()
            .uri(format!(
                "/2?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"User not present in group");
    }

    #[tokio::test]
    async fn test_get_group_key_by_id() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        let key = vec![22u8, 33u8, 11u8];
        conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00'), (3, 1, 'group_name', ?);", [&key]).unwrap();
        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route(
                "/{group_id}/key",
                authenticated(&state, get(get_group_key_by_id)),
            )
            .with_state(state);

        // try properly authenticated request
        let request = Request::builder()
            .uri(format!(
                "/1/key?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetGroupKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.encrypted_key, vec![0 as u8]);

        // try request to group that user is not part of
        let request = Request::builder()
            .uri(format!(
                "/2/key?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Failed to get group key");

        // try request to group where group key is a "
        let request = Request::builder()
            .uri(format!(
                "/3/key?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetGroupKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.encrypted_key, key);
    }

    #[tokio::test]
    pub async fn test_get_group_by_members() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        let salt = make_salt();
        let user_password_hash = vec![12u8, 8u8, 4u8, 13u8, 7u8, 2u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);

        conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![&password_hash, &salt]).unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (1, 2, 'group_name', X'00'), (1, 3, 'group_name', X'00'), (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00');", []).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(get_group_by_members)))
            .with_state(state);

        // try properly authenticated request
        let body = "{\"members\":[{\"user_id\":1,\"email\":\"test@test.com\"},{\"user_id\":2,\"email\":\"test2@test.com\"},{\"user_id\":3,\"email\":\"test3@test.com\"}]}";
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("GET")
            .body(Body::from(body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GetGroupsByMembersResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);

        // try one where the group doesn't exist
        let body = "{\"members\":[{\"user_id\":1,\"email\":\"test@test.com\"},{\"user_id\":2,\"email\":\"test2@test.com\"}]}";
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("GET")
            .body(Body::from(body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"No such group exists");

        // try one where not all users exist
        let body = "{\"members\":[{\"user_id\":1,\"email\":\"test@test.com\"},{\"user_id\":2,\"email\":\"test2@test.com\"}, {\"user_id\":3,\"email\":\"test3@test.com\"}, {\"user_id\":4,\"email\":\"test4@test.com\"}]}";
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("GET")
            .body(Body::from(body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Not all users exist");

        // try one group exists but user not in it
        let body = "{\"members\":[{\"user_id\":2,\"email\":\"test2@test.com\"}, {\"user_id\":3,\"email\":\"test3@test.com\"}]}";
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("GET")
            .body(Body::from(body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"User not present in group");
    }

    struct TestCreateGroupCleaner {}
    impl Drop for TestCreateGroupCleaner {
        fn drop(&mut self) {
            fs::remove_file("/tmp/test_create_group.db").unwrap();
        }
    }

    #[tokio::test]
    async fn test_create_group() {
        let _cleaner = TestCreateGroupCleaner {};
        let conn = Connection::open("/tmp/test_create_group.db").unwrap();
        db::init_db(&conn).unwrap();
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        conn.execute("INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![salt, password_hash]).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // initialize app
        let mut app = Router::new()
            .route("/", authenticated(&state, post(create_group)))
            .with_state(state);

        // try properly authenticated request
        let key = [0u8, 1u8];
        let key2 = [2u8, 3u8];
        let request_body = CreateGroupBody {
            members: vec![
                CreateGroupItem {
                    user_id: 1,
                    email: "test@test.com".to_string(),
                    encrypted_key: key.to_vec(),
                },
                CreateGroupItem {
                    user_id: 2,
                    email: "test2@test.com".to_string(),
                    encrypted_key: key2.to_vec(),
                },
            ],
        };
        let request_body = serde_json::to_string(&request_body).unwrap();
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: CreateGroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);
        let conn = Connection::open("/tmp/test_create_group.db").unwrap();
        let recovered_key = conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id=1 AND user_id=1",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(recovered_key, key);
        let recovered_key2 = conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id=1 AND user_id=2",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(recovered_key2, key2);

        // try when not all users exist
        let request_body = CreateGroupBody {
            members: vec![
                CreateGroupItem {
                    user_id: 1,
                    email: "test@test.com".to_string(),
                    encrypted_key: key.to_vec(),
                },
                CreateGroupItem {
                    user_id: 4,
                    email: "test2@test.com".to_string(),
                    encrypted_key: key2.to_vec(),
                },
            ],
        };
        let request_body = serde_json::to_string(&request_body).unwrap();
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Not all users exist");

        // try when user not present
        let request_body = CreateGroupBody {
            members: vec![CreateGroupItem {
                user_id: 2,
                email: "test2@test.com".to_string(),
                encrypted_key: key2.to_vec(),
            }],
        };
        let request_body = serde_json::to_string(&request_body).unwrap();
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"User not present in group");

        // try when group already exists
        let request_body = CreateGroupBody {
            members: vec![
                CreateGroupItem {
                    user_id: 1,
                    email: "test@test.com".to_string(),
                    encrypted_key: key.to_vec(),
                },
                CreateGroupItem {
                    user_id: 2,
                    email: "test2@test.com".to_string(),
                    encrypted_key: key2.to_vec(),
                },
            ],
        };
        let request_body = serde_json::to_string(&request_body).unwrap();
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: CreateGroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);
    }

    #[tokio::test]
    async fn test_register_user() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();

        // initialize state
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = HandlerState {
            tx,
            upload_directory: "".to_string(),
        };
        tokio::spawn(connection_task(conn, rx));

        // initialize app
        // build app
        let app = Router::new()
            .route("/", post(register_user))
            .with_state(state);

        // create user parameters
        let user_password_hash: Vec<u8> = b"PASSWORD".to_vec();
        let key: Vec<u8> = b"PKPUB".to_vec();

        let body = json!({
            "user_email": "test@test.test",
            "user_password_hash": BASE64_STANDARD.encode(user_password_hash),
            "key": BASE64_STANDARD.encode(key),
        })
        .to_string();

        // try request
        let request = Request::builder()
            .uri("/")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_user: RegisterUserResponse = from_slice(&body).unwrap();
        assert!(response_user.id > 0);
    }
}
