use axum::{
    Extension, Json,
    body::Body,
    extract::{Multipart, Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE, Engine as _};
use corelib::server::{make_salt, salt_password};
use models::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};
use tokio_util::io::ReaderStream;

use crate::db::{self, Database};

// ==============================
// Misc
// ==============================
fn to_path(upload_directory: &str, file_id: i64) -> String {
    format!("{upload_directory}/{file_id}")
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
    pub new_db: Arc<Box<dyn Fn() -> Database + Send + Sync>>,
}

impl HandlerState {
    thread_local! {
        static DB: RefCell<Option<Database>> = const { RefCell::new(None) };
    }

    // https://www.reddit.com/r/rust/comments/1e6dqz1/thread_local_smart_pointer/
    // hence `RefCell::borrow_mut` is not available, hence the need to use a closure.

    pub fn run_with_db<F, R>(st: &HandlerState, callback: F) -> R
    where
        F: FnOnce(&Database) -> R,
    {
        HandlerState::DB.with_borrow_mut(|opt| {
            let db = opt.get_or_insert_with(|| (st.new_db)());
            callback(&db)
        })
    }
}

// task thread that manages a connection
pub(crate) enum DatabaseCommand {
    InsertFile {
        group_id: i64,
        filename: String,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    CreateGroup {
        members: Vec<(i64, Vec<u8>)>,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
    RegisterUser {
        user_email: String,
        user_password_hash: Vec<u8>,
        salt: [u8; 8],
        pub_key: Vec<u8>,
        responder: oneshot::Sender<rusqlite::Result<i64>>,
    },
}
pub(crate) async fn connection_task(mut db: Database, mut rx: mpsc::Receiver<DatabaseCommand>) {
    use DatabaseCommand::*;
    while let Some(cmd) = rx.recv().await {
        match cmd {
            InsertFile {
                group_id,
                filename,
                responder,
            } => {
                responder
                    .send(db::insert_file(&mut db, group_id, &filename))
                    .unwrap();
            }
            CreateGroup { members, responder } => {
                responder.send(db::create_group(&mut db, members)).unwrap();
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
                        &mut db,
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

#[derive(utoipa::IntoParams, Deserialize, Debug)]
#[into_params(style=Form, parameter_in = Query)]
pub(crate) struct UserAuth {
    /// user email address
    user_email: String,
    /// url-safe base64 encoded password hash
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
    // decode password
    let decoded_password = match BASE64_URL_SAFE.decode(params.user_password_hash) {
        Ok(decoded) => decoded,
        Err(e) => {
            println!("Failed to decode password with {e:?}");
            return (StatusCode::UNAUTHORIZED, "Invalid base64 encoding").into_response();
        }
    };

    // query db
    let user_id = HandlerState::run_with_db(&st, |db| {
        db::get_user_id(db, &params.user_email, &decoded_password)
    });
    let user_id = match user_id {
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

// TODO - ideally upload and download
// would stream data instead of just using
// multipart/form-data because this would
// allow easy handling of large files.
/// List all files that the user has access to
#[utoipa::path(
    get,
    path = "/api/v1/list-files",
    tag = "Files",
    responses(
        (status=OK, body=FileInfos, description="List of files"),
        (status=BAD_REQUEST, description="Failed to get files"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        UserAuth
    ),
)]
pub(crate) async fn list_files(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // get all files that match this user id
    let files_vec =
        match HandlerState::run_with_db(&st, |db| db::get_files_for_user_id(db, user_id)) {
            Ok(files) => files,
            Err(e) => {
                println!("Error getting files: {e:?}!");
                return (StatusCode::BAD_REQUEST, "Failed to get files!").into_response();
            }
        };

    // return the files, as proper response
    let files = files_vec
        .iter()
        .map(|(file_name, file_id, group_name, group_id)| FileInfo {
            file_name: file_name.clone(),
            file_id: *file_id,
            group_name: group_name.clone(),
            group_id: *group_id,
        })
        .collect();
    let response = FileInfos { files };
    (StatusCode::OK, Json(response)).into_response()
}

#[derive(utoipa::IntoParams, Deserialize, Debug)]
#[into_params(style=Form, parameter_in = Query)]
pub(crate) struct GetFileQueryParams {
    file_id: i64,
}

/// Download the requested file
#[utoipa::path(
    get,
    path = "/api/v1/file",
    tag = "Files",
    responses(
        (status=OK, body=String, content_type="application/octet-stream",  description="File contents"),
        (status=BAD_REQUEST, description="Nonexistent file or permission denied"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        UserAuth,
        GetFileQueryParams
    ),
)]
pub(crate) async fn get_file(
    Query(params): Query<GetFileQueryParams>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> Response {
    // authentication succeeded, proceed to get the file storage location
    // get the file name
    let info =
        match HandlerState::run_with_db(&st, |db| db::get_file_info(db, user_id, params.file_id)) {
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

#[derive(utoipa::IntoParams, Deserialize, Debug)]
#[into_params(style=Form, parameter_in = Query)]
pub(crate) struct UploadFileQueryParams {
    group_id: i64,
}

// struct to outline the structure of the form
// that should be submitted to the endpoint
#[derive(utoipa::ToSchema)]
#[allow(unused)]
struct FileForm {
    #[schema(format=Binary, content_media_type="application/octet-stream")]
    file: String,
}

/// Upload a file
#[utoipa::path(
    post,
    path = "/api/v1/file",
    tag = "Files",
    responses(
        (status=OK, body=FileId, description="File id"),
        (status=BAD_REQUEST, description="Failed to get group or user not in group"),
        (status=INTERNAL_SERVER_ERROR, description="Failed to save file or database error"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        UserAuth,
        UploadFileQueryParams
    ),
    request_body(content_type = "multipart/form-data", content = FileForm)
)]
pub(crate) async fn upload_file(
    Query(params): Query<UploadFileQueryParams>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    mut multipart: Multipart,
) -> Response {
    // check if user is in the group
    // since this is a read, then we can use threadlocal read-only connection
    let group = match HandlerState::run_with_db(&st, |db| db::get_group(db, params.group_id)) {
        Ok(group) => group,
        Err(e) => {
            println!("Failed to get group {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group").into_response();
        }
    };
    if !group.iter().any(|user| user.1 == user_id) {
        return (StatusCode::BAD_REQUEST, "User not in group").into_response();
    }

    // now actually do the writing
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name();
        match field_name {
            Some("file") => {
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
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to insert file")
                            .into_response();
                    }
                };

                // write that to a file
                // since files are uniquely identified by their file id, then we
                // can simply save as the file id
                // and later fetch files by their file_id
                let path = to_path(&st.upload_directory, file_id);
                if let Err(e) = tokio::fs::write(path, data).await {
                    println!("Failed to save file with {e:?}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file")
                        .into_response();
                } else {
                    return (StatusCode::OK, Json(FileId { file_id })).into_response();
                }
            }
            // ignore other fields
            _ => (),
        }
    }
    (StatusCode::BAD_REQUEST, "No file body provided").into_response()
}

/// Get file info (file name, file id, group name, group id)
#[utoipa::path(
    get,
    path = "/api/v1/file/{file_id}/info",
    tag = "Files",
    responses(
        (status=OK, body=FileInfo, description="File info"),
        (status=BAD_REQUEST, description="No such file or user not in group"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        ("file_id" = i64, Path, description="File id"),
        UserAuth,
    ),
)]
pub(crate) async fn get_file_info(
    Path(file_id): Path<i64>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    State(st): State<HandlerState>,
) -> Response {
    // get read-only database connection
    match HandlerState::run_with_db(&st, |db| db::get_file_info(db, user_id, file_id)) {
        Ok(info) => (
            StatusCode::OK,
            Json(FileInfo {
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

/// Get user info (user id)
#[utoipa::path(
    get,
    path = "/api/v1/user/info",
    tag = "Users",
    responses(
        (status=OK, body=UserId, description="User info"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        UserAuth
    ),
)]
pub(crate) async fn get_user_info(
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(UserId { user_id }))
}

#[derive(utoipa::IntoParams, Deserialize, Debug)]
#[into_params(style=Form, parameter_in = Query)]
pub(crate) struct GetUserKeyQueryParams {
    target_user_id: i64,
}

/// Get a user's public key
#[utoipa::path(
    get,
    path = "/api/v1/user/key",
    tag = "Users",
    responses(
        (status=OK, body=Key, description="Standard base64 encoded user public key"),
        (status=BAD_REQUEST, description="Failed to get user key"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding")
    ),
    params(
        UserAuth,
        GetUserKeyQueryParams
    ),
)]
pub(crate) async fn get_user_key(
    Query(params): Query<GetUserKeyQueryParams>,
    Extension(_): Extension<UserAuthExtension>,
    State(st): State<HandlerState>,
) -> Response {
    // get db
    let key = match HandlerState::run_with_db(&st, |db| db::get_user_key(db, params.target_user_id))
    {
        Ok(key) => key,
        Err(e) => {
            println!("Failed to get user key with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get user key").into_response();
        }
    };
    let key = BASE64_STANDARD.encode(key);
    (StatusCode::OK, Json(Key { key })).into_response()
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/api/v1/user",
    tag = "Users",
    responses(
        (status=OK, body=UserId, description="User Id"),
        (status=BAD_REQUEST, description="Failed to register user"),
        (status=CONFLICT, description="Email is already taken"),
    ),
    request_body=UserWithKeyAndPassword
)]
pub(crate) async fn register_user(
    State(st): State<HandlerState>,
    Json(params): Json<UserWithKeyAndPassword>,
) -> Response {
    // first, convert password and key into bytes
    let password_bytes = BASE64_STANDARD.decode(&params.user_password_hash).unwrap();
    let key_bytes = BASE64_STANDARD.decode(&params.key).unwrap();

    // then, salt and hash the password
    let salt = make_salt();
    let hashed_password2: Vec<u8> = salt_password(password_bytes.as_slice(), &salt);

    // send request to writing db thread
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::RegisterUser {
            user_email: params.user_email,
            user_password_hash: hashed_password2,
            salt,
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
    (StatusCode::OK, Json(UserId { user_id: id })).into_response()
}

// ==============================
// GROUPS endpoints
// ==============================

/// Get group members
#[utoipa::path(
    get,
    path = "/api/v1/group/{group_id}/members",
    tag = "Groups",
    responses(
        (status=OK, body=GroupMembers, description="Group members"),
        (status=BAD_REQUEST, description="Failed to get group members"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding"),
    ),
    params(
        ("group_id" = i64, Path, description = "Group id"),
        UserAuth,
    )
)]
pub(crate) async fn get_group_by_id(
    Path(group_id): Path<i64>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // send request
    let group_members = match HandlerState::run_with_db(&st, |db| db::get_group(db, group_id)) {
        Ok(group_members) => group_members,
        Err(e) => {
            println!("Failed to get group members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group members").into_response();
        }
    };

    // collect into proper format
    let mut members = Vec::new();
    for (email, user_id) in group_members {
        members.push(User {
            user_email: email,
            user_id,
        });
    }

    // validate that the user is in the group before returning
    if !members.iter().any(|member| member.user_id == user_id) {
        return (StatusCode::UNAUTHORIZED, "User not present in group").into_response();
    }
    (StatusCode::OK, Json(GroupMembers { members })).into_response()
}

/// Get the group key encrypted for the calling user
#[utoipa::path(
    get,
    path = "/api/v1/group/{group_id}/key",
    tag = "Groups",
    responses(
        (status=OK, body=Key, description="Standard base-64 encoded AES group key"),
        (status=BAD_REQUEST, description="Failed to get group key"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding"),
    ),
    params(
        ("group_id" = i64, Path, description = "Group id"),
        UserAuth,
    )
)]
pub(crate) async fn get_group_key_by_id(
    Path(group_id): Path<i64>,
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // send request
    let encrypted_key =
        match HandlerState::run_with_db(&st, |db| db::get_group_key(db, group_id, user_id)) {
            Ok(encrypted_key) => encrypted_key,
            Err(e) => {
                println!("Failed to get group key with {e:?}");
                return (StatusCode::BAD_REQUEST, "Failed to get group key").into_response();
            }
        };
    let key = BASE64_STANDARD.encode(encrypted_key);

    (StatusCode::OK, Json(Key { key })).into_response()
}

/// Get the group Id for the group
/// containing the given members
#[utoipa::path(
    get,
    path = "/api/v1/group",
    tag = "Groups",
    responses(
        (status=OK, body=GroupMembers, description="Group id"),
        (status=BAD_REQUEST, description="Failed to get group id"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding"),
    ),
    params(
        UserAuth,
    ),
    request_body = GroupId
)]
pub(crate) async fn get_group_by_members(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    Json(body): Json<GroupMembers>,
) -> impl IntoResponse {
    // validate that all users exist
    let existing_users = match HandlerState::run_with_db(&st, |db| {
        db::get_existing_users(
            db,
            body.members
                .iter()
                .map(|m| (m.user_id, m.user_email.clone()))
                .collect(),
        )
    }) {
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
    let group_id = match HandlerState::run_with_db(&st, |db| {
        db::get_group_id(db, body.members.iter().map(|m| m.user_id).collect())
    }) {
        Ok(group_id) => group_id,
        Err(e) => {
            println!("Failed to get group by members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group by members").into_response();
        }
    };

    // return either the group id or a 404
    match group_id {
        Some(group_id) => (StatusCode::OK, Json(GroupId { group_id })).into_response(),
        None => (StatusCode::NOT_FOUND, "No such group exists").into_response(),
    }
}

/// Create a new group
#[utoipa::path(
    post,
    path = "/api/v1/group",
    tag = "Groups",
    responses(
        (status=OK, body=GroupId, description="Group id"),
        (status=BAD_REQUEST, description="Failed to create group"),
        (status=CONFLICT, description="Group already exists"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding"),
    ),
    params(
        UserAuth,
    ),
    request_body = GroupMembersWithKey
)]
pub(crate) async fn create_group(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
    Json(body): Json<GroupMembersWithKey>,
) -> impl IntoResponse {
    // validate that all users exist
    let existing_users = match HandlerState::run_with_db(&st, |db| {
        db::get_existing_users(
            db,
            body.members
                .iter()
                .map(|m| (m.user_id, m.user_email.clone()))
                .collect(),
        )
    }) {
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

    // check if such a group exists before creating
    let group_id = match HandlerState::run_with_db(&st, |db| {
        db::get_group_id(db, body.members.iter().map(|m| m.user_id).collect())
    }) {
        Ok(group_id) => group_id,
        Err(e) => {
            println!("Failed to get group by members with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to get group by members").into_response();
        }
    };
    if let Some(group_id) = group_id {
        // then return 409 and the group id
        return (StatusCode::CONFLICT, Json(GroupId { group_id })).into_response();
    }
    // so now actually create group with the writeable db
    let (tx, rx) = oneshot::channel();
    st.tx
        .send(DatabaseCommand::CreateGroup {
            members: body
                .members
                .into_iter()
                .map(|m| (m.user_id, BASE64_STANDARD.decode(m.key).unwrap()))
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
    (StatusCode::OK, Json(GroupId { group_id })).into_response()
}

/// List all groups that the user has access to
#[utoipa::path(
    get,
    path = "/api/v1/list-groups",
    tag = "Groups",
    responses(
        (status=OK, body=Groups, description="Groups"),
        (status=BAD_REQUEST, description="Failed to list groups"),
        (status=UNAUTHORIZED, description="User email and password mismatch or improper base64 password encoding"),
    ),
    params(
        UserAuth,
    )
)]
pub(crate) async fn list_groups(
    State(st): State<HandlerState>,
    Extension(UserAuthExtension { user_id }): Extension<UserAuthExtension>,
) -> impl IntoResponse {
    // extract and convert to response type
    let groups = match HandlerState::run_with_db(&st, |db| db::get_groups_for_user_id(db, user_id))
    {
        Ok(groups) => groups,
        Err(e) => {
            println!("Failed to list groups with {e:?}");
            return (StatusCode::BAD_REQUEST, "Failed to list groups").into_response();
        }
    };
    let groups = groups
        .into_iter()
        .map(|g| Group {
            group_id: g.0,
            name: g.1,
        })
        .collect();
    // send response
    (StatusCode::OK, Json(Groups { groups })).into_response()
}

// ==============================
// Tests
// ==============================

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        http::Request,
        middleware::from_fn_with_state,
        routing::{get, post},
    };
    use http_body_util::BodyExt;
    use rusqlite::params;
    use serde_json::{from_slice, json};
    use std::sync::atomic::AtomicUsize;
    use std::{fs, vec};
    use tower::{Service, ServiceExt};

    use crate::db;

    use super::*;
    use corelib::server::{make_salt, salt_password};

    // ==============================
    // AUTH endpoints
    // ==============================
    // dummy endpoint for testing that auth works
    async fn hello() -> &'static str {
        "This is the ACM E2E file sharing server instance."
    }
    // helper function that way we don't have to write .layer
    // on every authenticated endpoint
    pub(crate) fn authenticated(
        state: &HandlerState,
        a: axum::routing::MethodRouter<HandlerState>,
    ) -> axum::routing::MethodRouter<HandlerState> {
        a.layer(from_fn_with_state(state.clone(), user_auth))
    }

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

    // test id counter
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    fn setup_http_server(upload_directory: &str) -> (Database, HandlerState) {
        let value = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let db_path = format!("file:{}?mode=memory&cache=shared", value);

        let mut db = Database::open(&db_path).unwrap();
        db::init_db(&mut db).unwrap();

        // Extra SQLite connection for inspecting and manipulating database contents by the test code
        let mut db_for_test_harness = Database::open(&db_path).unwrap();

        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(connection_task(db, rx));

        let state = HandlerState {
            tx,
            upload_directory: upload_directory.to_string(),
            new_db: Arc::new(Box::new(move || Database::open(&db_path).unwrap())),
        };

        (db_for_test_harness, state)
    }

    #[tokio::test]
    async fn test_auth() {
        // setup
        let (db, state) = setup_http_server("");
        // and add an initial user
        let salt = make_salt();
        let user_password_hash = vec![1u8, 22u8, 33u8, 7u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        // initialize state

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
        let (db, state) = setup_http_server("");
        let conn = &db.conn;
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
        let body: FileInfos = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body.files,
            vec![
                FileInfo {
                    file_id: 1,
                    file_name: "test_file.txt".to_string(),
                    group_name: "group_name".to_string(),
                    group_id: 1
                },
                FileInfo {
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
        let upload_directory = "/tmp/upload-e2e-test";
        let (db, state) = setup_http_server(upload_directory);
        let conn = &db.conn;
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
        let upload_directory = "/tmp/upload-e2e-test-upload";
        let (db, state) = setup_http_server(upload_directory);
        tokio::fs::create_dir_all(upload_directory).await.unwrap();
        // and add an initial user and such
        let salt = make_salt();
        let user_password_hash = vec![3u8, 15u8, 2u8, 10u8, 3u8, 3u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        // add group and add dummy user
        db.conn.execute_batch("
            INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');
            INSERT INTO groups (id) VALUES (NULL), (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (2, 2, 'second', X'00');
        ").unwrap();

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, post(upload_file)))
            .with_state(state);

        // try properly authenticated request
        // make request body
        let data = "--MYBOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nHELLO WORLD\r\n--MYBOUNDARY\r\n";
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
        let body: FileId = serde_json::from_slice(&body).unwrap();
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
        let (db, state) = setup_http_server("");
        // add user
        let salt = make_salt();
        let user_password_hash = vec![11u8, 10u8, 12u8, 11u8, 10u8, 12u8];
        let server_password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00');", params![server_password_hash, salt]).unwrap();
        db.conn.execute_batch("
            INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');
            INSERT INTO groups (id) VALUES (NULL), (NULL);
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (2, 2, 'second', X'00');
            INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt'), (2, 'test_file2.txt');
        ").unwrap();

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
        let body: FileInfo = serde_json::from_slice(&body).unwrap();
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
        let (db, state) = setup_http_server("");
        // add user
        let salt = make_salt();
        let user_password_hash = vec![12u8, 8u8, 4u8, 13u8, 7u8, 2u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();

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
        let body: UserId = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.user_id, 1);
    }

    #[tokio::test]
    async fn test_get_user_key() {
        // setup
        let (db, state) = setup_http_server("");
        // add user
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'e0'), ('test2@test.com', X'00', X'00', X'ef'), ('test3@test.com', X'00', X'00', X'ed');", params![password_hash, salt]).unwrap();

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
        let body: Key = serde_json::from_slice(&body).unwrap();
        let key = BASE64_STANDARD.decode(body.key).unwrap();
        assert_eq!(key, vec![0xe0]);
    }

    // ==============================
    // GROUP endpoints
    // ==============================

    #[tokio::test]
    async fn test_get_group_by_id() {
        // setup
        let (db, state) = setup_http_server("");
        // add several users and a group
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (1, 2, 'group_name', X'00'), (1, 3, 'group_name', X'00');", []).unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00');", []).unwrap();

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
        let body: GroupMembers = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.members.len(), 3);
        assert_eq!(
            body.members,
            vec![
                User {
                    user_id: 1,
                    user_email: "test@test.com".to_string()
                },
                User {
                    user_id: 2,
                    user_email: "test2@test.com".to_string()
                },
                User {
                    user_id: 3,
                    user_email: "test3@test.com".to_string()
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
        let (db, state) = setup_http_server("");
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![password_hash, salt]).unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        let key = vec![22u8, 33u8, 11u8];
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'ef'), (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00'), (3, 1, 'group_name', ?);", [&key]).unwrap();

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
        let body: Key = serde_json::from_slice(&body).unwrap();
        let retrieved_key = BASE64_STANDARD.decode(body.key).unwrap();
        assert_eq!(retrieved_key, vec![0xef as u8]);

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
        let body: Key = serde_json::from_slice(&body).unwrap();
        let retrieved_key = BASE64_STANDARD.decode(body.key).unwrap();
        assert_eq!(retrieved_key, key);
    }

    #[tokio::test]
    pub async fn test_get_group_by_members() {
        let (db, state) = setup_http_server("");
        let salt = make_salt();
        let user_password_hash = vec![12u8, 8u8, 4u8, 13u8, 7u8, 2u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);

        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![&password_hash, &salt]).unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .unwrap();
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00'), (1, 2, 'group_name', X'00'), (1, 3, 'group_name', X'00'), (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00');", []).unwrap();

        // build app
        let mut app = Router::new()
            .route("/", authenticated(&state, get(get_group_by_members)))
            .with_state(state);

        // try properly authenticated request
        let body = "{\"members\":[{\"user_id\":1,\"user_email\":\"test@test.com\"},{\"user_id\":2,\"user_email\":\"test2@test.com\"},{\"user_id\":3,\"user_email\":\"test3@test.com\"}]}";
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
        let body: GroupId = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);

        // try one where the group doesn't exist
        let body = "{\"members\":[{\"user_id\":1,\"user_email\":\"test@test.com\"},{\"user_id\":2,\"user_email\":\"test2@test.com\"}]}";
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
        let body = "{\"members\":[{\"user_id\":1,\"user_email\":\"test@test.com\"},{\"user_id\":2,\"user_email\":\"test2@test.com\"}, {\"user_id\":3,\"user_email\":\"test3@test.com\"}, {\"user_id\":4,\"user_email\":\"test4@test.com\"}]}";
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
        let body = "{\"members\":[{\"user_id\":2,\"user_email\":\"test2@test.com\"}, {\"user_id\":3,\"user_email\":\"test3@test.com\"}]}";
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

    #[tokio::test]
    async fn test_create_group() {
        let (db, state) = setup_http_server("");
        let salt = make_salt();
        let user_password_hash = vec![12u8, 12u8, 13u8, 13u8, 7u8, 7u8];
        let password_hash = salt_password(&user_password_hash, &salt);
        let encoded_password_hash = BASE64_URL_SAFE.encode(&user_password_hash);
        db.conn.execute("INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test@test.com', ?, ?, X'00'), ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00');", params![salt, password_hash]).unwrap();

        // initialize app
        let mut app = Router::new()
            .route("/", authenticated(&state, post(create_group)))
            .with_state(state);

        // try properly authenticated request
        let key = [0u8, 1u8];
        let key2 = [2u8, 3u8];
        let request_body = GroupMembersWithKey {
            members: vec![
                UserWithKey {
                    user_id: 1,
                    user_email: "test@test.com".to_string(),
                    key: BASE64_STANDARD.encode(key.to_vec()),
                },
                UserWithKey {
                    user_id: 2,
                    user_email: "test2@test.com".to_string(),
                    key: BASE64_STANDARD.encode(key2.to_vec()),
                },
            ],
        };
        let request_body_good = serde_json::to_string(&request_body).unwrap();
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body_good.clone()))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GroupId = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);
        let recovered_key = db
            .conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id=1 AND user_id=1",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(recovered_key, key);
        let recovered_key2 = db
            .conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id=1 AND user_id=2",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(recovered_key2, key2);

        // try when not all users exist
        let request_body = GroupMembersWithKey {
            members: vec![
                UserWithKey {
                    user_id: 1,
                    user_email: "test@test.com".to_string(),
                    key: BASE64_STANDARD.encode(key.to_vec()),
                },
                UserWithKey {
                    user_id: 4,
                    user_email: "test2@test.com".to_string(),
                    key: BASE64_STANDARD.encode(key2.to_vec()),
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
        let request_body = GroupMembersWithKey {
            members: vec![UserWithKey {
                user_id: 2,
                user_email: "test2@test.com".to_string(),
                key: BASE64_STANDARD.encode(key2.to_vec()),
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
        let request = Request::builder()
            .uri(format!(
                "/?user_email=test@test.com&user_password_hash={encoded_password_hash}"
            ))
            .header("Content-Type", "application/json")
            .method("POST")
            .body(Body::from(request_body_good))
            .unwrap();
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: GroupId = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.group_id, 1);
    }

    #[tokio::test]
    async fn test_register_user() {
        let (db, state) = setup_http_server("");

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
        let response_user: UserId = from_slice(&body).unwrap();
        assert!(response_user.user_id > 0);
    }
}
