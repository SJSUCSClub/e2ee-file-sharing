use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListFilesItem {
    pub file_name: String,
    pub file_id: i64,
    pub group_name: String,
    pub group_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListFilesResponse {
    pub files: Vec<ListFilesItem>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetFileQueryParams {
    pub file_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UploadFileQueryParams {
    pub group_id: i64,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UploadFileResponse {
    pub file_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetUserInfoResponse {
    pub user_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetUserKeyQueryParams {
    pub target_user_id: i64,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetUserKeyResponse {
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterUser {
    pub user_email: String,
    pub user_password_hash: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RegisterUserResponse {
    pub id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupItem {
    pub email: String,
    pub user_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupResponse {
    pub members: Vec<GetGroupItem>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupKeyResponse {
    pub encrypted_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetGroupByMembersResponse {
    pub group_id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateGroupItem {
    pub user_id: i64,
    pub email: String,
    pub encrypted_key: Vec<u8>,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateGroupBody {
    pub members: Vec<CreateGroupItem>,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateGroupResponse {
    pub group_id: i64,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListGroupsItem {
    pub group_id: i64,
    pub name: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListGroupsResponse {
    pub groups: Vec<ListGroupsItem>,
}
