use serde::{Deserialize, Serialize};

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct FileInfo {
    /// the name of the file that was uploaded
    pub file_name: String,
    /// the id of the file, guaranteed to be unique
    pub file_id: i64,
    /// the name of the group that the file belongs to
    /// name can be different per user/group pair
    pub group_name: String,
    /// the id of the group, guaranteed to be unique
    pub group_id: i64,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct FileInfos {
    /// list of files
    pub files: Vec<FileInfo>,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct FileID {
    /// the id of the file, guaranteed to be unique
    pub file_id: i64,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct UserID {
    /// the id of the user, guaranteed to be unique
    pub user_id: i64,
}
#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct GroupID {
    /// the id of the group, guaranteed to be unique
    pub group_id: i64,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct Key {
    /// base64 encoded bytes
    pub key: String,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct User {
    /// user email
    pub user_email: String,
    /// the id of the user, guaranteed to be unique
    pub user_id: i64,
}
#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UserWithKey {
    /// user email
    pub user_email: String,
    /// the id of the user, guaranteed to be unique
    pub user_id: i64,
    /// Base64 encoded key
    pub key: String,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct UserWithKeyAndPassword {
    /// user email
    pub user_email: String,
    /// Base64 encoded password hash
    pub user_password_hash: String,
    /// Base64 encoded public key
    pub key: String,
}

#[derive(utoipa::ToSchema, Serialize, Deserialize, Debug)]
pub struct GroupMembers {
    /// list of all members of the group
    pub members: Vec<User>,
}

#[derive(utoipa::ToSchema, Deserialize, Serialize, Debug)]
pub struct GroupMembersWithKey {
    /// list of all members of the group, including their encoded
    /// AES key
    pub members: Vec<UserWithKey>,
}

#[derive(utoipa::ToSchema, Deserialize, Serialize, Debug)]
pub struct Group {
    /// the id of the group, guaranteed to be unique
    pub group_id: i64,
    /// the name of the group
    pub name: String,
}
#[derive(utoipa::ToSchema, Deserialize, Serialize, Debug)]
pub struct Groups {
    pub groups: Vec<Group>,
}
