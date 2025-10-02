use aws_lc_rs::{
    digest::{Context, SHA256, SHA256_OUTPUT_LEN},
    rand::{self},
};

const SALT_BYTES: usize = 8;

/// Generates a random salt
///
/// # Returns
///
/// A random 8-byte salt, as bytes
pub fn make_salt() -> [u8; SALT_BYTES] {
    let mut bytes = [0; SALT_BYTES]; // 8-byte salt
    rand::fill(&mut bytes).unwrap();
    bytes
}

/// Hashes a password with a salt
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - The salt to use
///
/// # Returns
///
/// The hashed password, as bytes
pub fn salt_password(password: &[u8], salt: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(password);
    ctx.update(salt);

    let mut res: [u8; 32] = [0; 32];
    res.copy_from_slice(ctx.finish().as_ref());
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_password() {
        let password = b"password123";
        let salt = make_salt();
        let salted_password = salt_password(password, &salt);
        let salted_password_2 = salt_password(password, &salt);
        assert_eq!(salted_password, salted_password_2);
    }
}
