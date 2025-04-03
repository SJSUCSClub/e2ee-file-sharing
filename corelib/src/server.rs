use rand::RngCore;
use sha2::Digest;

/// Generates a random salt
///
/// # Returns
///
/// A random 8-byte salt, as bytes
pub fn make_salt() -> [u8; 8] {
    let mut bytes = [0; 8]; // 8-byte salt
    let mut rng = rand::thread_rng();
    rng.try_fill_bytes(&mut bytes).unwrap();
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
pub fn salt_password(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(password);
    hasher.update(&salt);
    hasher.finalize().to_vec()
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
