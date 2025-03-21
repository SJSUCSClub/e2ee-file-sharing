use rand::RngCore;
use sha2::Digest;

pub fn make_salt() -> u64 {
    let mut bytes = [0; 8];
    let mut rng = rand::thread_rng();
    rng.try_fill_bytes(&mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

pub fn salt_password(password: &str, salt: u64) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(password);
    hasher.update(salt.to_le_bytes());
    hasher.finalize().to_vec()
}
