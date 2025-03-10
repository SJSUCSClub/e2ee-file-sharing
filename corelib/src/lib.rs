use aes_gcm::{Aes256Gcm, Key};
use argon2::{Algorithm, Argon2, Params, Version};

/// AES-256 key size in bytes. Same as [Aes256Gcm::key_size].
const MASTER_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    pub fn derive(email: &str, password: &str) -> Self {
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::default(),
            Params::new(
                Params::DEFAULT_M_COST,
                Params::DEFAULT_P_COST,
                Params::DEFAULT_P_COST,
                Some(MASTER_KEY_LEN),
            )
            .expect("argon2::Params construction should succeed"),
        );

        let mut hash_bytes = [0u8; MASTER_KEY_LEN];
        argon
            .hash_password_into(
                password.as_bytes(),
                email.as_bytes(),
                hash_bytes.as_mut_slice(),
            )
            .expect("argon2 hash should succeed");

        MasterKey { key: hash_bytes }
    }

    pub fn as_aes256gcm_key(self: &Self) -> &Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(self.key.as_slice())
    }
}

impl Into<Key<Aes256Gcm>> for MasterKey {
    fn into(self) -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from(self.key)
    }
}
