use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, AeadInPlace, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{
    Pkcs1v15Encrypt,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, digest::generic_array::GenericArray};

/// AES-256 key size in bytes. Same as [Aes256Gcm::key_size].
const PERSONAL_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct PersonalKey {
    /// An AES-256 key.
    /// Corresponds to *PersonalKey* from the Cryptography Outline.
    key: [u8; PERSONAL_KEY_LEN],
}

impl PersonalKey {
    /// Deterministic key derivation using Argon2id.
    pub fn derive(email: &str, password: &str) -> Self {
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::default(),
            Params::new(
                Params::DEFAULT_M_COST,
                Params::DEFAULT_P_COST,
                Params::DEFAULT_P_COST,
                Some(PERSONAL_KEY_LEN),
            )
            .expect("argon2::Params construction failed"),
        );

        let mut hash_bytes = [0u8; PERSONAL_KEY_LEN];
        argon
            .hash_password_into(
                password.as_bytes(),
                email.as_bytes(),
                hash_bytes.as_mut_slice(),
            )
            .expect("argon2 hash failed");

        PersonalKey { key: hash_bytes }
    }

    /// Produce *PasswordHash1* from the Cryptography Outline.
    pub fn hash(self: &Self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        hasher.finalize().into()
    }

    pub fn as_aes256gcm_key(self: &Self) -> &Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(self.key.as_slice())
    }
}

impl Into<Key<Aes256Gcm>> for PersonalKey {
    fn into(self) -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from(self.key)
    }
}

/// In-memory only.
pub struct PkKeyPair {
    // PkPub - RSA
    // PkPriv - RSA
    pkpub: RsaPublicKey,
    pkpriv: RsaPrivateKey,
}

/// OpenSSH default length as of 2025.
const RSA_BITS: usize = 3072;

impl PkKeyPair {
    pub fn new() -> Self {
        // generates pkpub and pkpriv
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, RSA_BITS).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        PkKeyPair {
            pkpub: pub_key,
            pkpriv: priv_key,
        }
    }

    /// Decrypts a group key with the private key of the user.
    pub fn get_group_key(&self, group_key_encrypted: &[u8]) -> GroupKey {
        // decrypt the encrypted group key with the private key
        GroupKey {
            key: self
                .pkpriv
                .decrypt(Pkcs1v15Encrypt, group_key_encrypted)
                .expect("Failed to decrypt key"),
        }
    }
}

/// On-disk storage format.
#[derive(Serialize, Deserialize)]
pub struct DiskKeys {
    nonce: Vec<u8>,        // 12 bytes
    pk_pub: String,        // pem
    pk_priv_prot: Vec<u8>, // pem, encoded with the aes key
}

impl DiskKeys {
    pub fn new(personal_key: &PersonalKey, kp: &PkKeyPair) -> Self {
        let encoded_pk_pub =
            EncodePublicKey::to_public_key_pem(&kp.pkpub, pkcs8::LineEnding::LF).unwrap();

        // generate pk_priv_prot
        // by encrypting pkpriv with the aes key and the nonce
        let cipher = Aes256Gcm::new(personal_key.as_aes256gcm_key());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut encoded_pk_priv = EncodePrivateKey::to_pkcs8_pem(&kp.pkpriv, pkcs8::LineEnding::LF)
            .unwrap()
            .as_bytes()
            .to_vec();
        cipher
            .encrypt_in_place(&nonce, b"", &mut encoded_pk_priv)
            .expect("AES-GCM encrypt failed");

        DiskKeys {
            nonce: nonce.to_vec(),
            pk_pub: encoded_pk_pub,
            pk_priv_prot: encoded_pk_priv,
        }
    }

    pub fn to_memory(self, personal_key: &PersonalKey) -> PkKeyPair {
        let cipher = Aes256Gcm::new(personal_key.as_aes256gcm_key());
        let nonce = GenericArray::from_slice(self.nonce.as_slice());

        let mut buffer = self.pk_priv_prot;
        cipher
            .decrypt_in_place(&nonce, b"", &mut buffer)
            .expect("Failed to decrypt priv key!");

        PkKeyPair {
            pkpub: DecodePublicKey::from_public_key_pem(&self.pk_pub).unwrap(),
            pkpriv: DecodePrivateKey::from_pkcs8_pem(&String::from_utf8(buffer).unwrap()).unwrap(),
        }
    }
}

// In-memory only
pub struct GroupKey {
    key: Vec<u8>,
}
// wifi transport and storage on server disk
#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub nonce: Vec<u8>,
    pub bytes: Vec<u8>,
}
impl GroupKey {
    /// Encrypts the group key with the public keys of the recipients.
    /// Returns a vector, where result[i] is the group key, encrypted for
    /// the recipient whose public key is public_keys[i].
    pub fn make_encrypted_group_keys(public_keys: &[RsaPublicKey]) -> Vec<Vec<u8>> {
        let group_key = aes_gcm::Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let group_key = group_key.to_vec();

        let mut rng = rand::thread_rng();
        public_keys
            .iter()
            .map(|pk| {
                pk.encrypt(&mut rng, Pkcs1v15Encrypt, &group_key[..])
                    .expect("Failed to encrypt group key!")
            })
            .collect()
    }

    /// Encrypts a file using the group key
    /// Returns the encrypted file and the nonce
    pub fn encrypt_file(&self, bytes: &[u8]) -> EncryptedFile {
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_slice()).expect("Failed to init AES-GCM");
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let bytes = cipher.encrypt(&nonce, bytes).expect("Failed to encrypt");
        EncryptedFile {
            nonce: nonce.to_vec(),
            bytes,
        }
    }
    /// Decrypts a file using the group key and the nonce
    /// Returns the decrypted bytes
    pub fn decrypt_file(&self, encrypted_file: &EncryptedFile) -> Vec<u8> {
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_slice()).expect("Failed to init AES-GCM");
        let nonce = GenericArray::from_slice(encrypted_file.nonce.as_slice());
        cipher
            .decrypt(&nonce, encrypted_file.bytes.as_slice())
            .expect("Failed to decrypt file")
    }
}
