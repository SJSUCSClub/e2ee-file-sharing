use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use aws_lc_rs::cipher::AES_256_KEY_LEN;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    PrivateDecryptingKey, PublicEncryptingKey,
};
use aws_lc_rs::{digest, rand};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

const PERSONAL_KEY_LEN: usize = AES_256_KEY_LEN;

#[derive(Clone)]
pub struct PersonalKey {
    /// An AES-256 key.
    /// Corresponds to *PersonalKey* from the Cryptography Outline.
    key: [u8; PERSONAL_KEY_LEN],
}

impl PersonalKey {
    /// Deterministic PersonalKey derivation using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address of the user
    /// * `password` - The password of the user
    ///
    /// # Returns
    ///
    /// A new PersonalKey
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
    ///
    /// # Returns
    ///
    /// The hash of the personal key, as bytes
    pub fn hash(self: &Self) -> [u8; 32] {
        let d = digest::digest(&digest::SHA256, &self.key);
        let mut res: [u8; 32] = [0; 32];
        res.copy_from_slice(d.as_ref());
        res
    }
}

/// In-memory only.
pub struct PkKeyPair {
    // PkPub - RSA
    // PkPriv - RSA
    pkpub: PublicEncryptingKey,
    pkpriv: PrivateDecryptingKey,
}

impl PkKeyPair {
    /// Creates a new PkKeyPair.
    ///
    /// # Returns
    ///
    /// A new PkKeyPair
    pub fn new() -> Self {
        // generates pkpub and pkpriv
        let priv_key =
            PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("failed to generate a key");
        PkKeyPair {
            pkpub: priv_key.public_key(),
            // Fuck AWS for writing a Result<> when it's completely unnecessary
            pkpriv: priv_key,
        }
    }

    /// Decrypts a group key with the private key of the user.
    ///
    /// # Arguments
    ///
    /// * `group_key_encrypted` - The encrypted group key, as bytes
    ///
    /// # Returns
    ///
    /// The decrypted group key
    pub fn get_group_key(&self, group_key_encrypted: &[u8]) -> GroupKey {
        // decrypt the encrypted group key with the private key
        let pkpriv = OaepPrivateDecryptingKey::new(self.pkpriv.clone()).unwrap();
        let mut plaintext = vec![0u8; pkpriv.min_output_size()];
        let plaintext = pkpriv
            .decrypt(
                &OAEP_SHA256_MGF1SHA256,
                group_key_encrypted,
                &mut plaintext,
                None,
            )
            .expect("Failed to decrypt key");
        GroupKey {
            key: plaintext.try_into().unwrap(),
        }
    }
}

/// On-disk storage format.
#[derive(Serialize, Deserialize)]
pub struct DiskKeys {
    nonce: [u8; NONCE_LEN], // 12 bytes
    pk_pub: String,         // base64 encode of DER
    pk_priv_prot: String,   // base64 encode of ciphertext of DER
}

fn aead_encrypt(plaintext: &[u8], key: &[u8; AES_256_KEY_LEN]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let key = RandomizedNonceKey::new(&AES_256_GCM, key).unwrap();
    let mut ciphertext = Vec::from(plaintext);
    let nonce = key
        .seal_in_place_append_tag(Aad::empty(), &mut ciphertext)
        .unwrap();
    // Hope compiler will optmize out this copy of an unescaped value (nonce)
    (nonce.as_ref().clone(), ciphertext)
}

fn base64_encode(der: &[u8]) -> String {
    BASE64_STANDARD.encode(der)
}
fn base64_decode(pem: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(pem).unwrap()
}

fn aead_decrypt(
    ciphertext: Vec<u8>, // We need a `mut Vec<u8>` anyways, let the caller do a copy if necessary
    nonce: &[u8; NONCE_LEN],
    key: &[u8; AES_256_KEY_LEN],
) -> Vec<u8> {
    // Give it a more accurate name: both incoming ciphertext, and output plaintext will be stored in this buffer
    let mut in_out = ciphertext;

    let key = RandomizedNonceKey::new(&AES_256_GCM, key).unwrap();
    let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
    key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
    in_out
}

impl DiskKeys {
    /// Creates a new DiskKeys object, which can be securely stored on disk.
    ///
    /// # Arguments
    ///
    /// * `personal_key` - The personal key used to encrypt the private key
    /// * `kp` - The public and private keys of the user
    ///
    /// # Returns
    ///
    /// A new DiskKeys object
    pub fn new(personal_key: &PersonalKey, kp: &PkKeyPair) -> Self {
        let pub_der =
            AsDer::<PublicKeyX509Der>::as_der(&kp.pkpub).expect("failed to DER public key");
        let priv_der = AsDer::<Pkcs8V1Der>::as_der(&kp.pkpriv).expect("failed to DER private key");

        let (nonce, ciphertext) = aead_encrypt(priv_der.as_ref(), &personal_key.key);

        DiskKeys {
            nonce,
            pk_pub: base64_encode(pub_der.as_ref()),
            pk_priv_prot: base64_encode(ciphertext.as_slice()),
        }
    }

    /// Decrypts the PkKeyPair by using the personal key and the stored nonce
    ///
    /// # Arguments
    ///
    /// * `personal_key` - The personal key used to decrypt the private key
    ///
    /// # Returns
    ///
    /// The decrypted PkKeyPair
    pub fn to_memory(self, personal_key: &PersonalKey) -> PkKeyPair {
        let pk_pub = base64_decode(&self.pk_pub);
        let pk_priv = aead_decrypt(
            base64_decode(&self.pk_priv_prot),
            &self.nonce,
            &personal_key.key,
        );

        PkKeyPair {
            pkpub: PublicEncryptingKey::from_der(pk_pub.as_slice()).unwrap(),
            pkpriv: PrivateDecryptingKey::from_pkcs8(pk_priv.as_slice()).unwrap(),
        }
    }
}

// In-memory only
#[derive(PartialEq, Eq, Debug)]
pub struct GroupKey {
    key: [u8; AES_256_KEY_LEN],
}
// wifi transport and storage on server disk
#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub nonce: [u8; NONCE_LEN],
    pub bytes: Vec<u8>,
}
impl GroupKey {
    /// Encrypts the group key with the public keys of the recipients.
    /// Returns a vector, where result[i] is the group key, encrypted for
    /// the recipient whose public key is public_keys[i].
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The public keys of the recipients
    ///
    /// # Returns
    ///
    /// A vector of encrypted group keys (as bytes)
    pub fn make_encrypted_group_keys(public_keys: &[PublicEncryptingKey]) -> Vec<Vec<u8>> {
        let mut group_key = [0u8; AES_256_KEY_LEN];
        rand::fill(&mut group_key).unwrap();

        public_keys
            .iter()
            .map(|pk| {
                let pkpub = OaepPublicEncryptingKey::new(pk.clone()).unwrap();
                let mut ciphertext = vec![0u8; pkpub.ciphertext_size()];
                let ciphertext = pkpub
                    .encrypt(&OAEP_SHA256_MGF1SHA256, &group_key, &mut ciphertext, None)
                    .unwrap();
                ciphertext.to_vec()
            })
            .collect()
    }

    /// Encrypts a file using the group key
    /// Returns the encrypted file and the nonce
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to encrypt
    ///
    /// # Returns
    ///
    /// An EncryptedFile object
    pub fn encrypt_file(&self, bytes: &[u8]) -> EncryptedFile {
        let (nonce, ciphertext) = aead_encrypt(bytes, &self.key);

        EncryptedFile {
            nonce,
            bytes: ciphertext,
        }
    }
    /// Decrypts a file using the group key and the nonce
    /// Returns the decrypted bytes
    ///
    /// # Arguments
    ///
    /// * `encrypted_file` - The encrypted file
    ///
    /// # Returns
    ///
    /// A vector of decrypted bytes
    pub fn decrypt_file(&self, encrypted_file: &EncryptedFile) -> Vec<u8> {
        aead_decrypt(
            encrypted_file.bytes.clone(),
            &encrypted_file.nonce,
            &self.key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_personal_key() {
        let email = "test@test.com";
        let password = "abcdefghijklmnopqrstuvwxyz";
        let personal_key = PersonalKey::derive(email, password);
        let personal_key_2 = PersonalKey::derive(email, password);
        assert_eq!(personal_key.key, personal_key_2.key);
        assert_eq!(personal_key.hash(), personal_key_2.hash());
    }

    fn pub_der(a: &PublicEncryptingKey) {
        AsDer::<PublicKeyX509Der>::as_der(a).unwrap();
    }

    fn priv_der(a: &PrivateDecryptingKey) {
        AsDer::<Pkcs8V1Der>::as_der(a).unwrap();
    }

    #[test]
    fn test_disk_keys() {
        let personal_key = PersonalKey::derive("test@test.com", "password123");
        let kp = PkKeyPair::new();
        let disk_keys = DiskKeys::new(&personal_key, &kp);
        // make sure that its to_memory works
        let kp_recovered = disk_keys.to_memory(&personal_key);
        assert_eq!(pub_der(&kp.pkpub), pub_der(&kp_recovered.pkpub));
        assert_eq!(priv_der(&kp.pkpriv), priv_der(&kp_recovered.pkpriv));
    }

    #[test]
    fn test_group_key() {
        // generate key pairs
        let kp1 = PkKeyPair::new();
        let kp2 = PkKeyPair::new();
        assert_eq!(pub_der(&kp1.pkpub), pub_der(&kp2.pkpub));
        assert_eq!(priv_der(&kp1.pkpriv), priv_der(&kp2.pkpriv));

        // encrypt group key for them and recover
        let encrypted_group_keys =
            GroupKey::make_encrypted_group_keys(&[kp1.pkpub.clone(), kp2.pkpub.clone()]);
        let recovered_group_key1 = kp1.get_group_key(&encrypted_group_keys[0]);
        let recovered_group_key2 = kp2.get_group_key(&encrypted_group_keys[1]);
        assert_eq!(recovered_group_key1, recovered_group_key2);

        // encrypt things with group key and recover
        let group_key = recovered_group_key1;
        let encrypted_file = group_key.encrypt_file(b"hello world");
        let recovered_bytes = group_key.decrypt_file(&encrypted_file);
        assert_eq!(recovered_bytes, b"hello world");
    }
}
