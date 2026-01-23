use crate::error::{Error, Result};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    pub fn derive_from_passphrase(passphrase: &Secret, salt: Option<&[u8]>) -> Result<(Self, Vec<u8>)> {
        let salt = match salt {
            Some(s) => SaltString::encode_b64(s).map_err(|e| Error::Crypto(e.to_string()))?,
            None => SaltString::generate(&mut OsRng),
        };

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        
        let hash = password_hash.hash.ok_or_else(|| Error::Crypto("No hash output".into()))?;
        
        let key_bytes = hash.as_bytes().to_vec();
        
        // Return raw salt bytes (decoded from b64 if needed, or just keep original bytes?)
        // SaltString handles b64 encoding. 
        // We want to return something we can store and reuse.
        // `salt` is a SaltString.
        // `salt.as_str()` gives the b64 string.
        // If we want to store raw bytes, we need to decode?
        // But `encode_b64` takes raw bytes.
        // So we should store the raw bytes used to create the salt?
        // Wait, `SaltString::generate` creates a random salt.
        // We can get the string rep.
        // The store expects `Vec<u8>` for salt.
        // If we store the string bytes, we can pass them back to `encode_b64`?
        // No, `encode_b64` expects raw bytes and encodes them.
        // If we have a `SaltString`, we can get the underlying string.
        // If we want the raw bytes, `SaltString` doesn't easily give them back if generated?
        // Actually, `SaltString` wraps a b64 string.
        // Let's just store the string bytes.
        
        Ok((Self(key_bytes), salt.as_str().as_bytes().to_vec()))
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| Error::Crypto("Invalid key length".into()))?;
        
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| Error::Crypto("Encryption failed".into()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_with_nonce: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < NONCE_LEN {
            return Err(Error::Crypto("Ciphertext too short".into()));
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        
        let cipher = XChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| Error::Crypto("Invalid key length".into()))?;

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::Crypto("Decryption failed".into()))
    }
}
