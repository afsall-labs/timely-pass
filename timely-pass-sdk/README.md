# Timely Pass SDK

The `timely-pass-sdk` is the core library powering the Timely Pass ecosystem. It provides the fundamental building blocks for creating, managing, and enforcing time-based security policies for credentials.

## 📦 Features

- **Time-Based Policy Engine**: Define and evaluate complex time constraints (OnlyBefore, OnlyAfter, OnlyWithin, OnlyFor).
- **Secure Cryptography**:
  - **Encryption**: XChaCha20Poly1305 (Authenticated Encryption).
  - **Key Derivation**: Argon2id for robust password hashing.
  - **Memory Safety**: Zeroize integration for secure memory wiping.
- **Secure Store**: Encrypted-at-rest storage backend for credentials and policies.
- **Auditability**: Detailed evaluation verdicts for every access attempt.

## 🛠️ Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
timely-pass-sdk = { path = "../timely-pass-sdk" } # Or version from crates.io when published
```

## 🚀 Usage Example

```rust
use timely_pass_sdk::store::{SecretStore, Credential, SecretType};
use timely_pass_sdk::crypto::Secret;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    // 1. Initialize a new store
    let path = PathBuf::from("my_secure_store.timely");
    let passphrase = Secret::new(b"my-super-strong-password".to_vec());
    let mut store = SecretStore::init(&path, &passphrase)?;

    // 2. Add a credential
    let cred = Credential::new(
        "api-key-1".to_string(),
        SecretType::Key,
        b"secret-api-key-value".to_vec()
    );
    store.add_credential(cred)?;

    // 3. Save changes
    store.save()?;

    // 4. Retrieve (decrypts and verifies)
    if let Some(c) = store.get_credential("api-key-1") {
        println!("Found credential: {}", c.id);
    }

    Ok(())
}
```

## 🛡️ Security

This SDK is designed with a "Security First" mindset.
- All secrets are wrapped in `Secret` types that zero out memory on drop.
- The store uses a random 32-byte salt for KDF.
- Encryption uses a random 24-byte nonce for every save operation.

## 📄 License

MIT
