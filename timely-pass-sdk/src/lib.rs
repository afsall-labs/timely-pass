//! # Timely Pass SDK
//!
//! `timely-pass-sdk` provides the core logic and data structures for the Timely Pass password manager.
//! It handles:
//! - Secure storage of credentials using Argon2id and XChaCha20Poly1305.
//! - Time-based policy evaluation.
//! - Cryptographic operations.
//!
//! ## Modules
//!
//! - `crypto`: Cryptographic primitives (hashing, encryption, random generation).
//! - `store`: Credential storage management.
//! - `policy`: Policy definitions and validation.
//! - `eval`: Policy evaluation logic against time.
//! - `error`: Error types.

pub mod crypto;
pub mod error;
pub mod eval;
pub mod policy;
pub mod store;

pub use error::Error;
