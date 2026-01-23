# SDK Guide

The `timely-pass-sdk` crate allows you to embed secure, time-based credential management directly into your Rust applications.

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
timely-pass-sdk = { path = "../path/to/timely-pass/timely-pass-sdk" }
# Or once published:
# timely-pass-sdk = "0.1.0"
```

## Core Concepts

- **SecretStore**: The encrypted container for all your credentials and policies.
- **Credential**: A named secret (password, key, etc.) stored within the store.
- **Policy**: A set of time-based rules that dictate when a credential can be accessed.
- **Evaluation**: The process of checking a policy against the current context (time, usage count) to grant or deny access.

---

## Usage Examples

### 1. Initialize a Store

Before you can store anything, you need to initialize a `SecretStore` with a master passphrase.

**Example: Creating a New Encrypted Store**

```rust
use timely_pass_sdk::store::SecretStore;
use timely_pass_sdk::crypto::Secret;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("my_store.timely");
    // In a real app, get this securely (e.g., from user input or env var)
    let passphrase = Secret::new(b"my-secure-passphrase".to_vec());

    // Initialize a new store at the specified path
    // This will error if the file already exists
    let mut store = SecretStore::init(&path, &passphrase)?;
    
    println!("Store initialized successfully!");
    Ok(())
}
```

### 2. Add a Credential

You can add various types of credentials (passwords, API keys, tokens) to the store.

**Example: Adding an API Key**

```rust
use timely_pass_sdk::store::{Credential, SecretType, SecretStore};
use timely_pass_sdk::crypto::Secret;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("my_store.timely");
    let passphrase = Secret::new(b"my-secure-passphrase".to_vec());
    
    // Open the existing store
    let mut store = SecretStore::open(&path, &passphrase)?;

    // Create a new credential
    let cred = Credential::new(
        "stripe-api-key".to_string(), // ID
        SecretType::Key,              // Type
        b"sk_test_4eC39HqLyjWDarjtT1zdp7dc".to_vec() // Secret Data
    );

    // Add it to the store
    store.add_credential(cred)?;
    
    // Save changes to disk
    store.save()?;
    
    println!("Credential added!");
    Ok(())
}
```

### 3. Read a Credential

Reading a credential involves decrypting the store and retrieving the secret. If a policy is attached, it will be evaluated automatically (if you use the high-level API) or you can evaluate it manually.

**Example: Retrieving and Using a Secret**

```rust
use timely_pass_sdk::store::SecretStore;
use timely_pass_sdk::crypto::Secret;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("my_store.timely");
    let passphrase = Secret::new(b"my-secure-passphrase".to_vec());
    
    // Open the store
    let mut store = SecretStore::open(&path, &passphrase)?;

    // Retrieve the credential by ID
    // Note: In a full implementation, you would check policies here.
    if let Some(cred) = store.get_credential("stripe-api-key") {
        println!("Found credential created at: {}", cred.created_at);
        
        // Access the raw secret bytes securely
        let secret_bytes = &cred.secret.expose_secret();
        println!("Secret length: {}", secret_bytes.len());
        // Use the secret...
    } else {
        println!("Credential not found.");
    }
    
    Ok(())
}
```

### 4. Policy Definition and Evaluation

You can define complex time-based policies using hooks like `OnlyWithin`, `OnlyAfter`, etc.

**Example: defining a "Business Hours Only" Policy**

```rust
use timely_pass_sdk::policy::{Policy, Period, Hook};
use timely_pass_sdk::eval::{EvaluationContext, Verdict};
use chrono::{Utc, TimeZone};

fn main() {
    // Define the policy
    let policy = Policy {
        id: "business-hours".to_string(),
        version: 1,
        clock_skew_secs: 60,
        max_attempts: None,
        single_use: false,
        enabled: true,
        hooks: vec![
            Hook::OnlyWithin(Period::Range {
                // Example: Valid from 9 AM to 5 PM UTC on a specific day
                start: Utc.ymd(2024, 1, 1).and_hms(9, 0, 0),
                end: Utc.ymd(2024, 1, 1).and_hms(17, 0, 0),
            })
        ],
    };

    // Create an evaluation context (e.g., current time is 12:00 PM)
    let ctx = EvaluationContext {
        now: Utc.ymd(2024, 1, 1).and_hms(12, 0, 0),
        created_at: Some(Utc::now()),
        last_used_at: None,
        usage_count: 0,
    };

    // Evaluate the policy
    let result = policy.evaluate(&ctx);

    match result.verdict {
        Verdict::Accept => println!("Access Granted!"),
        Verdict::Reject => println!("Access Denied: {:?}", result.details),
    }
}
```

### 5. Rotation

You can update a credential's secret (rotation) while keeping its ID and metadata intact.

**Example: Rotating a Credential's Secret**

```rust
use timely_pass_sdk::store::SecretStore;
use timely_pass_sdk::crypto::{Secret, generate_random_bytes};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("my_store.timely");
    let passphrase = Secret::new(b"my-secure-passphrase".to_vec());
    let mut store = SecretStore::open(&path, &passphrase)?;

    let id = "stripe-api-key";
    
    // Generate a new random 32-byte secret
    let new_secret_bytes = generate_random_bytes(32);
    let new_secret = Secret::new(new_secret_bytes);

    // Update the credential in the store
    store.update_credential_secret(id, new_secret)?;
    store.save()?;

    println!("Secret rotated successfully.");
    Ok(())
}
```
