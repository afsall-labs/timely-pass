use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use timely_pass_sdk::crypto::{Secret, generate_random_bytes};
use timely_pass_sdk::eval::{EvaluationContext, Verdict};
use timely_pass_sdk::policy::Policy;
use timely_pass_sdk::store::{Credential, SecretStore, SecretType};

pub(crate) fn prompt_passphrase(confirm: bool) -> Result<Secret> {
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let pass = rpassword::read_password()?;
    
    if confirm {
        print!("Confirm passphrase: ");
        io::stdout().flush()?;
        let confirm_pass = rpassword::read_password()?;
        if pass != confirm_pass {
            anyhow::bail!("Passphrases do not match");
        }
    }
    
    Ok(Secret::new(pass.into_bytes()))
}

fn prompt_secret() -> Result<Vec<u8>> {
    print!("Enter secret value: ");
    io::stdout().flush()?;
    let secret = rpassword::read_password()?;
    Ok(secret.into_bytes())
}

pub(crate) fn open_store_helper(store_path: &PathBuf, passphrase: &Secret) -> Result<SecretStore> {
    match SecretStore::open(store_path, passphrase) {
        Ok(s) => Ok(s),
        Err(e) => {
            // Check if it's a NotFound error
            if let timely_pass_sdk::error::Error::Io(ref io_err) = e {
                if io_err.kind() == std::io::ErrorKind::NotFound {
                    anyhow::bail!("Store file not found at {:?}.\nPlease run 'timely-pass init' first to create a new store.", store_path);
                }
            }
            Err(e.into())
        }
    }
}

pub async fn init(store_path: PathBuf) -> Result<()> {
    if store_path.exists() {
        anyhow::bail!("Store already exists at {:?}", store_path);
    }

    println!("Initializing new store at {:?}", store_path);
    let passphrase = prompt_passphrase(true)?;
    
    SecretStore::init(&store_path, &passphrase)?;
    println!("Store initialized successfully.");
    Ok(())
}

pub async fn remove(store_path: PathBuf, id: String) -> Result<()> {
    let passphrase = prompt_passphrase(false)?;
    let mut store = open_store_helper(&store_path, &passphrase)?;
    store.remove_credential(&id)?;
    println!("Credential '{}' removed.", id);
    Ok(())
}

pub async fn add(
    store_path: PathBuf,
    id: String,
    type_: String,
    policy_path: Option<PathBuf>,
    read_secret: bool,
) -> Result<()> {
    let passphrase = prompt_passphrase(false)?;
    let mut store = open_store_helper(&store_path, &passphrase)?;

    let secret_data = if read_secret {
        prompt_secret()?
    } else {
        println!("Generating random 32-byte secret...");
        generate_random_bytes(32)
    };

    let secret_type = match type_.as_str() {
        "password" => SecretType::Password,
        "key" => SecretType::Key,
        "token" => SecretType::Token,
        _ => anyhow::bail!("Invalid secret type. Allowed: password, key, token"),
    };

    let mut cred = Credential::new(id.clone(), secret_type, secret_data);
    cred.id = id.clone();

    if let Some(path) = policy_path {
        let content = fs::read_to_string(&path).context("Failed to read policy file")?;
        // Parse TOML policy
        // We need to implement Deserialize for Policy from TOML
        // Our Policy struct has Deserialize derived, so:
        let policy: Policy = toml::from_str(&content).context("Failed to parse policy TOML")?;
        
        // Add policy to store
        store.add_policy(policy.clone())?;
        cred.policy_id = Some(policy.id);
    }

    store.add_credential(cred)?;
    println!("Credential '{}' added.", id);
    Ok(())
}

pub async fn get(store_path: PathBuf, id: String) -> Result<()> {
    let passphrase = prompt_passphrase(false)?;
    let mut store = open_store_helper(&store_path, &passphrase)?;

    let (secret, policy_id, created_at, updated_at, usage_counter) = {
        let cred = store.get_credential(&id).context("Credential not found")?;
        (cred.secret.clone(), cred.policy_id.clone(), cred.created_at, cred.updated_at, cred.usage_counter)
    };
    
    // Evaluate policy if present
    if let Some(pid) = policy_id {
        if let Some(policy) = store.get_policy(&pid) {
            let ctx = EvaluationContext {
                now: Utc::now(),
                created_at: Some(created_at),
                last_used_at: Some(updated_at),
                usage_count: usage_counter,
            };

            let eval = policy.evaluate(&ctx);
            match eval.verdict {
                Verdict::Accept => {},
                v => {
                    println!("Access Denied: {:?}", v);
                    println!("Details: {:?}", eval.details);
                    return Ok(());
                }
            }
        }
    }

    // Output secret (careful with printing bytes)
    match secret.type_ {
        SecretType::Password => {
             println!("{}", String::from_utf8_lossy(&secret.data));
        },
        _ => {
            println!("{}", hex::encode(&secret.data));
        }
    }

    // Update usage count
    store.increment_usage(&id)?;
    
    Ok(())
}

pub async fn eval(policy_path: PathBuf, time: Option<String>) -> Result<()> {
    let content = fs::read_to_string(&policy_path).context("Failed to read policy file")?;
    let policy: Policy = toml::from_str(&content).context("Failed to parse policy TOML")?;

    let now = if let Some(t) = time {
        DateTime::parse_from_rfc3339(&t)
            .context("Invalid time format (use ISO 8601)")?
            .with_timezone(&Utc)
    } else {
        Utc::now()
    };

    let ctx = EvaluationContext {
        now,
        created_at: Some(now), // Assume just created for stateless eval?
        ..Default::default()
    };

    let result = policy.evaluate(&ctx);
    println!("{:#?}", result);
    Ok(())
}

pub async fn list(store_path: PathBuf) -> Result<()> {
    let passphrase = prompt_passphrase(false)?;
    let store = open_store_helper(&store_path, &passphrase)?;

    let creds = store.list_credentials();
    if creds.is_empty() {
        println!("No credentials found.");
    } else {
        println!("{:<20} {:<20} {:<30}", "ID", "Type", "Created At");
        println!("{:-<20} {:-<20} {:-<30}", "", "", "");
        for cred in creds {
            println!("{:<20} {:<20?} {:<30}", cred.id, cred.secret.type_, cred.created_at);
        }
    }
    Ok(())
}

pub async fn rotate(store_path: PathBuf, id: String) -> Result<()> {
    let passphrase = prompt_passphrase(false)?;
    let mut store = open_store_helper(&store_path, &passphrase)?;
    
    // Check if exists
    let _ = store.get_credential(&id).context("Credential not found")?;
    
    // For rotation, we usually generate a new secret.
    println!("Rotating credential '{}'", id);
    let new_secret_data = prompt_secret()?;
    
    // We need a replace/update method in SDK.
    // For now, remove and add (not atomic, but works for MVP).
    // Wait, SDK doesn't have remove yet.
    // I should add `update_credential` to SDK.
    
    // Since I can't easily change SDK in this file, I'll assume I can just overwrite with `add_credential` 
    // because `add_credential` in `store.rs` uses `HashMap::insert` which overwrites.
    // But I need to preserve metadata (created_at, policy).
    
    // Fetch, modify, insert.
    if let Some(mut cred) = store.get_credential(&id).cloned() {
        cred.secret.data = new_secret_data;
        cred.updated_at = Utc::now();
        store.add_credential(cred)?;
        println!("Rotated successfully.");
    }

    Ok(())
}
