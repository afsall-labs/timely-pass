use crate::crypto::{MasterKey, Secret};
use crate::error::{Error, Result};
use crate::policy::Policy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    Password,
    Key,
    Token,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSecret {
    #[zeroize(skip)]
    pub type_: SecretType,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub label: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub policy_id: Option<String>,
    pub secret: CredentialSecret,
    pub usage_counter: u64,
}

impl Credential {
    pub fn new(label: String, secret_type: SecretType, secret_data: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            label,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            policy_id: None,
            secret: CredentialSecret {
                type_: secret_type,
                data: secret_data,
            },
            usage_counter: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoreHeader {
    version: u32,
    salt: Vec<u8>, // Salt used for KDF to derive MasterKey
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub target_type: String, // "credential", "policy", "system"
    pub target_id: String,
    pub details: String,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>, target_type: impl Into<String>, target_id: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            action: action.into(),
            target_type: target_type.into(),
            target_id: target_id.into(),
            details: details.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StorePayload {
    credentials: HashMap<String, Credential>,
    policies: HashMap<String, Policy>,
    #[serde(default)]
    audit_logs: Vec<AuditEntry>,
}

pub struct SecretStore {
    path: PathBuf,
    master_key: MasterKey,
    salt: Vec<u8>,
    credentials: HashMap<String, Credential>,
    policies: HashMap<String, Policy>,
    audit_logs: Vec<AuditEntry>,
}

impl SecretStore {
    pub fn init(path: impl AsRef<Path>, passphrase: &Secret) -> Result<Self> {
        let (master_key, salt) = MasterKey::derive_from_passphrase(passphrase, None)?;
        
        let store = Self {
            path: path.as_ref().to_path_buf(),
            master_key,
            salt,
            credentials: HashMap::new(),
            policies: HashMap::new(),
            audit_logs: vec![AuditEntry::new("init", "system", "store", "Store initialized")],
        };
        
        store.save()?;
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>, passphrase: &Secret) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).map_err(Error::Io)?;
        
        let mut header_len_bytes = [0u8; 4];
        file.read_exact(&mut header_len_bytes).map_err(Error::Io)?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;
        
        let mut header_bytes = vec![0u8; header_len];
        file.read_exact(&mut header_bytes).map_err(Error::Io)?;
        
        let header: StoreHeader = bincode::deserialize(&header_bytes)?;
        
        let mut encrypted_payload = Vec::new();
        file.read_to_end(&mut encrypted_payload).map_err(Error::Io)?;
        
        let master_key = MasterKey::derive_from_passphrase(passphrase, Some(&header.salt))?.0;
        
        let payload_bytes = master_key.decrypt(&encrypted_payload, &header_bytes)?;
        let payload: StorePayload = bincode::deserialize(&payload_bytes)?;
        
        Ok(Self {
            path,
            master_key,
            salt: header.salt,
            credentials: payload.credentials,
            policies: payload.policies,
            audit_logs: payload.audit_logs,
        })
    }

    pub fn save(&self) -> Result<()> {
        let header = StoreHeader {
            version: 1,
            salt: self.salt.clone(),
        };

        let header_bytes = bincode::serialize(&header)?;
        let header_len = header_bytes.len() as u32;

        let payload = StorePayload {
            credentials: self.credentials.clone(),
            policies: self.policies.clone(),
            audit_logs: self.audit_logs.clone(),
        };
        let payload_bytes = bincode::serialize(&payload)?;

        let encrypted_payload = self.master_key.encrypt(&payload_bytes, &header_bytes)?;

        // Write to temp file first
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = tempfile::NamedTempFile::new_in(dir).map_err(Error::Io)?;
        
        temp_file.write_all(&header_len.to_le_bytes())?;
        temp_file.write_all(&header_bytes)?;
        temp_file.write_all(&encrypted_payload)?;
        
        temp_file.persist(&self.path).map_err(|e| Error::Io(e.error))?;

        Ok(())
    }

    pub fn add_policy(&mut self, policy: Policy) -> Result<()> {
        self.audit_logs.push(AuditEntry::new("add", "policy", &policy.id, format!("Policy added/updated: version {}", policy.version)));
        self.policies.insert(policy.id.clone(), policy);
        self.save()
    }

    pub fn get_policy(&self, id: &str) -> Option<&Policy> {
        self.policies.get(id)
    }

    pub fn remove_policy(&mut self, id: &str) -> Result<()> {
        if self.policies.remove(id).is_some() {
            self.audit_logs.push(AuditEntry::new("remove", "policy", id, "Policy removed"));
            self.save()
        } else {
            Ok(())
        }
    }

    pub fn list_policies(&self) -> Vec<&Policy> {
        self.policies.values().collect()
    }

    pub fn get_audit_logs(&self) -> &[AuditEntry] {
        &self.audit_logs
    }

    pub fn add_credential(&mut self, cred: Credential) -> Result<()> {
        self.audit_logs.push(AuditEntry::new("add", "credential", &cred.id, format!("Credential added: {}", cred.label)));
        self.credentials.insert(cred.id.clone(), cred);
        self.save()
    }

    pub fn get_credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.get(id)
    }

    pub fn list_credentials(&self) -> Vec<&Credential> {
        self.credentials.values().collect()
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        if self.credentials.remove(id).is_some() {
            self.audit_logs.push(AuditEntry::new("remove", "credential", id, "Credential removed"));
            self.save()
        } else {
            Ok(())
        }
    }

    pub fn increment_usage(&mut self, id: &str) -> Result<()> {
        if let Some(cred) = self.credentials.get_mut(id) {
            cred.usage_counter += 1;
            cred.updated_at = Utc::now();
            // We don't necessarily want to log every usage in audit log to avoid bloat, 
            // but for security it might be good. Let's log it.
            self.audit_logs.push(AuditEntry::new("usage", "credential", id, "Credential accessed"));
            self.save()
        } else {
            Err(Error::Store(format!("Credential {} not found", id)))
        }
    }
}
