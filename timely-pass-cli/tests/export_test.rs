use timely_pass_sdk::policy::{Policy, Hook, Period};
use timely_pass_sdk::store::{Credential, SecretType};
use chrono::Utc;
use serde_json;

#[test]
fn test_policy_serialization() {
    let mut policy = Policy::new("test-policy");
    policy.clock_skew_secs = 120;
    policy.single_use = true;
    policy.hooks.push(Hook::OnlyAfter {
        period: Period::Instant { value: Utc::now() }
    });

    let json = serde_json::to_string_pretty(&policy).expect("Failed to serialize policy");
    println!("Serialized Policy:\n{}", json);

    let deserialized: Policy = serde_json::from_str(&json).expect("Failed to deserialize policy");
    assert_eq!(policy.id, deserialized.id);
    assert_eq!(policy.clock_skew_secs, deserialized.clock_skew_secs);
    assert_eq!(policy.single_use, deserialized.single_use);
    assert_eq!(policy.hooks.len(), deserialized.hooks.len());
}

#[test]
fn test_credential_serialization() {
    let cred = Credential::new(
        "test-cred".to_string(),
        SecretType::Password,
        b"secret".to_vec(),
    );

    let json = serde_json::to_string_pretty(&cred).expect("Failed to serialize credential");
    println!("Serialized Credential:\n{}", json);

    let deserialized: Credential = serde_json::from_str(&json).expect("Failed to deserialize credential");
    assert_eq!(cred.id, deserialized.id);
    assert_eq!(cred.label, deserialized.label);
    // Note: Secret data is NOT serialized/deserialized by default if we were using a custom serializer that hides it,
    // but here we are testing the full struct serialization for export.
    // Wait, `CredentialSecret` derives `Serialize` and `Deserialize`, but fields might be skipped?
    // Let's check `store.rs`. `CredentialSecret` derives `Zeroize` and `ZeroizeOnDrop`.
    // The `type_` field has `#[zeroize(skip)]`.
    // The `data` field is `Vec<u8>`.
    // It should serialize fine.
    
    assert_eq!(cred.secret.type_, deserialized.secret.type_);
    assert_eq!(cred.secret.data, deserialized.secret.data);
}
