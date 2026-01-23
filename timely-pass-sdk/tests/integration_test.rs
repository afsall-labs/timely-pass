use chrono::{Duration, Utc};
use tempfile::tempdir;
use timely_pass_sdk::crypto::Secret;
use timely_pass_sdk::eval::{EvaluationContext, Verdict};
use timely_pass_sdk::policy::{Hook, Period, Policy};
use timely_pass_sdk::store::{Credential, SecretStore, SecretType};

#[test]
fn test_store_encryption_and_roundtrip() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("store.timely");
    let passphrase = Secret::new(b"correct-horse-battery-staple".to_vec());

    // Init
    let cred_id;
    {
        let mut store = SecretStore::init(&store_path, &passphrase).unwrap();
        let cred = Credential::new(
            "test-cred".to_string(),
            SecretType::Password,
            b"super-secret".to_vec(),
        );
        cred_id = cred.id.clone();
        store.add_credential(cred).unwrap();
    }

    // Open with correct pass
    {
        let store = SecretStore::open(&store_path, &passphrase).unwrap();
        let cred = store.get_credential(&cred_id).unwrap();
        assert_eq!(cred.secret.data, b"super-secret");
    }

    // Open with wrong pass
    {
        let wrong_pass = Secret::new(b"wrong".to_vec());
        let res = SecretStore::open(&store_path, &wrong_pass);
        assert!(res.is_err());
    }
}

#[test]
fn test_policy_evaluation() {
    let now = Utc::now();
    let one_hour = Duration::hours(1);

    let policy = Policy::new("test-policy")
        .add_hook(Hook::OnlyBefore {
            period: Period::Instant { value: now + one_hour },
        })
        .add_hook(Hook::OnlyAfter {
            period: Period::Instant { value: now - one_hour },
        });

    let ctx_valid = EvaluationContext {
        now,
        ..Default::default()
    };
    
    let eval = policy.evaluate(&ctx_valid);
    assert_eq!(eval.verdict, Verdict::Accept);

    let ctx_expired = EvaluationContext {
        now: now + Duration::hours(2),
        ..Default::default()
    };
    let eval_expired = policy.evaluate(&ctx_expired);
    assert!(matches!(eval_expired.verdict, Verdict::Expired));
}

#[test]
fn test_only_for_duration() {
    let now = Utc::now();
    let created = now - Duration::minutes(30);
    
    // Valid for 1 hour after creation
    let policy = Policy::new("duration-policy")
        .add_hook(Hook::OnlyFor { duration_secs: 3600 }); // 1 hour

    let ctx_valid = EvaluationContext {
        now, // 30 mins after creation
        created_at: Some(created),
        ..Default::default()
    };
    assert_eq!(policy.evaluate(&ctx_valid).verdict, Verdict::Accept);

    let ctx_expired = EvaluationContext {
        now: now + Duration::hours(1), // 1h 30m after creation
        created_at: Some(created),
        ..Default::default()
    };
    assert!(matches!(policy.evaluate(&ctx_expired).verdict, Verdict::Expired));
}
