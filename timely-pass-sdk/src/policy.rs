use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Period {
    Instant { value: DateTime<Utc> },
    Range { start: DateTime<Utc>, end: DateTime<Utc> },
    Duration { seconds: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Hook {
    OnlyBefore { period: Period },
    OnlyAfter { period: Period },
    OnlyWithin { period: Period },
    OnlyFor { duration_secs: u64 }, // interpreted as duration anchored to creation/activation
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    pub id: String,
    pub hooks: Vec<Hook>,
    pub timezone: Option<String>, // e.g., "UTC" or IANA TZ
    pub clock_skew_secs: u64,
    pub max_attempts: Option<u32>,
    pub single_use: bool,
    pub version: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            hooks: Vec::new(),
            timezone: Some("UTC".to_string()),
            clock_skew_secs: 60,
            max_attempts: None,
            single_use: false,
            version: 1,
        }
    }
}

impl Policy {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }

    pub fn add_hook(mut self, hook: Hook) -> Self {
        self.hooks.push(hook);
        self
    }
}
