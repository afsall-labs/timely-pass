use crate::policy::{Hook, Period, Policy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Reject,
    Expired,
    NotYetValid,
    PolicyViolation(String),
}

pub struct EvaluationContext {
    pub now: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>, // For relative policies like OnlyFor
    pub last_used_at: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

impl Default for EvaluationContext {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            created_at: None,
            last_used_at: None,
            usage_count: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub verdict: Verdict,
    pub matched_hooks: Vec<usize>, // indices of matched hooks
    pub details: HashMap<String, String>,
}

impl Policy {
    pub fn evaluate(&self, ctx: &EvaluationContext) -> PolicyEvaluation {
        let mut matched_hooks = Vec::new();
        let mut details = HashMap::new();

        // Check single use
        if self.single_use && ctx.usage_count > 0 {
             return PolicyEvaluation {
                verdict: Verdict::Reject,
                matched_hooks,
                details: {
                    details.insert("reason".to_string(), "Single use policy violation".to_string());
                    details
                },
            };
        }

        // Check max attempts
        if let Some(max) = self.max_attempts {
            if ctx.usage_count >= max as u64 {
                return PolicyEvaluation {
                    verdict: Verdict::Reject,
                    matched_hooks,
                    details: {
                        details.insert("reason".to_string(), "Max attempts exceeded".to_string());
                        details
                    },
                };
            }
        }

        for (i, hook) in self.hooks.iter().enumerate() {
            let passed = match hook {
                Hook::OnlyBefore { period } => match period {
                    Period::Instant { value } => ctx.now < *value,
                    _ => false, // Invalid period type for OnlyBefore
                },
                Hook::OnlyAfter { period } => match period {
                    Period::Instant { value } => ctx.now > *value,
                    _ => false,
                },
                Hook::OnlyWithin { period } => match period {
                    Period::Range { start, end } => ctx.now >= *start && ctx.now <= *end,
                    _ => false,
                },
                Hook::OnlyFor { duration_secs } => {
                    if let Some(created) = ctx.created_at {
                         let end_time = created + chrono::Duration::seconds(*duration_secs as i64);
                         ctx.now <= end_time
                    } else {
                        // If we don't know creation time, we can't enforce OnlyFor, so we might fail closed?
                        // Or maybe it's a configuration error. Fail closed for security.
                        false
                    }
                }
            };

            if !passed {
                // If ANY hook fails, the policy fails (AND logic). 
                // Wait, are hooks AND or OR?
                // PRD doesn't explicitly say, but usually policies are restrictive "OnlyBefore X AND OnlyAfter Y".
                // "accepts only if..." implies restrictive.
                // So if any hook fails, we reject.
                
                // However, we need to return specific verdicts.
                let reason = match hook {
                    Hook::OnlyBefore { .. } => "Expired (After allowed time)",
                    Hook::OnlyAfter { .. } => "NotYetValid (Before allowed time)",
                    Hook::OnlyWithin { .. } => "Outside allowed window",
                    Hook::OnlyFor { .. } => "Expired (Duration elapsed)",
                };
                
                details.insert("failed_hook_index".to_string(), i.to_string());
                details.insert("reason".to_string(), reason.to_string());

                let verdict = match hook {
                    Hook::OnlyBefore { .. } | Hook::OnlyFor { .. } => Verdict::Expired,
                    Hook::OnlyAfter { .. } => Verdict::NotYetValid,
                    _ => Verdict::PolicyViolation(reason.to_string()),
                };

                return PolicyEvaluation {
                    verdict,
                    matched_hooks, // Only previously matched ones
                    details,
                };
            }
            
            matched_hooks.push(i);
        }

        PolicyEvaluation {
            verdict: Verdict::Accept,
            matched_hooks,
            details,
        }
    }
}
