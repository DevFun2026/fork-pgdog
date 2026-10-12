//! The process policy is installed before any configuration can be published.
//! Reloading configuration never reloads or replaces this snapshot.
use std::sync::{Arc, LazyLock, OnceLock};

use super::{PolicyError, ProcessPolicy, QueryPolicy};

static POLICY: OnceLock<Arc<ProcessPolicy>> = OnceLock::new();
static UNRESTRICTED: LazyLock<Arc<ProcessPolicy>> = LazyLock::new(|| {
    ProcessPolicy::load(QueryPolicy::Unrestricted, None)
        .expect("unrestricted policy requires no external inputs")
});

pub(crate) fn install(policy: Arc<ProcessPolicy>) -> Result<(), PolicyError> {
    POLICY
        .set(policy)
        .map_err(|_| PolicyError::configuration("process_policy_already_initialized"))
}

pub(crate) fn current() -> Arc<ProcessPolicy> {
    POLICY.get().unwrap_or(&UNRESTRICTED).clone()
}

pub(crate) fn validate(config: &crate::config::ConfigAndUsers) -> Result<(), crate::config::Error> {
    current()
        .validate_config(config)
        .map_err(|e| crate::config::Error::ParseError(e.to_string()))
}
