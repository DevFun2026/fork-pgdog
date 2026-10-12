//! Immutable, fail-closed admission policy for strict read-only listeners.

mod admission;
mod error;
mod manifest;
mod policy;
pub(crate) mod process;
pub(crate) mod session;
pub(crate) mod transaction;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod live_tests;

pub(crate) use admission::{
    AdmittedSql, CatalogRequirements, ReadAction, ReadIsolation, admit_sql, gate_message,
};
pub(crate) use error::{PolicyError, PolicyErrorKind};
pub(crate) use manifest::{ManifestDigest, ReadManifest};
pub(crate) use policy::{ProcessPolicy, QueryPolicy};
pub(crate) use session::StrictSession;
