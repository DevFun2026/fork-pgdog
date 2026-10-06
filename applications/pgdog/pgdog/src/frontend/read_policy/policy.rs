use std::{fs, path::Path, sync::Arc};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::{ManifestDigest, PolicyError, ReadManifest};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum QueryPolicy {
    #[default]
    Unrestricted,
    StrictRead,
}

#[derive(Debug)]
pub(crate) struct ProcessPolicy {
    mode: QueryPolicy,
    manifest: Option<ReadManifest>,
    digest: ManifestDigest,
}

impl ProcessPolicy {
    pub(crate) fn load(mode: QueryPolicy, path: Option<&Path>) -> Result<Arc<Self>, PolicyError> {
        let (manifest, digest) = match (mode, path) {
            (QueryPolicy::Unrestricted, None) => (None, ManifestDigest([0; 32])),
            (QueryPolicy::Unrestricted, Some(_)) => {
                return Err(PolicyError::configuration(
                    "read_policy_file_requires_strict_read",
                ));
            }
            (QueryPolicy::StrictRead, None) => {
                return Err(PolicyError::configuration("strict_read_requires_manifest"));
            }
            (QueryPolicy::StrictRead, Some(path)) => {
                let bytes = fs::read(path).map_err(|_| PolicyError::io())?;
                let manifest = ReadManifest::parse(&bytes)?;
                let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
                let mut value = [0; 32];
                value.copy_from_slice(digest.as_ref());
                (Some(manifest), ManifestDigest(value))
            }
        };
        Ok(Arc::new(Self {
            mode,
            manifest,
            digest,
        }))
    }

    pub(crate) fn mode(&self) -> QueryPolicy {
        self.mode
    }

    pub(crate) fn manifest(&self) -> Option<&ReadManifest> {
        self.manifest.as_ref()
    }

    pub(crate) fn digest(&self) -> &ManifestDigest {
        &self.digest
    }

    pub(crate) fn validate_config(
        &self,
        config: &crate::config::ConfigAndUsers,
    ) -> Result<(), PolicyError> {
        if self.mode == QueryPolicy::Unrestricted {
            return Ok(());
        }
        let cfg = &config.config;
        if cfg.general.load_schema == pgdog_config::LoadSchema::On
            || cfg.general.canonicalize_type_information
            || cfg
                .databases
                .iter()
                .any(|database| database.role != crate::config::Role::Primary)
            || config.users.users.iter().any(|user| user.schema_admin)
        {
            return Err(PolicyError::configuration(
                "strict_read_background_execution_forbidden",
            ));
        }
        if !cfg.plugins.is_empty() {
            return Err(PolicyError::configuration("strict_read_plugins_forbidden"));
        }
        if !cfg.mirroring.is_empty() {
            return Err(PolicyError::configuration(
                "strict_read_mirroring_forbidden",
            ));
        }
        if cfg.rewrite.enabled
            || [
                cfg.rewrite.shard_key,
                cfg.rewrite.split_inserts,
                cfg.rewrite.primary_key,
                cfg.rewrite.non_deterministic_functions,
            ]
            .iter()
            .any(|mode| {
                matches!(
                    mode,
                    crate::config::RewriteMode::Rewrite
                        | crate::config::RewriteMode::RewriteOmni
                        | crate::config::RewriteMode::RewriteOmniGlobal
                )
            })
        {
            return Err(PolicyError::configuration("strict_read_rewrites_forbidden"));
        }
        if !cfg.sharded_tables.is_empty()
            || !cfg.sharded_mappings.is_empty()
            || !cfg.sharded_schemas.is_empty()
            || !cfg.omnisharded_tables.is_empty()
            || cfg.databases.iter().any(|database| database.shard != 0)
            || config
                .users
                .users
                .iter()
                .any(|user| user.replication_mode || user.replication_sharding.is_some())
        {
            return Err(PolicyError::configuration("strict_read_sharding_forbidden"));
        }
        if cfg.general.query_log.is_some()
            || cfg.general.query_log_stdout
            || cfg.general.log_min_duration_parse.is_some()
        {
            return Err(PolicyError::configuration(
                "strict_read_query_logging_forbidden",
            ));
        }
        if cfg.general.dry_run
            || cfg.general.two_phase_commit
            || cfg.general.two_phase_commit_auto == Some(true)
            || config.users.users.iter().any(|user| {
                user.two_phase_commit == Some(true) || user.two_phase_commit_auto == Some(true)
            })
        {
            return Err(PolicyError::configuration(
                "strict_read_execution_features_forbidden",
            ));
        }
        if self.manifest.is_none() {
            return Err(PolicyError::configuration("strict_read_requires_manifest"));
        }
        Ok(())
    }
}
