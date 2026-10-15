//! Immutable profiles generated only from owned pinned PostgreSQL references.
use super::dependency_profile::ValidatedDependencyProfile;
use std::sync::OnceLock;

type ProfileSet = [Option<ValidatedDependencyProfile>; 4];

static PG12: OnceLock<ProfileSet> = OnceLock::new();
static PG18: OnceLock<ProfileSet> = OnceLock::new();

fn load_profile(
    bytes: &'static [u8],
    digest: &'static str,
    major: u32,
    image: &'static str,
) -> Option<ValidatedDependencyProfile> {
    ValidatedDependencyProfile::load_profile(bytes, digest, major, image).ok()
}

fn profiles_for_major(major: u32) -> Option<&'static ProfileSet> {
    let (slot, artifacts) = match major {
        12 => (
            &PG12,
            [
                (
                    include_bytes!("profiles/dependency-pg12-core.json").as_slice(),
                    "c582205267781f52732c376519cfa816f86740b6d2d060ad6fa3676c2dd17ffd",
                ),
                (
                    include_bytes!("profiles/dependency-pg12-btree-gist.json").as_slice(),
                    "3f2ffa6fa29e45ee7243d941abeaf216a740d95224f544bd2af8f6327d492c01",
                ),
                (
                    include_bytes!("profiles/dependency-pg12-pg-trgm.json").as_slice(),
                    "e757fac65056bad23f0fe76e9fbd5a11cd33322dfa6e7705b6a7dd0fccef70ee",
                ),
                (
                    include_bytes!("profiles/dependency-pg12-both.json").as_slice(),
                    "ff96fb1f2e5d62d877a254947c144da3cf21bc2eff05b19cd1eafdbbbb3560b6",
                ),
            ],
        ),
        18 => (
            &PG18,
            [
                (
                    include_bytes!("profiles/dependency-pg18-core.json").as_slice(),
                    "5929692510591dd4fc62d4fb23fdfd9ca42f1a9759755391de93b05762934499",
                ),
                (
                    include_bytes!("profiles/dependency-pg18-btree-gist.json").as_slice(),
                    "96e83051f2310feef397b7279dab9e70f3fcb8b0958a55dfd5b9da6fed95ebe7",
                ),
                (
                    include_bytes!("profiles/dependency-pg18-pg-trgm.json").as_slice(),
                    "8187f41b655bf6e5fa364f338caf9d11a2ff33edec15a2502aaa022d11687640",
                ),
                (
                    include_bytes!("profiles/dependency-pg18-both.json").as_slice(),
                    "a30b7032dd74aa87d3c6a54f73fed2386a40dc528ddb94d87dbef6e0dbbfd89e",
                ),
            ],
        ),
        _ => return None,
    };
    let image = match major {
        12 => {
            "postgres:12.22-bookworm@sha256:2f2a8c2a7d10862e7fba2602e304523554f9df8244c632dafe2628ccb398fb5c"
        }
        18 => "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
        _ => return None,
    };
    Some(
        slot.get_or_init(|| {
            artifacts.map(|(bytes, digest)| load_profile(bytes, digest, major, image))
        }),
    )
}

fn module_index(modules: &[&str]) -> Option<usize> {
    match modules {
        [] => Some(0),
        ["btree_gist"] => Some(1),
        ["pg_trgm"] => Some(2),
        ["btree_gist", "pg_trgm"] => Some(3),
        _ => None,
    }
}

/// Return the profile for one exact reviewed set of installed module dependencies.
/// Names must be in canonical sorted order, matching the artifact selector.
pub(crate) fn for_modules(
    major: u32,
    modules: &[&str],
) -> Option<&'static ValidatedDependencyProfile> {
    let index = module_index(modules)?;
    profiles_for_major(major)?.get(index)?.as_ref()
}

/// Backwards-compatible selector for the historical both-modules profile.
#[cfg(test)]
pub(crate) fn for_major(major: u32) -> Option<&'static ValidatedDependencyProfile> {
    for_modules(major, &["btree_gist", "pg_trgm"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_bound_to_separate_exact_major_artifacts() {
        assert_eq!(for_major(12).unwrap().major(), 12);
        assert_eq!(for_major(18).unwrap().major(), 18);
        assert!(for_major(11).is_none());
        assert!(for_major(17).is_none());
        assert!(for_major(19).is_none());
    }

    #[test]
    fn module_selector_returns_only_the_exact_reviewed_subset() {
        let variants: [(&[&str], &[&str]); 4] = [
            (&[], &[]),
            (&["btree_gist"], &["btree_gist"]),
            (&["pg_trgm"], &["pg_trgm"]),
            (&["btree_gist", "pg_trgm"], &["btree_gist", "pg_trgm"]),
        ];
        for major in [12, 18] {
            for (requested, expected) in variants {
                let profile = for_modules(major, requested).unwrap();
                assert_eq!(profile.major(), major);
                assert_eq!(
                    profile.enabled_extensions(),
                    expected
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect::<Vec<_>>()
                );
            }
        }
        assert!(for_modules(12, &["pg_trgm", "btree_gist"]).is_none());
        assert!(for_modules(12, &["unknown"]).is_none());
    }
}
