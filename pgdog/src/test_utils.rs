use std::process::Command;

/// Run an environment-dependent test with variables set before process startup.
/// Returns true only in the child; the parent verifies exactly one passing test.
pub(crate) fn run_in_test_process(test: &str, variables: &[(&str, Option<&str>)]) -> bool {
    let name = test.split_once("::").expect("test module path").1;
    const MARKER: &str = "PGDOG_ENV_TEST_CHILD";
    if std::env::var(MARKER).as_deref() == Ok(name) {
        for (key, value) in variables {
            assert_eq!(std::env::var(*key).ok().as_deref(), *value);
        }
        return true;
    }
    // Test-only re-execution of the current Cargo test binary in the developer-owned build directory.
    // No privilege boundary or production invocation; the child inherits the same OS identity.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args(["--exact", name, "--nocapture", "--include-ignored"]);
    command.env(MARKER, name);
    for (key, value) in variables {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    let output = command.output().expect("launch isolated environment test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed; 0 failed"),
        "isolated test {name} failed: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn child_environment_does_not_mutate_parent() {
        let key = "PGDOG_TEST_CHILD_ENV_ISOLATION";
        let before = std::env::var_os(key);
        if super::run_in_test_process(
            concat!(module_path!(), "::child_environment_does_not_mutate_parent"),
            &[(key, Some("child-only")), ("PGDOG_TEST_REMOVED_ENV", None)],
        ) {
            assert_eq!(std::env::var(key).unwrap(), "child-only");
            assert!(std::env::var_os("PGDOG_TEST_REMOVED_ENV").is_none());
        } else {
            assert_eq!(std::env::var_os(key), before);
        }
    }
}
