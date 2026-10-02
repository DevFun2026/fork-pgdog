use std::process::Command;

mod build_metadata;

// Compile time checks.
fn main() {
    println!("cargo:rerun-if-changed=src/frontend/router/sharding/hashfn.c");
    println!("cargo:rerun-if-changed=build_metadata.rs");
    println!("cargo:rerun-if-env-changed=PGDOG_BUILD_REVISION");

    cc::Build::new()
        .file("src/frontend/router/sharding/hashfn.c")
        .flags(["-Wno-implicit-fallthrough"])
        .compile("postgres_hash");

    let explicit = std::env::var("PGDOG_BUILD_REVISION")
        .ok()
        .filter(|value| !value.is_empty());
    let git = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok());
    let revision = build_metadata::resolve_revision(
        explicit.as_deref(),
        git.as_deref().map(str::trim),
        env!("CARGO_PKG_VERSION"),
    )
    .expect("invalid build revision");
    println!("cargo:rustc-env=GIT_HASH={revision}");
}
