//! Build revision selection, kept independent from native C compilation.

pub fn resolve_revision(
    explicit: Option<&str>,
    git: Option<&str>,
    fallback: &str,
) -> Result<String, &'static str> {
    fn valid(value: &str) -> bool {
        value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    if let Some(value) = explicit {
        if !valid(value) {
            return Err("PGDOG_BUILD_REVISION must be a full 40-character Git SHA");
        }
        return Ok(value[..7].to_ascii_lowercase());
    }
    match git.filter(|value| valid(value)) {
        Some(value) => Ok(value[..7].to_ascii_lowercase()),
        None => Ok(fallback.to_owned()),
    }
}
