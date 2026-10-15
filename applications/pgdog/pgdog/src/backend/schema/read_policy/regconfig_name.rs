//! Semantic name extraction after every catalog-expression dependency is proved.
//! Raw serialized Const bytes do not establish a backend's byte order or ABI.

pub(crate) fn builtin_name(deparsed: &str) -> Result<&'static str, ()> {
    use pg_raw_parse::{
        ConstValue, Node,
        walk::{self, Recurse},
    };
    use std::panic::{AssertUnwindSafe, catch_unwind};
    if deparsed.is_empty() || deparsed.len() > 256 * 1024 {
        return Err(());
    }
    let sql = format!("SELECT {deparsed}");
    let parsed = pg_raw_parse::parse(&sql).map_err(|_| ())?;
    let mut statements = parsed.stmts();
    let root = statements.next().ok_or(())?;
    if statements.next().is_some() || !matches!(root, Node::SelectStmt(_)) {
        return Err(());
    }
    let mut todo = vec![(root, 0)];
    let mut count = 0;
    let mut configuration = None;
    while let Some((node, depth)) = todo.pop() {
        count += 1;
        if depth > 64 || count > 4096 {
            return Err(());
        }
        match node {
            Node::SelectStmt(_) if depth != 0 => return Err(()),
            Node::SubLink(_) | Node::RangeVar(_) => return Err(()),
            Node::TypeCast(cast) => {
                let target = cast.type_name().ok_or(())?;
                let names = target
                    .names()
                    .iter()
                    .map(|name| name.sval().ok_or(()))
                    .collect::<Result<Vec<_>, _>>()?;
                if names.last().copied() == Some("regconfig") {
                    if !matches!(
                        names.as_slice(),
                        ["regconfig"] | ["pg_catalog", "regconfig"]
                    ) || !target.array_bounds().is_empty()
                        || !target.typmods().is_empty()
                        || target.pct_type
                        || configuration.is_some()
                    {
                        return Err(());
                    }
                    let Node::A_Const(constant) = cast.arg() else {
                        return Err(());
                    };
                    let Some(ConstValue::String(name)) = constant.val() else {
                        return Err(());
                    };
                    configuration = Some(match name {
                        "simple" | "pg_catalog.simple" => "simple",
                        "english" | "pg_catalog.english" => "english",
                        _ => return Err(()),
                    });
                }
            }
            _ => (),
        }
        let walked = catch_unwind(AssertUnwindSafe(|| {
            walk::walk_manual::<()>(node, |child| {
                todo.push((child, depth + 1));
                Recurse::no()
            })
        }));
        if walked.is_err() || matches!(walked, Ok(Some(()))) {
            return Err(());
        }
    }
    configuration.ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_only_explicit_exact_catalog_config_literals() {
        assert_eq!(
            builtin_name("to_tsvector('simple'::regconfig, payload)"),
            Ok("simple")
        );
        assert_eq!(
            builtin_name("to_tsvector('pg_catalog.english'::pg_catalog.regconfig, payload)"),
            Ok("english")
        );
        for expression in [
            "to_tsvector('public.english'::regconfig, payload)",
            "to_tsvector(current_setting('default_text_search_config')::regconfig, payload)",
            "to_tsvector(1::regconfig, payload)",
            "to_tsvector(payload)",
            "to_tsvector('simple'::regconfig, payload) || to_tsvector('english'::regconfig, payload)",
            "to_tsvector('simple'::regconfig, payload); SELECT 1",
            "to_tsvector('simple'::public.regconfig, payload)",
            "to_tsvector('simple'::regconfig[], payload)",
            "to_tsvector((SELECT 'simple')::regconfig, payload)",
        ] {
            assert!(builtin_name(expression).is_err(), "{expression}");
        }
    }
}
