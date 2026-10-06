-- Prove pg_catalog is first before any other lookup or operator query.
SELECT pg_catalog.current_schemas(true)::pg_catalog.text;

-- Constant SQL only. Parameters are always bound through ServerRequest::strict_internal.
SELECT pg_catalog.current_database()::pg_catalog.text,
       current_user::pg_catalog.text,
       (SELECT d.oid FROM pg_catalog.pg_database AS d
        WHERE d.datname = pg_catalog.current_database()),
       (SELECT r.oid FROM pg_catalog.pg_roles AS r
        WHERE r.rolname = current_user),
       (SELECT d.datdba FROM pg_catalog.pg_database AS d
        WHERE d.datname = pg_catalog.current_database()),
       (SELECT pg_catalog.has_database_privilege(current_user, d.oid, 'CREATE')
        FROM pg_catalog.pg_database AS d
        WHERE d.datname = pg_catalog.current_database()),
       EXISTS (SELECT 1 FROM pg_catalog.pg_namespace AS n
               WHERE n.nspname = ANY(pg_catalog.current_schemas(true))
                 AND pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE')),
       pg_catalog.current_setting('server_version_num')::pg_catalog.int4::pg_catalog.text;

-- The relation name is a bound, quoted, canonical parser identifier. to_regclass
-- is explicitly qualified to prevent search-path substitution.
SELECT c.oid, n.nspname, c.relname, c.relkind::pg_catalog.text,
       c.relpersistence::pg_catalog.text, c.relowner,
       c.relrowsecurity, c.relforcerowsecurity, c.relhasrules,
       c.relispartition,
       EXISTS (SELECT 1 FROM pg_catalog.pg_inherits AS inh
               WHERE inh.inhrelid = c.oid OR inh.inhparent = c.oid),
       pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE'),
       COALESCE(am.amname, '')
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_am AS am ON am.oid = c.relam
WHERE c.oid = pg_catalog.to_regclass($1)::pg_catalog.oid;

SELECT a.attrelid, a.attname, a.atttypid, tn.nspname, t.typname,
       t.typtype::pg_catalog.text, t.typbasetype,
       t.typinput::pg_catalog.oid, t.typoutput::pg_catalog.oid,
       t.typreceive::pg_catalog.oid, t.typsend::pg_catalog.oid,
       a.attnotnull, a.attgenerated::pg_catalog.text,
       a.attidentity::pg_catalog.text, a.attcollation
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid
JOIN pg_catalog.pg_namespace AS tn ON tn.oid = t.typnamespace
WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum;

-- Index AM, expression and predicate checks run for every selected relation.
-- V1 accepts only plain default pg_catalog btree indexes.
SELECT NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_index AS i
    JOIN pg_catalog.pg_class AS idx ON idx.oid = i.indexrelid
    JOIN pg_catalog.pg_am AS am ON am.oid = idx.relam
    WHERE i.indrelid = $1 AND (
        i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR am.amname <> 'btree'
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(i.indclass::pg_catalog.oid[]) AS classes(opclass_oid)
            JOIN pg_catalog.pg_opclass AS opc ON opc.oid = classes.opclass_oid
            JOIN pg_catalog.pg_namespace AS onsp ON onsp.oid = opc.opcnamespace
            WHERE onsp.nspname <> 'pg_catalog' OR NOT opc.opcdefault
               OR opc.opcmethod <> am.oid
               OR NOT (opc.oid = ANY(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[]))
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(i.indcollation::pg_catalog.oid[]) AS collations(collation_oid)
            WHERE collations.collation_oid NOT IN (0, 100, 950, 951)
        )
    )
) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS con
    WHERE con.conrelid = $1 AND con.contype IN ('c', 'x', 'f')
) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_statistic_ext AS stx
    WHERE stx.stxrelid = $1 AND stx.stxexprs IS NOT NULL
);

SELECT r.oid, r.rolsuper, r.rolcreaterole, r.rolcreatedb,
       r.rolreplication, r.rolbypassrls, r.rolinherit,
       EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m
               WHERE m.member = r.oid)
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = current_user;

-- Any visible same-name user overload is denied before the resolver chooses a
-- trusted pg_catalog signature, avoiding overload ambiguity and shadowing.
SELECT NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE p.proname = ANY(pg_catalog.string_to_array($1, ','))
      AND n.nspname <> 'pg_catalog'
      AND n.nspname = ANY(pg_catalog.current_schemas(true))
) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_operator AS o
    JOIN pg_catalog.pg_namespace AS n ON n.oid = o.oprnamespace
    WHERE o.oprname = ANY(pg_catalog.string_to_array($2, ','))
      AND n.nspname <> 'pg_catalog'
      AND n.nspname = ANY(pg_catalog.current_schemas(true))
) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS p
    WHERE p.pronamespace = (SELECT n.oid FROM pg_catalog.pg_namespace AS n
                            WHERE n.nspname = 'pg_catalog')
      AND p.proname = ANY(pg_catalog.string_to_array($1, ','))
      AND p.oid <> ALL(pg_catalog.string_to_array($3, ',')::pg_catalog.oid[])
) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_operator AS o
    WHERE o.oprnamespace = (SELECT n.oid FROM pg_catalog.pg_namespace AS n
                            WHERE n.nspname = 'pg_catalog')
      AND o.oprname = ANY(pg_catalog.string_to_array($2, ','))
      AND o.oid <> ALL(pg_catalog.string_to_array($4, ',')::pg_catalog.oid[])
);

-- Complete catalog rows for the pinned strict-read registry. The eleven ID lists
-- are bound from the embedded registry, and this query executes no user code.
SELECT 'pg_type'::pg_catalog.text, t.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(t), '{oid}', pg_catalog.to_jsonb(t.oid), true)
        || pg_catalog.jsonb_build_object(
            'typinput', pg_catalog.to_jsonb(t.typinput::pg_catalog.oid),
            'typoutput', pg_catalog.to_jsonb(t.typoutput::pg_catalog.oid),
            'typreceive', pg_catalog.to_jsonb(t.typreceive::pg_catalog.oid),
            'typsend', pg_catalog.to_jsonb(t.typsend::pg_catalog.oid),
            'typmodin', pg_catalog.to_jsonb(t.typmodin::pg_catalog.oid),
            'typmodout', pg_catalog.to_jsonb(t.typmodout::pg_catalog.oid),
            'typanalyze', pg_catalog.to_jsonb(t.typanalyze::pg_catalog.oid),
            'typsubscript', pg_catalog.to_jsonb(t.typsubscript::pg_catalog.oid)
        ))::pg_catalog.text
FROM pg_catalog.pg_type AS t WHERE t.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_proc', p.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(p), '{oid}', pg_catalog.to_jsonb(p.oid), true)
        || pg_catalog.jsonb_build_object(
            'prosupport', pg_catalog.to_jsonb(p.prosupport::pg_catalog.oid),
            'proargtypes', pg_catalog.to_jsonb(p.proargtypes::pg_catalog.text),
            'proallargtypes', pg_catalog.to_jsonb(p.proallargtypes::pg_catalog.text),
            'proargmodes', pg_catalog.to_jsonb(p.proargmodes::pg_catalog.text),
            'proconfig', pg_catalog.to_jsonb(p.proconfig::pg_catalog.text),
            'protrftypes', pg_catalog.to_jsonb(p.protrftypes::pg_catalog.text)
        ))::pg_catalog.text
FROM pg_catalog.pg_proc AS p WHERE p.oid = ANY(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_operator', o.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(o), '{oid}', pg_catalog.to_jsonb(o.oid), true)
        || pg_catalog.jsonb_build_object(
            'oprcode', pg_catalog.to_jsonb(o.oprcode::pg_catalog.oid),
            'oprrest', pg_catalog.to_jsonb(o.oprrest::pg_catalog.oid),
            'oprjoin', pg_catalog.to_jsonb(o.oprjoin::pg_catalog.oid)
        ))::pg_catalog.text
FROM pg_catalog.pg_operator AS o WHERE o.oid = ANY(pg_catalog.string_to_array($3, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_aggregate', a.aggfnoid::pg_catalog.oid::pg_catalog.text,
       (pg_catalog.to_jsonb(a) || pg_catalog.jsonb_build_object(
            'aggfnoid', pg_catalog.to_jsonb(a.aggfnoid::pg_catalog.oid),
            'aggtransfn', pg_catalog.to_jsonb(a.aggtransfn::pg_catalog.oid),
            'aggfinalfn', pg_catalog.to_jsonb(a.aggfinalfn::pg_catalog.oid),
            'aggcombinefn', pg_catalog.to_jsonb(a.aggcombinefn::pg_catalog.oid),
            'aggserialfn', pg_catalog.to_jsonb(a.aggserialfn::pg_catalog.oid),
            'aggdeserialfn', pg_catalog.to_jsonb(a.aggdeserialfn::pg_catalog.oid),
            'aggmtransfn', pg_catalog.to_jsonb(a.aggmtransfn::pg_catalog.oid),
            'aggminvtransfn', pg_catalog.to_jsonb(a.aggminvtransfn::pg_catalog.oid),
            'aggmfinalfn', pg_catalog.to_jsonb(a.aggmfinalfn::pg_catalog.oid),
            'aggsortop', pg_catalog.to_jsonb(a.aggsortop::pg_catalog.oid),
            'aggtranstype', pg_catalog.to_jsonb(a.aggtranstype::pg_catalog.oid),
            'aggmtranstype', pg_catalog.to_jsonb(a.aggmtranstype::pg_catalog.oid)
       ))::pg_catalog.text
FROM pg_catalog.pg_aggregate AS a WHERE a.aggfnoid = ANY(pg_catalog.string_to_array($4, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_cast', c.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(c), '{oid}', pg_catalog.to_jsonb(c.oid), true)
        || pg_catalog.jsonb_build_object('castfunc', pg_catalog.to_jsonb(c.castfunc::pg_catalog.oid)))::pg_catalog.text
FROM pg_catalog.pg_cast AS c WHERE c.oid = ANY(pg_catalog.string_to_array($5, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_am', a.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(a), '{oid}', pg_catalog.to_jsonb(a.oid), true)
        || pg_catalog.jsonb_build_object('amhandler', pg_catalog.to_jsonb(a.amhandler::pg_catalog.oid)))::pg_catalog.text
FROM pg_catalog.pg_am AS a WHERE a.oid = ANY(pg_catalog.string_to_array($6, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_collation', c.oid::pg_catalog.text,
       pg_catalog.jsonb_set(pg_catalog.to_jsonb(c), '{oid}', pg_catalog.to_jsonb(c.oid), true)::pg_catalog.text
FROM pg_catalog.pg_collation AS c WHERE c.oid = ANY(pg_catalog.string_to_array($7, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_opclass', c.oid::pg_catalog.text,
       pg_catalog.jsonb_set(pg_catalog.to_jsonb(c), '{oid}', pg_catalog.to_jsonb(c.oid), true)::pg_catalog.text
FROM pg_catalog.pg_opclass AS c WHERE c.oid = ANY(pg_catalog.string_to_array($8, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_opfamily', f.oid::pg_catalog.text,
       pg_catalog.jsonb_set(pg_catalog.to_jsonb(f), '{oid}', pg_catalog.to_jsonb(f.oid), true)::pg_catalog.text
FROM pg_catalog.pg_opfamily AS f WHERE f.oid = ANY(pg_catalog.string_to_array($9, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_amop', o.oid::pg_catalog.text,
       pg_catalog.jsonb_set(pg_catalog.to_jsonb(o), '{oid}', pg_catalog.to_jsonb(o.oid), true)::pg_catalog.text
FROM pg_catalog.pg_amop AS o WHERE o.oid = ANY(pg_catalog.string_to_array($10, ',')::pg_catalog.oid[])
UNION ALL
SELECT 'pg_amproc', p.oid::pg_catalog.text,
       (pg_catalog.jsonb_set(pg_catalog.to_jsonb(p), '{oid}', pg_catalog.to_jsonb(p.oid), true)
        || pg_catalog.jsonb_build_object('amproc', pg_catalog.to_jsonb(p.amproc::pg_catalog.oid)))::pg_catalog.text
FROM pg_catalog.pg_amproc AS p WHERE p.oid = ANY(pg_catalog.string_to_array($11, ',')::pg_catalog.oid[]);

-- Candidate-set closure: no new default scalar hash/btree classes, family
-- support procedures/operators, or scalar casts may appear outside the pinned
-- complete registry. These are planner dependencies, even when SQL is SELECT.
SELECT NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_opclass AS c
    WHERE c.opcintype = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[])
      AND c.opcmethod IN (403, 405) AND c.opcdefault
      AND c.oid <> ALL(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[])
), NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_amop AS o
    WHERE o.amopfamily = ANY(pg_catalog.string_to_array($3, ',')::pg_catalog.oid[])
      AND o.oid <> ALL(pg_catalog.string_to_array($4, ',')::pg_catalog.oid[])
), NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_amproc AS p
    WHERE p.amprocfamily = ANY(pg_catalog.string_to_array($3, ',')::pg_catalog.oid[])
      AND p.oid <> ALL(pg_catalog.string_to_array($5, ',')::pg_catalog.oid[])
), NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_cast AS c
    WHERE c.castsource = ANY(pg_catalog.string_to_array($6, ',')::pg_catalog.oid[])
      AND c.casttarget = ANY(pg_catalog.string_to_array($6, ',')::pg_catalog.oid[])
      AND c.oid <> ALL(pg_catalog.string_to_array($7, ',')::pg_catalog.oid[])
);
