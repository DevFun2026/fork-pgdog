#!/usr/bin/env python3
"""Create private, source-redacted PostgreSQL catalog fixtures from local pins.

This producer never pulls images and runs containers with networking disabled.
Its output contains system catalog metadata and extension module hashes only;
function source is replaced inside PostgreSQL with UTF-8 SHA-256 markers before
any rows are serialized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from read_policy_registry import pinned_image

TABLES = (
    'pg_type','pg_proc','pg_operator','pg_aggregate','pg_cast','pg_am',
    'pg_collation','pg_opclass','pg_opfamily','pg_amop','pg_amproc',
    'pg_namespace','pg_extension','pg_range','pg_enum','pg_ts_config',
    'pg_ts_config_map','pg_ts_parser','pg_ts_dict','pg_ts_template',
)
OID_FIELDS = {
    'pg_type': ('typinput','typoutput','typreceive','typsend','typmodin','typmodout','typanalyze','typsubscript'),
    'pg_proc': ('prosupport',),
    'pg_operator': ('oprcode','oprrest','oprjoin'),
    'pg_aggregate': ('aggfnoid','aggtransfn','aggfinalfn','aggcombinefn','aggserialfn','aggdeserialfn','aggmtransfn','aggminvtransfn','aggmfinalfn','aggsortop'),
    'pg_cast': ('castfunc',),
    'pg_am': ('amhandler',),
    'pg_amproc': ('amproc',),
    'pg_range': ('rngcanonical','rngsubdiff'),
    'pg_ts_parser': ('prsstart','prstoken','prsend','prsheadline','prslextype'),
    'pg_ts_template': ('tmplinit','tmpllexize'),
}
DDL = 'CREATE EXTENSION pg_trgm; CREATE EXTENSION btree_gist;'
INDEX_MATRIX_DDL = """CREATE TABLE public.read_policy_index_matrix (
    id integer, doc jsonb, tags text[], body text, during tstzrange,
    label varchar(255), short_label varchar(36), amount numeric(8,2),
    amounts numeric(8,2)[][]
);
CREATE INDEX matrix_btree_include ON public.read_policy_index_matrix (label) INCLUDE (id);
CREATE INDEX matrix_btree_typmod ON public.read_policy_index_matrix (short_label) INCLUDE (amount, amounts);
CREATE INDEX matrix_hash_text ON public.read_policy_index_matrix USING hash (body);
CREATE INDEX matrix_gin_jsonb ON public.read_policy_index_matrix USING gin (doc);
CREATE INDEX matrix_gin_array ON public.read_policy_index_matrix USING gin (tags);
CREATE INDEX matrix_gist_range ON public.read_policy_index_matrix USING gist (during);
CREATE INDEX matrix_gist_trgm ON public.read_policy_index_matrix USING gist (body gist_trgm_ops);
CREATE INDEX matrix_gist_btree_gist ON public.read_policy_index_matrix USING gist (id);
"""
MISSING_VALUE_CANARY_DDL = """CREATE TYPE public.read_policy_missing_enum AS ENUM ('synthetic');
CREATE TABLE public.read_policy_missing_canary (id integer);
INSERT INTO public.read_policy_missing_canary VALUES (1);
ALTER TABLE public.read_policy_missing_canary
    ADD COLUMN value public.read_policy_missing_enum DEFAULT 'synthetic';
CREATE FUNCTION public.read_policy_missing_enum_json(public.read_policy_missing_enum)
RETURNS json LANGUAGE plpgsql VOLATILE AS $body$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(2147483000, 2147483001);
    RETURN pg_catalog.to_json($1::pg_catalog.text);
END
$body$;
CREATE CAST (public.read_policy_missing_enum AS json)
    WITH FUNCTION public.read_policy_missing_enum_json(public.read_policy_missing_enum)
    AS ASSIGNMENT;
"""

ATTRIBUTE_FIELDS = (
    'attacl','attalign','attbyval','attcollation','attfdwoptions','attgenerated',
    'atthasdef','atthasmissing','attmissingval_present','attidentity','attinhcount',
    'attisdropped','attislocal','attlen','attname','attndims','attnotnull','attnum',
    'attoptions','attrelid','attstattarget','attstorage','atttypid','atttypmod',
)


def safe_attribute_projection(alias: str, major: int) -> str:
    if alias not in {'a'} or major not in {12, 18}:
        raise ValueError('unsupported attribute projection')
    fields = list(ATTRIBUTE_FIELDS)
    if major == 12:
        fields.append('attcacheoff')
    else:
        fields.append('attcompression')
    pairs = []
    for field in fields:
        if field == 'attmissingval_present':
            value = f'({alias}.attmissingval IS NOT NULL)'
        else:
            value = f'{alias}.{field}'
        pairs.append(f"'{field}', {value}")
    return 'pg_catalog.jsonb_build_object('+', '.join(pairs)+')'


def assert_missing_value_io_canary(container: str, major: int) -> dict:
    sql(container, MISSING_VALUE_CANARY_DDL)
    # This intentionally unsafe baseline runs only against the owned synthetic
    # container and proves that whole-row conversion reaches the custom JSON
    # cast hidden inside pg_attribute.attmissingval.
    unsafe_probe = """DO $probe$
BEGIN
    PERFORM pg_catalog.octet_length(pg_catalog.to_jsonb(a)::pg_catalog.text)
      FROM pg_catalog.pg_attribute AS a
     WHERE a.attrelid='public.read_policy_missing_canary'::pg_catalog.regclass
       AND a.attnum > 0;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks
         WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
           AND granted AND classid=2147483000::pg_catalog.oid
           AND objid=2147483001::pg_catalog.oid
    ) THEN RAISE EXCEPTION 'unsafe whole-row baseline did not execute canary'; END IF;
END
$probe$"""
    sql(container, unsafe_probe)

    safe_probe = f"""DO $probe$
BEGIN
    PERFORM pg_catalog.octet_length(({safe_attribute_projection('a', major)})::pg_catalog.text)
      FROM pg_catalog.pg_attribute AS a
     WHERE a.attrelid='public.read_policy_missing_canary'::pg_catalog.regclass
       AND a.attnum > 0;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks
         WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
           AND granted AND classid=2147483000::pg_catalog.oid
           AND objid=2147483001::pg_catalog.oid
    ) THEN RAISE EXCEPTION 'safe attribute projection executed canary'; END IF;
END
$probe$"""
    sql(container, safe_probe)
    return {'major':major,'unsafe_baseline_executed':True,'safe_projection_executed':False}


def run(args: list[str], *, input: str | None = None, timeout: int = 180) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          input=input, timeout=timeout).stdout


def sql(container: str, statement: str) -> str:
    try:
        return run([
            'docker','exec','-i',container,'psql','-XqAt','-v','ON_ERROR_STOP=1',
            '-U','postgres','-d','postgres',
        ],input=statement)
    except subprocess.CalledProcessError as error:
        raise RuntimeError('catalog query failed: '+(error.stderr or '').strip()) from error


def source_hash(expression: str) -> str:
    return (
        "pg_catalog.jsonb_build_object('sha256_utf8', "
        "pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to("+expression+", 'UTF8')), 'hex'))"
    )


def row_expression(table: str, major: int) -> str:
    fields = list(OID_FIELDS.get(table, ()))
    if major == 12:
        fields = [field for field in fields if field != 'typsubscript']
    if table == 'pg_proc':
        fields.extend(('proargtypes','proallargtypes','proargmodes','proconfig'))
        if major >= 14:
            fields.append('protrftypes')
    pairs = []
    for field in fields:
        cast = 'pg_catalog.text' if field in {'proargtypes','proallargtypes','proargmodes','proconfig','protrftypes'} else 'pg_catalog.oid'
        pairs.append(("'"+field+"'", f'pg_catalog.to_jsonb(t.{field}::{cast})'))
    base = 'pg_catalog.to_jsonb(t)'
    if table == 'pg_proc':
        subtract = " - 'prosrc'"
        replacements = ["'prosrc', "+source_hash('t.prosrc')]
        if major >= 14:
            subtract += " - 'prosqlbody'"
            marker = (
                "CASE WHEN t.prosqlbody IS NULL THEN NULL::pg_catalog.jsonb ELSE "
                +source_hash('t.prosqlbody::pg_catalog.text')+" END"
            )
            replacements.append("'prosqlbody', "+marker)
        base = f'({base}{subtract}) || pg_catalog.jsonb_build_object('+', '.join(replacements)+')'
    if pairs:
        base += ' || pg_catalog.jsonb_build_object('+', '.join(
            f'{key}, {value}' for key,value in pairs)+')'
    return base


def capture_index_attribute_matrix(container: str, major: int, output_dir: Path) -> dict:
    sql(container, INDEX_MATRIX_DDL)
    canary = assert_missing_value_io_canary(container, major)
    attribute_projection = safe_attribute_projection('a', major)
    query = f"""WITH tab AS (
    SELECT c.oid FROM pg_catalog.pg_class c
    WHERE c.relname='read_policy_index_matrix'
      AND c.relnamespace='public'::pg_catalog.regnamespace
), idx AS (
    SELECT i.* FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
    WHERE c.relname LIKE 'matrix_%'
      AND c.relnamespace='public'::pg_catalog.regnamespace
)
SELECT pg_catalog.json_build_object(
    'major', pg_catalog.current_setting('server_version_num')::pg_catalog.int4 / 10000,
    'indexes', (SELECT pg_catalog.json_agg(
        pg_catalog.json_build_object('index', pg_catalog.to_jsonb(i),
                                     'relation', pg_catalog.to_jsonb(c))
        ORDER BY c.relname)
        FROM idx i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid),
    'index_attributes', (SELECT pg_catalog.json_agg({attribute_projection}
        ORDER BY a.attrelid,a.attnum) FROM pg_catalog.pg_attribute a
        WHERE a.attrelid IN (SELECT indexrelid FROM idx) AND a.attnum > 0),
    'table', (SELECT pg_catalog.to_jsonb(c) FROM pg_catalog.pg_class c
        WHERE c.oid=(SELECT oid FROM tab)),
    'table_attributes', (SELECT pg_catalog.json_agg({attribute_projection}
        ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
        WHERE a.attrelid=(SELECT oid FROM tab) AND a.attnum > 0)
 )::pg_catalog.text"""
    matrix = json.loads(sql(container, query).strip())
    expected_names = {
        'matrix_btree_include', 'matrix_btree_typmod', 'matrix_hash_text', 'matrix_gin_jsonb',
        'matrix_gin_array', 'matrix_gist_range', 'matrix_gist_trgm',
        'matrix_gist_btree_gist',
    }
    names = {item['relation']['relname'] for item in matrix.get('indexes', [])}
    if matrix.get('major') != major or names != expected_names:
        raise RuntimeError(f'PG{major} synthetic index matrix is incomplete')
    if len(matrix.get('index_attributes', [])) != 11 or len(matrix.get('table_attributes', [])) != 9:
        raise RuntimeError(f'PG{major} synthetic index attribute inventory is incomplete')
    for attribute in matrix['index_attributes']+matrix['table_attributes']:
        if 'attmissingval' in attribute or attribute.get('attmissingval_present') is not False:
            raise RuntimeError(f'PG{major} safe attribute projection shape is invalid')
    path = output_dir/f'index-attribute-matrix-pg{major}.json'
    encoded = (json.dumps(matrix, sort_keys=True, separators=(',', ':'))+'\n').encode()
    path.write_bytes(encoded)
    path.chmod(0o600)
    return {'path':str(path),'indexes':len(names),
            'index_attributes':len(matrix['index_attributes']),
            'table_attributes':len(matrix['table_attributes']),
            'missing_value_canary':canary}


def capture_major(major: int, output_dir: Path, *, matrix_only: bool = False) -> dict:
    image = pinned_image(major)
    # docker run may pull by default; requiring a local image makes the
    # no-egress property explicit before any container is created.
    try:
        run(['docker','image','inspect',image],timeout=30)
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        raise RuntimeError(
            f'local pinned PostgreSQL {major} image is unavailable; no pull was attempted'
        ) from error
    inspected = json.loads(run(['docker','image','inspect',image]))[0]
    platform = inspected.get('Os')+'/'+inspected.get('Architecture')
    if platform not in ('linux/amd64','linux/arm64'):
        raise RuntimeError(f'unsupported local pinned image platform: {platform}')

    container_name = 'pgdog-read-profile-'+str(major)+'-'+uuid.uuid4().hex
    container_id = ''
    try:
        with tempfile.TemporaryDirectory(prefix='pgdog-read-profile-') as temp:
            env_file = Path(temp)/'postgres.env'
            env_file.write_text('POSTGRES_PASSWORD='+secrets.token_hex(32)+'\n',encoding='utf-8')
            env_file.chmod(0o600)
            container_id = run([
                'docker','run','--detach','--name',container_name,'--network','none',
                '--env-file',str(env_file),image,
            ]).strip()
        for _ in range(120):
            # The official entrypoint's temporary init server accepts only
            # Unix sockets. Wait for the final server's loopback TCP listener
            # so catalog capture cannot race the temporary server shutdown.
            if subprocess.run(['docker','exec',container_id,'pg_isready','-h','127.0.0.1','-U','postgres'],
                              capture_output=True,timeout=10,check=False).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f'local PostgreSQL {major} fixture did not become ready')
        sql(container_id,DDL)
        if matrix_only:
            matrix = capture_index_attribute_matrix(container_id, major, output_dir)
            return {'major':major,'index_attribute_matrix':matrix}
        result = {
            'postgres_major':major,
            'source_image':image,
            'server_version':sql(container_id,'SHOW server_version').strip(),
            'server_version_num':int(sql(container_id,'SHOW server_version_num').strip()),
            'platform':platform,
            'capture_id':container_name,
            'tables':{},
        }
        for table in TABLES:
            query='SELECT ('+row_expression(table,major)+')::pg_catalog.text FROM pg_catalog.'+table+' t'
            result['tables'][table]=[
                json.loads(line) for line in sql(container_id,query).splitlines() if line.strip()
            ]
        result['extension_members']=[
            json.loads(line) for line in sql(container_id,
                "SELECT pg_catalog.row_to_json(x)::pg_catalog.text FROM ("
                "SELECT d.classid::pg_catalog.regclass::pg_catalog.text AS catalog, d.objid, "
                "d.objsubid, e.extname FROM pg_catalog.pg_depend d "
                "JOIN pg_catalog.pg_extension e ON d.refobjid=e.oid "
                "WHERE d.refclassid='pg_catalog.pg_extension'::pg_catalog.regclass "
                "AND d.deptype='e') x").splitlines() if line.strip()
        ]
        result['module_sha256']=run([
            'docker','exec',container_id,'sh','-c',
            'sha256sum "$(pg_config --pkglibdir)/pg_trgm.so" "$(pg_config --pkglibdir)/btree_gist.so"',
        ]).splitlines()
        # Capture the independent synthetic access-method matrix only after
        # the reference catalog and extension membership snapshot are complete.
        matrix = capture_index_attribute_matrix(container_id, major, output_dir)
        output=output_dir/f'reference-extended-pg{major}.json'
        encoded=(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode()
        output.write_bytes(encoded)
        output.chmod(0o600)
        return {'major':major,'path':str(output),'sha256':hashlib.sha256(encoded).hexdigest(),
                'catalog_rows':sum(map(len,result['tables'].values())),
                'extension_members':len(result['extension_members']),
                'index_attribute_matrix':matrix}
    finally:
        if container_id or container_name:
            subprocess.run(['docker','rm','--force',container_id or container_name],check=False,
                           capture_output=True,text=True,timeout=30)


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True,
                        help='private temporary directory for mode-0600 JSON fixtures')
    parser.add_argument('--matrix-only', action='store_true',
                        help='refresh only the owned synthetic index/attribute matrix')
    args=parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(args.output_dir,0o700)
    results=[capture_major(major,args.output_dir,matrix_only=args.matrix_only) for major in (12,18)]
    print(json.dumps(results,sort_keys=True))


if __name__=='__main__':
    main()
