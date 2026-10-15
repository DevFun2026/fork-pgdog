"""Offline version-bound dependency profiles; never accept live application catalogs."""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from read_policy_registry import pinned_image, validate_provenance


class ProfileError(ValueError):
    pass

MAX_ROWS = 20000
PROFILE_FORMAT_V1 = 'pgdog-read-dependency-profile/v1'
PROFILE_FORMAT = 'pgdog-read-dependency-profile/v2'
CATALOGS = ('pg_aggregate','pg_am','pg_amop','pg_amproc','pg_cast','pg_collation',
    'pg_enum','pg_extension','pg_namespace','pg_opclass','pg_operator','pg_opfamily',
    'pg_proc','pg_range','pg_ts_config','pg_ts_config_map','pg_ts_dict','pg_ts_parser',
    'pg_ts_template','pg_type')
EXPLICIT_TYPES = {
    'bool','bytea','int2','int4','int8','float4','float8','text','bpchar','varchar',
    'date','time','timestamp','timestamptz','interval','timetz','numeric','uuid','oid',
    'jsonb','regconfig','regdictionary','regtype','anyelement','anyarray','anyenum',
    'tsvector','tsquery','int4range','int8range','numrange','tsrange','tstzrange','daterange',
}
FUNCTION_ROOTS = {'date_trunc','timezone','tstzrange','to_tsvector','right','lower','concat',
    'count','sum','avg','min','max','enum_in','enum_out','enum_recv','enum_send',
    'time','interval','textcat','jsonb_object_field_text'}
OPERATOR_ROOTS = {'=','<>','<','<=','>','>=','+','-','*','/','%','^','||','~~','!~~','~~*','!~~*',
    '->','->>','#>','#>>','?','?|','?&','@>','<@','&&'}
INDEX_METHODS = {'btree','hash','gin','gist'}
EXTENSIONS = {'pg_trgm','btree_gist'}
EXPECTED_EXTENSION_MEMBER_COUNTS = {
    12: {
        'btree_gist': {'pg_opclass':25,'pg_operator':12,'pg_opfamily':25,'pg_proc':179,'pg_type':5},
        'pg_trgm': {'pg_opclass':2,'pg_operator':10,'pg_opfamily':2,'pg_proc':30,'pg_type':1},
    },
    18: {
        'btree_gist': {'pg_opclass':26,'pg_operator':12,'pg_opfamily':26,'pg_proc':212,'pg_type':12},
        'pg_trgm': {'pg_opclass':2,'pg_operator':10,'pg_opfamily':2,'pg_proc':31,'pg_type':2},
    },
}
EXPECTED_PROFILE_ROW_COUNTS = {
    (12, ()): (57,5,272,161,95,3,0,0,1,59,595,47,1282,6,2,38,2,1,2,124),
    (12, ('pg_trgm',)): (57,5,289,174,95,3,0,1,2,61,609,49,1326,6,2,38,2,1,2,126),
    (12, ('btree_gist',)): (57,5,439,371,95,3,0,1,2,84,607,73,1466,6,2,38,2,1,2,136),
    (12, ('btree_gist','pg_trgm')): (57,5,456,384,95,3,0,2,2,86,621,75,1510,6,2,38,2,1,2,138),
    (18, ()): (65,5,280,191,107,3,0,0,1,59,632,47,1400,6,2,38,2,1,2,141),
    (18, ('pg_trgm',)): (65,5,299,205,107,3,0,1,2,61,646,49,1445,6,2,38,2,1,2,143),
    (18, ('btree_gist',)): (65,5,453,462,107,3,0,1,2,85,644,74,1617,6,2,38,2,1,2,155),
    (18, ('btree_gist','pg_trgm')): (65,5,472,476,107,3,0,2,2,87,658,76,1662,6,2,38,2,1,2,157),
}
BUILTIN_IDENTITIES = {
    'pg_ts_config': {'pg_catalog.simple','pg_catalog.english'},
    'pg_ts_dict': {'pg_catalog.simple','pg_catalog.english_stem'},
    'pg_ts_template': {'pg_catalog.simple','pg_catalog.snowball'},
    'pg_proc': {
        'pg_catalog.dsnowball_init(pg_catalog.internal)->pg_catalog.internal/f',
        'pg_catalog.dsnowball_lexize(pg_catalog.internal,pg_catalog.internal,pg_catalog.internal,pg_catalog.internal)->pg_catalog.internal/f',
    },
}
# Direct catalog edges are explicit: pinned built-ins need not have pg_depend rows.
EDGES = {
    'pg_type': {'typelem':'pg_type','typarray':'pg_type','typbasetype':'pg_type','typcollation':'pg_collation',
        **{f:'pg_proc' for f in ('typinput','typoutput','typreceive','typsend','typmodin','typmodout','typanalyze','typsubscript')}},
    'pg_proc': {'prorettype':'pg_type','provariadic':'pg_type','prosupport':'pg_proc'},
    'pg_operator': {'oprleft':'pg_type','oprright':'pg_type','oprresult':'pg_type',
        'oprcode':'pg_proc','oprrest':'pg_proc','oprjoin':'pg_proc','oprcom':'pg_operator','oprnegate':'pg_operator'},
    'pg_cast': {'castsource':'pg_type','casttarget':'pg_type','castfunc':'pg_proc'},
    'pg_am': {'amhandler':'pg_proc'},
    'pg_opclass': {'opcmethod':'pg_am','opcfamily':'pg_opfamily','opcintype':'pg_type','opckeytype':'pg_type'},
    'pg_opfamily': {'opfmethod':'pg_am'},
    'pg_amop': {'amopfamily':'pg_opfamily','amoplefttype':'pg_type','amoprighttype':'pg_type',
        'amopopr':'pg_operator','amopmethod':'pg_am','amopsortfamily':'pg_opfamily'},
    'pg_amproc': {'amprocfamily':'pg_opfamily','amproclefttype':'pg_type','amprocrighttype':'pg_type','amproc':'pg_proc'},
    'pg_range': {'rngtypid':'pg_type','rngsubtype':'pg_type','rngcollation':'pg_collation',
        'rngsubopc':'pg_opclass','rngcanonical':'pg_proc','rngsubdiff':'pg_proc','rngmultitypid':'pg_type'},
    'pg_aggregate': {**{f:'pg_proc' for f in ('aggfnoid','aggtransfn','aggfinalfn','aggcombinefn','aggserialfn',
        'aggdeserialfn','aggmtransfn','aggminvtransfn','aggmfinalfn')},
        'aggsortop':'pg_operator','aggtranstype':'pg_type','aggmtranstype':'pg_type'},
    'pg_collation': {},
    'pg_ts_config': {'cfgparser':'pg_ts_parser'},
    'pg_ts_parser': {f:'pg_proc' for f in ('prsstart','prstoken','prsend','prsheadline','prslextype')},
    'pg_ts_dict': {'dicttemplate':'pg_ts_template'},
    'pg_ts_template': {'tmplinit':'pg_proc','tmpllexize':'pg_proc'},
}

def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileError(f'malformed {label}')
    return value

def _oid_indexes(tables: dict[str, list[dict]]) -> dict[str, dict[int, dict]]:
    indexes={}
    for table in CATALOGS:
        rows=tables.get(table)
        if not isinstance(rows,list): raise ProfileError('missing catalog '+table)
        index={}
        for ordinal,row in enumerate(rows):
            if not isinstance(row,dict): raise ProfileError('malformed catalog row')
            if table=='pg_ts_config_map':
                try: ident=(oid(row['mapcfg']),oid(row['maptokentype']),oid(row['mapseqno']))
                except (KeyError,TypeError) as error: raise ProfileError('malformed text search map') from error
            else:
                key='aggfnoid' if table=='pg_aggregate' else 'rngtypid' if table=='pg_range' else 'oid'
                if key not in row: raise ProfileError('malformed catalog row')
                ident=oid(row[key])
            if ident in index: raise ProfileError('duplicate catalog identity')
            index[ident]=row
        indexes[table]=index
    return indexes

def _qualified(namespace: str, name: str) -> str:
    return f'{namespace}.{name}'

def _sig_type(identities: dict[str,dict[int,str]], value: Any) -> str:
    number=oid(value,zero=True)
    return '0' if number==0 else identities['pg_type'].get(number, f'oid:{number}')

def _build_identities(indexes: dict[str,dict[int,dict]], members: dict[tuple[str,int],str]) -> dict[str,dict[int,str]]:
    ids: dict[str,dict[int,str]]={t:{} for t in CATALOGS}
    ns={i:_text(r.get('nspname'),'namespace') for i,r in indexes['pg_namespace'].items()}
    am={i:_text(r.get('amname'),'access method') for i,r in indexes['pg_am'].items()}
    for i,r in indexes['pg_namespace'].items(): ids['pg_namespace'][i]=r['nspname']
    for i,r in indexes['pg_extension'].items(): ids['pg_extension'][i]=_text(r.get('extname'),'extension name')
    for i,r in indexes['pg_am'].items(): ids['pg_am'][i]=r['amname']
    for i,r in indexes['pg_type'].items():
        n=ns.get(oid(r.get('typnamespace')))
        if n is None: raise ProfileError('type references missing namespace')
        ids['pg_type'][i]=_qualified(n,_text(r.get('typname'),'type name'))
    for i,r in indexes['pg_proc'].items():
        n=ns.get(oid(r.get('pronamespace')))
        if n is None: raise ProfileError('function references missing namespace')
        args=','.join(_sig_type(ids, v) for v in oid_list(r.get('proargtypes')))
        ret=_sig_type(ids,r.get('prorettype'))
        ids['pg_proc'][i]=f'{_qualified(n,_text(r.get("proname"),"function name"))}({args})->{ret}/{_text(r.get("prokind"),"function kind")}'
    for i,r in indexes['pg_operator'].items():
        n=ns.get(oid(r.get('oprnamespace')))
        if n is None: raise ProfileError('operator references missing namespace')
        ids['pg_operator'][i]=f'{_qualified(n,_text(r.get("oprname"),"operator name"))}({_sig_type(ids,r.get("oprleft"))},{_sig_type(ids,r.get("oprright"))})'
    for table, prefix, nfield, namefield, methodfield in (
        ('pg_opclass','opclass','opcnamespace','opcname','opcmethod'),
        ('pg_opfamily','opfamily','opfnamespace','opfname','opfmethod')):
        for i,r in indexes[table].items():
            n=ns.get(oid(r.get(nfield))); method=am.get(oid(r.get(methodfield)))
            if n is None or method is None: raise ProfileError(f'{table} references missing namespace or method')
            ids[table][i]=f'{_qualified(n,_text(r.get(namefield),prefix+" name"))}@{method}'
    for i,r in indexes['pg_amop'].items():
        family=ids['pg_opfamily'].get(oid(r.get('amopfamily')))
        if family is None: raise ProfileError('operator support row references missing family')
        ids['pg_amop'][i]=f'{family}/{_sig_type(ids,r.get("amoplefttype"))}/{_sig_type(ids,r.get("amoprighttype"))}/{r.get("amoppurpose")}/{r.get("amopstrategy")}/{am.get(oid(r.get("amopmethod")),"?")}'
    for i,r in indexes['pg_amproc'].items():
        family=ids['pg_opfamily'].get(oid(r.get('amprocfamily')))
        if family is None: raise ProfileError('procedure support row references missing family')
        ids['pg_amproc'][i]=f'{family}/{_sig_type(ids,r.get("amproclefttype"))}/{_sig_type(ids,r.get("amprocrighttype"))}/{r.get("amprocnum")}'
    for i,r in indexes['pg_cast'].items():
        ids['pg_cast'][i]=f'{_sig_type(ids,r.get("castsource"))}->{_sig_type(ids,r.get("casttarget"))}/{r.get("castcontext")}/{r.get("castmethod")}'
    for i,r in indexes['pg_collation'].items():
        n=ns.get(oid(r.get('collnamespace')))
        if n is None: raise ProfileError('collation references missing namespace')
        ids['pg_collation'][i]=f'{_qualified(n,_text(r.get("collname"),"collation name"))}/{r.get("collprovider")}/{r.get("collencoding")}'
    for i,r in indexes['pg_range'].items(): ids['pg_range'][i]=ids['pg_type'].get(oid(r.get('rngtypid')),'')
    for table,nfield,namefield in (('pg_ts_config','cfgnamespace','cfgname'),('pg_ts_dict','dictnamespace','dictname'),('pg_ts_parser','prsnamespace','prsname'),('pg_ts_template','tmplnamespace','tmplname')):
        for i,r in indexes[table].items():
            n=ns.get(oid(r.get(nfield)))
            if n is None: raise ProfileError(f'{table} references missing namespace')
            ids[table][i]=_qualified(n,_text(r.get(namefield),table+' name'))
    for table,key,ref in (('pg_aggregate','aggfnoid','pg_proc'),):
        for i,r in indexes[table].items(): ids[table][i]=ids[ref].get(oid(r.get(key)),'')
    for i,r in indexes['pg_ts_config_map'].items():
        ids['pg_ts_config_map'][i]=f'{ids["pg_ts_config"].get(oid(r.get("mapcfg")),"?")}/{oid(r.get("maptokentype"))}/{oid(r.get("mapseqno"))}'
    for table,expected in BUILTIN_IDENTITIES.items():
        matched=[(oid_value,identity) for oid_value,identity in ids[table].items() if identity in expected]
        if {identity for _,identity in matched}!=expected or len(matched)!=len(expected):
            raise ProfileError(f'incomplete or ambiguous pg_catalog builtin set in {table}')
        for oid_value,identity in matched:
            ids[table][oid_value]=f'$builtin:{table}:{identity}'
    # Direct extension members get identities from their catalog row. Auto-created
    # array types may not be listed as extension members; their qualified type name
    # remains stable and is assigned to the owning extension through typelem.
    for (table,objid),extname in members.items():
        if table in ids and objid in ids[table]:
            ids[table][objid]=f'$extension:{extname}:{table}:{ids[table][objid]}'
    for oid_value,row in indexes['pg_type'].items():
        elem=oid(row.get('typelem',0),zero=True)
        if elem and ('pg_type',elem) in members:
            extname=members[('pg_type',elem)]
            if ('pg_type',oid_value) not in members:
                ids['pg_type'][oid_value]=f'$extension:{extname}:pg_type:{ids["pg_type"][oid_value]}'
    # AM operator/procedure rows are not always direct extension members.
    for table,family_field in (('pg_amop','amopfamily'),('pg_amproc','amprocfamily')):
        for i,r in indexes[table].items():
            family=oid(r.get(family_field))
            ext=members.get(('pg_opfamily',family))
            if ext: ids[table][i]=f'$extension:{ext}:{table}:{ids[table][i]}'
    return ids

OID_FIELDS = {
    'pg_type': {'typnamespace':'pg_namespace','typelem':'pg_type','typarray':'pg_type','typbasetype':'pg_type','typcollation':'pg_collation',**{f:'pg_proc' for f in ('typinput','typoutput','typreceive','typsend','typmodin','typmodout','typanalyze','typsubscript')},'typrelid':None},
    'pg_proc': {'pronamespace':'pg_namespace','prorettype':'pg_type','provariadic':'pg_type','prosupport':'pg_proc','prolang':None,'proowner':None},
    'pg_operator': {'oprnamespace':'pg_namespace','oprleft':'pg_type','oprright':'pg_type','oprresult':'pg_type','oprcode':'pg_proc','oprrest':'pg_proc','oprjoin':'pg_proc','oprcom':'pg_operator','oprnegate':'pg_operator'},
    'pg_aggregate': {**{f:'pg_proc' for f in ('aggfnoid','aggtransfn','aggfinalfn','aggcombinefn','aggserialfn','aggdeserialfn','aggmtransfn','aggminvtransfn','aggmfinalfn')},'aggsortop':'pg_operator','aggtranstype':'pg_type','aggmtranstype':'pg_type'},
    'pg_cast': {'castsource':'pg_type','casttarget':'pg_type','castfunc':'pg_proc'},
    'pg_am': {'amhandler':'pg_proc'}, 'pg_collation': {'collnamespace':'pg_namespace','collowner':None},
    'pg_opclass': {'opcmethod':'pg_am','opcfamily':'pg_opfamily','opcintype':'pg_type','opckeytype':'pg_type','opcnamespace':'pg_namespace','opcowner':None},
    'pg_opfamily': {'opfmethod':'pg_am','opfnamespace':'pg_namespace','opfowner':None},
    'pg_amop': {'amopfamily':'pg_opfamily','amoplefttype':'pg_type','amoprighttype':'pg_type','amopopr':'pg_operator','amopmethod':'pg_am','amopsortfamily':'pg_opfamily'},
    'pg_amproc': {'amprocfamily':'pg_opfamily','amproclefttype':'pg_type','amprocrighttype':'pg_type','amproc':'pg_proc'},
    'pg_range': {'rngtypid':'pg_type','rngsubtype':'pg_type','rngcollation':'pg_collation','rngsubopc':'pg_opclass','rngcanonical':'pg_proc','rngsubdiff':'pg_proc','rngmultitypid':'pg_type'},
    'pg_ts_config': {'cfgnamespace':'pg_namespace','cfgowner':None,'cfgparser':'pg_ts_parser'},
    'pg_ts_config_map': {'mapcfg':'pg_ts_config','mapdict':'pg_ts_dict'},
    'pg_ts_dict': {'dictnamespace':'pg_namespace','dictowner':None,'dicttemplate':'pg_ts_template'},
    'pg_ts_parser': {'prsnamespace':'pg_namespace',**{f:'pg_proc' for f in ('prsstart','prstoken','prsend','prsheadline','prslextype')}},
    'pg_ts_template': {'tmplnamespace':'pg_namespace','tmplinit':'pg_proc','tmpllexize':'pg_proc'},
    'pg_extension': {'extnamespace':'pg_namespace','extowner':None}, 'pg_namespace': {'nspowner':None},
}
VECTOR_FIELDS={'pg_proc': {'proargtypes','proallargtypes','protrftypes'}}

def _normalize_rows(selected: dict[str,list[dict]], ids: dict[str,dict[int,str]]) -> dict[str,list[dict]]:
    result={}
    for table in CATALOGS:
        normalized=[]; stable_identities=set()
        for raw in selected.get(table,[]):
            row=dict(raw)
            if table=='pg_proc':
                for source_field in ('prosrc','prosqlbody'):
                    if source_field in row:
                        row[source_field]=_source_fingerprint(row[source_field],source_field)
            for field,target in OID_FIELDS.get(table,{}).items():
                if field not in row: continue
                number=oid(row[field],zero=True)
                if not number or target is None: row[field]=number;continue
                token=ids[target].get(number)
                if token is None: raise ProfileError(f'unprofiled {target} reference {number} in {table}.{field}')
                row[field]=token if token.startswith(('$extension:','$builtin:')) else number
            for field in VECTOR_FIELDS.get(table,set()):
                if field not in row: continue
                if row[field] is None: continue
                vals=oid_list(row[field]); target=[]
                for number in vals:
                    value=ids['pg_type'].get(number)
                    if value is None: raise ProfileError(f'unprofiled pg_type vector reference {number}')
                    target.append(value if value.startswith(('$extension:','$builtin:')) else number)
                row[field]=target
            if table=='pg_ts_config_map':
                lookup=(oid(raw['mapcfg']),oid(raw['maptokentype']),oid(raw['mapseqno']))
            else:
                key='aggfnoid' if table=='pg_aggregate' else 'rngtypid' if table=='pg_range' else 'oid'
                lookup=oid(raw[key])
            ident=ids[table].get(lookup)
            if not ident: raise ProfileError(f'missing stable {table} identity')
            if ident in stable_identities: raise ProfileError('duplicate canonical identity in '+table)
            stable_identities.add(ident)
            output_ident: int | str
            if ident.startswith(('$extension:','$builtin:')) or table=='pg_extension' or table=='pg_ts_config_map':
                output_ident=ident
            elif table=='pg_range':
                output_ident=oid(raw['rngtypid'])
            else:
                key='aggfnoid' if table=='pg_aggregate' else 'oid'
                output_ident=oid(raw[key])
            if ident.startswith(('$extension:','$builtin:')) or table=='pg_extension':
                row[key]=ident
            elif table not in ('pg_range','pg_ts_config_map'):
                row[key]=oid(raw[key])
            normalized.append({'identity':output_ident,'fields':row})
        result[table]=sorted(normalized,key=lambda x:str(x['identity']))
        if len(result[table])>MAX_ROWS: raise ProfileError('profile table budget exceeded')
    return result

def _source_fingerprint(value: Any, field: str) -> Any:
    """Keep exact function-row shape without retaining executable source."""
    if value is None:
        return None
    if isinstance(value,str):
        return {'sha256_utf8':hashlib.sha256(value.encode('utf-8')).hexdigest()}
    if (isinstance(value,dict) and set(value)=={'sha256_utf8'}
            and isinstance(value['sha256_utf8'],str)
            and re.fullmatch(r'[0-9a-f]{64}',value['sha256_utf8'])):
        return {'sha256_utf8':value['sha256_utf8']}
    raise ProfileError('malformed '+field+' fingerprint')

def oid(value: Any, *, zero: bool=False) -> int:
    if isinstance(value,bool) or not (isinstance(value,int) or isinstance(value,str) and re.fullmatch(r'[0-9]+',value)):
        raise ProfileError('malformed OID')
    number=int(value)
    if number < (0 if zero else 1) or number > 0xffffffff: raise ProfileError('invalid OID')
    return number

def oid_list(value: Any) -> list[int]:
    if value is None: return []
    if isinstance(value,list): return [oid(v) for v in value]
    if not isinstance(value,str):raise ProfileError('malformed OID vector')
    if value.startswith('{') and value.endswith('}'):
        values=value[1:-1].split(',') if value[1:-1] else []
    else: values=value.split()
    return [oid(v) for v in values]

def close_dependencies(tables: dict[str, list[dict]], roots: set[tuple[str,int]]) -> dict[str,list[dict]]:
    indexes={}
    for table in EDGES:
        rows=tables.get(table)
        if not isinstance(rows,list):raise ProfileError('missing catalog '+table)
        key='aggfnoid' if table=='pg_aggregate' else 'rngtypid' if table=='pg_range' else 'oid'
        index={}
        for row in rows:
            if not isinstance(row,dict) or key not in row:raise ProfileError('malformed catalog row in '+table)
            ident=oid(row[key])
            if ident in index:raise ProfileError('duplicate catalog identity')
            index[ident]=row
        indexes[table]=index
    maps=tables.get('pg_ts_config_map',[])
    if not isinstance(maps,list):raise ProfileError('missing text search maps')
    mapkeys=set()
    for row in maps:
        try: key=(oid(row['mapcfg']),oid(row['maptokentype']),oid(row['mapseqno']))
        except (KeyError,TypeError) as e:raise ProfileError('malformed text search map') from e
        if key in mapkeys:raise ProfileError('duplicate text search map')
        mapkeys.add(key);oid(row.get('mapdict'))
    queue=deque(roots);seen=set();selected_maps=[]
    while queue:
        table,ident=queue.popleft();ident=oid(ident)
        if (table,ident) in seen:continue
        if table not in indexes or ident not in indexes[table]:raise ProfileError(f'missing {table} dependency {ident}')
        seen.add((table,ident))
        if len(seen)>MAX_ROWS:raise ProfileError('dependency budget exceeded')
        row=indexes[table][ident]
        for field,target in EDGES[table].items():
            value=oid(row.get(field,0),zero=True)
            if value:queue.append((target,value))
        if table=='pg_proc':
            for f in ('proargtypes','proallargtypes','protrftypes'):
                queue.extend(('pg_type',v) for v in oid_list(row.get(f)))
        if table=='pg_type' and ident in indexes['pg_range']:
            queue.append(('pg_range',ident))
        if table=='pg_opfamily':
            # ALL family members, including cross-type callbacks, are compared.
            for name,field in (('pg_amop','amopfamily'),('pg_amproc','amprocfamily')):
                queue.extend((name,v) for v,r in indexes[name].items() if oid(r.get(field,0),zero=True)==ident)
        if table=='pg_ts_config':
            matches=[r for r in maps if oid(r['mapcfg'])==ident]
            if not matches:raise ProfileError('text search config has no dictionary closure')
            selected_maps.extend(matches)
            queue.extend(('pg_ts_dict',oid(r['mapdict'])) for r in matches)
        if table=='pg_proc' and row.get('prokind')=='a':queue.append(('pg_aggregate',ident))
    result={t:[indexes[t][i] for i in sorted(i for name,i in seen if name==t)] for t in EDGES}
    result['pg_ts_config_map']=sorted(selected_maps,key=lambda r:(int(r['mapcfg']),int(r['maptokentype']),int(r['mapseqno'])))
    return result

def _source_indexes(reference: dict) -> tuple[dict[str,dict[int,dict]],dict[tuple[str,int],str]]:
    tables=reference.get('tables')
    if not isinstance(tables,dict) or set(tables)!=set(CATALOGS):
        raise ProfileError('reference must contain the exact supported catalog inventory')
    indexes=_oid_indexes(tables)
    raw_members=reference.get('extension_members')
    if not isinstance(raw_members,list): raise ProfileError('reference has no extension member inventory')
    members={}
    member_counts: dict[tuple[str,str],int]={}
    for item in raw_members:
        if not isinstance(item,dict): raise ProfileError('malformed extension member')
        ext=_text(item.get('extname'),'extension member name')
        table=_text(item.get('catalog'),'extension member catalog')
        if ext not in {'pg_trgm','btree_gist','plpgsql'}: raise ProfileError('unknown extension in reference')
        if table not in CATALOGS:
            if ext in EXTENSIONS: raise ProfileError('selected extension member catalog is unsupported')
            continue
        if oid(item.get('objsubid',0),zero=True)!=0:
            raise ProfileError('extension subobject membership is unsupported')
        obj=oid(item.get('objid'))
        if ext in EXTENSIONS:
            key_count=(ext,table)
            member_counts[key_count]=member_counts.get(key_count,0)+1
        key=(table,obj)
        if key in members: raise ProfileError('duplicate extension membership')
        members[key]=ext
    extensions={r.get('extname'):r for r in indexes['pg_extension'].values()}
    expected={'plpgsql':'1.0','pg_trgm':{12:'1.4',18:'1.6'},'btree_gist':{12:'1.5',18:'1.8'}}
    major=reference.get('postgres_major')
    if type(major) is not int or major not in (12,18): raise ProfileError('unsupported PostgreSQL major')
    if set(extensions)!=set(expected): raise ProfileError('reference extension inventory differs from the reviewed set')
    for name,version in expected.items():
        wanted=version if isinstance(version,str) else version[major]
        if extensions[name].get('extversion')!=wanted: raise ProfileError('unreviewed extension version')
    actual_counts={name:{table:count for (owner,table),count in member_counts.items() if owner==name}
                   for name in EXTENSIONS}
    wanted_counts=EXPECTED_EXTENSION_MEMBER_COUNTS[major]
    if actual_counts!=wanted_counts:
        raise ProfileError('extension direct member inventory differs from the reviewed major')
    return indexes,members

def _root_selection(reference: dict,indexes: dict[str,dict[int,dict]],members: dict[tuple[str,int],str],enabled_extensions: set[str]) -> tuple[set[tuple[str,int]],dict[str,list[str]]]:
    ns={oid(r['oid']):r['nspname'] for r in indexes['pg_namespace'].values()}
    pg_catalog=[i for i,name in ns.items() if name=='pg_catalog']
    if len(pg_catalog)!=1: raise ProfileError('reference must contain one pg_catalog namespace')
    pgcat=pg_catalog[0]
    roots:set[tuple[str,int]]=set()
    type_rows=indexes['pg_type']
    named={r.get('typname'):i for i,r in type_rows.items() if oid(r.get('typnamespace'))==pgcat}
    required_types=set(EXPLICIT_TYPES)
    if reference['postgres_major']>=14:
        required_types.update({'int4multirange','int8multirange','nummultirange','tsmultirange','tstzmultirange','datemultirange'})
    missing=required_types-set(named)
    if missing: raise ProfileError('missing explicit core type roots: '+','.join(sorted(missing)))
    type_ids={named[name] for name in required_types}
    roots.update(('pg_type',i) for i in type_ids)
    array_names={'_int4','_date','_numeric','_text'}
    missing_arrays=array_names-set(named)
    if missing_arrays: raise ProfileError('missing explicit core array roots: '+','.join(sorted(missing_arrays)))
    array_ids={named[name] for name in array_names}
    roots.update(('pg_type',i) for i in array_ids)
    type_ids.update(array_ids)
    for type_id in list(type_ids):
        array_id=oid(type_rows[type_id].get('typarray',0),zero=True)
        if array_id:
            type_ids.add(array_id)
            roots.add(('pg_type',array_id))
    # Include every catalog range implementation as a named, explicit built-in root.
    range_names={'int4range','int8range','numrange','tsrange','tstzrange','daterange'}
    if reference['postgres_major']>=14:
        range_names.update({'int4multirange','int8multirange','nummultirange','tsmultirange','tstzmultirange','datemultirange'})
    for i,row in indexes['pg_range'].items():
        typ=type_rows.get(oid(row.get('rngtypid')))
        if typ and oid(typ.get('typnamespace'))==pgcat and typ.get('typname') in range_names:
            roots.add(('pg_range',i));type_ids.add(oid(row['rngtypid']))
    for name in FUNCTION_ROOTS:
        candidates=[(i,r) for i,r in indexes['pg_proc'].items() if r.get('proname')==name]
        if not candidates: raise ProfileError('missing known expression function '+name)
        if any(oid(r.get('pronamespace'))!=pgcat for _,r in candidates):
            raise ProfileError('known function name exists outside pg_catalog: '+name)
        roots.update(('pg_proc',i) for i,_ in candidates)
    for name in OPERATOR_ROOTS:
        candidates=[(i,r) for i,r in indexes['pg_operator'].items() if r.get('oprname')==name]
        if not candidates: raise ProfileError('missing known expression operator '+name)
        if any(oid(r.get('oprnamespace'))!=pgcat and ('pg_operator',i) not in members for i,r in candidates):
            raise ProfileError('known operator name exists outside pg_catalog: '+name)
        roots.update(('pg_operator',i) for i,r in candidates
                     if oid(r.get('oprnamespace'))==pgcat
                     or members.get(('pg_operator',i)) in enabled_extensions)
    access={r['amname']:i for i,r in indexes['pg_am'].items()}
    if not INDEX_METHODS<=access.keys(): raise ProfileError('missing required index access method')
    roots.update(('pg_am',access[name]) for name in INDEX_METHODS)
    heap_methods=[(i,r) for i,r in indexes['pg_am'].items()
                  if r.get('amname')=='heap' and r.get('amtype')=='t']
    if len(heap_methods)!=1: raise ProfileError('missing or ambiguous table heap access method')
    heap_handler=oid(heap_methods[0][1].get('amhandler',0),zero=True)
    if not heap_handler or heap_handler not in indexes['pg_proc']:
        raise ProfileError('heap table access method handler is missing')
    roots.add(('pg_am',heap_methods[0][0]))
    # Root every opclass for supported key types and the reviewed extension opclasses.
    direct_ext={k for k,v in members.items() if v in enabled_extensions}
    type_ids.update(i for table,i in direct_ext if table=='pg_type')
    for i,row in indexes['pg_opclass'].items():
        direct_owner=members.get(('pg_opclass',i))
        if (oid(row.get('opcmethod')) in {access[n] for n in INDEX_METHODS}
                and ((oid(row.get('opcintype')) in type_ids and direct_owner is None)
                     or direct_owner in enabled_extensions)):
            roots.add(('pg_opclass',i))
    anyrange_ids={i for i,row in type_rows.items()
                  if oid(row.get('typnamespace'))==pgcat and row.get('typname')=='anyrange'}
    range_gist=[(i,row) for i,row in indexes['pg_opclass'].items()
                if oid(row.get('opcnamespace'))==pgcat
                and row.get('opcname')=='range_ops'
                and oid(row.get('opcmethod'))==access['gist']
                and oid(row.get('opcintype')) in anyrange_ids]
    if len(anyrange_ids)!=1 or len(range_gist)!=1:
        raise ProfileError('missing or ambiguous core GiST range_ops opclass')
    roots.add(('pg_opclass',range_gist[0][0]))
    for i,row in indexes['pg_cast'].items():
        if oid(row.get('castsource')) in type_ids and oid(row.get('casttarget')) in type_ids:
            roots.add(('pg_cast',i))
    for table,objid in direct_ext:
        if table in indexes:
            if objid in indexes[table]: roots.add((table,objid))
            elif table not in {'pg_amop','pg_amproc'}: raise ProfileError('extension member does not resolve to a captured row')
    # Include reviewed default collations required by parser and type metadata.
    for i,row in indexes['pg_collation'].items():
        if oid(row.get('collnamespace'))==pgcat and row.get('collname') in {'default','C','POSIX'}:
            roots.add(('pg_collation',i))
    config_names={'simple','english'}
    found=set()
    for i,row in indexes['pg_ts_config'].items():
        if oid(row.get('cfgnamespace'))==pgcat and row.get('cfgname') in config_names:
            roots.add(('pg_ts_config',i));found.add(row['cfgname'])
    if found!=config_names: raise ProfileError('missing required text-search configuration')
    return roots,{}

def _extension_metadata(reference: dict,indexes: dict[str,dict[int,dict]],members: dict[tuple[str,int],str],ids: dict[str,dict[int,str]],enabled_extensions: set[str]) -> tuple[list[dict],dict[str,str]]:
    hashes=reference.get('module_sha256')
    if not isinstance(hashes,list): raise ProfileError('missing extension module provenance')
    hash_by_name={}
    for line in hashes:
        if not isinstance(line,str): raise ProfileError('malformed module hash')
        match=re.fullmatch(r'([0-9a-f]{64})  /usr/lib/postgresql/(12|18)/lib/(pg_trgm|btree_gist)\.so',line)
        if not match: raise ProfileError('unrecognized extension module hash record')
        digest,major,name=match.groups()
        if int(major)!=reference['postgres_major'] or name in hash_by_name: raise ProfileError('duplicate or wrong-major module hash')
        hash_by_name[name]=digest
    if set(hash_by_name)!=EXTENSIONS: raise ProfileError('incomplete extension module provenance')
    rows=[]
    for extname in sorted(enabled_extensions):
        ext=next(r for r in indexes['pg_extension'].values() if r.get('extname')==extname)
        ns=next((r['nspname'] for r in indexes['pg_namespace'].values() if oid(r['oid'])==oid(ext['extnamespace'])),None)
        if ns is None: raise ProfileError('extension namespace missing')
        member_ids={ids[t][i] for (t,i),name in members.items() if name==extname and t in ids and i in ids[t]}
        derived_ids=set()
        family_ids={i for (table,i),name in members.items() if table=='pg_opfamily' and name==extname}
        for table,field in (('pg_amop','amopfamily'),('pg_amproc','amprocfamily')):
            for i,row in indexes[table].items():
                if oid(row.get(field)) in family_ids and (table,i) not in members:
                    derived_ids.add(ids[table][i])
        ext_type_ids={i for (table,i),name in members.items() if table=='pg_type' and name==extname}
        for i,row in indexes['pg_type'].items():
            if oid(row.get('typelem',0),zero=True) in ext_type_ids and ('pg_type',i) not in members:
                derived_ids.add(ids['pg_type'][i])
        member_ids=sorted(member_ids)
        derived_members=sorted(derived_ids)
        if not member_ids: raise ProfileError('reviewed extension has no captured members')
        normalized_ext=dict(ext)
        normalized_ext['oid']=ids['pg_extension'][oid(ext['oid'])]
        normalized_ext['extnamespace']=ns
        rows.append({'name':extname,'version':ext['extversion'],'namespace':ns,'members':member_ids,
                     'derived_members':derived_members,
                     'fields':normalized_ext})
    return rows,{name:hash_by_name[name] for name in sorted(enabled_extensions)}

def build_profile(reference: dict, enabled_extensions: list[str] | tuple[str, ...] | set[str] | None = None) -> dict:
    """Build a deterministic internal dependency profile from an owned capture."""
    if not isinstance(reference,dict): raise ProfileError('reference must be an object')
    if enabled_extensions is None:
        enabled=set(EXTENSIONS)
    else:
        if not isinstance(enabled_extensions,(list,tuple,set)):
            raise ProfileError('enabled extensions must be an explicit sequence')
        requested=list(enabled_extensions)
        if any(not isinstance(name,str) or name not in EXTENSIONS for name in requested):
            raise ProfileError('unsupported enabled extension')
        if len(set(requested))!=len(requested):
            raise ProfileError('duplicate enabled extension')
        enabled=set(requested)
    major=reference.get('postgres_major')
    try:
        image=pinned_image(major)
        validate_provenance(reference,major,image,'reference')
    except (ValueError,TypeError) as error:
        raise ProfileError(str(error)) from error
    indexes,members=_source_indexes(reference)
    roots,_=_root_selection(reference,indexes,members,enabled)
    raw_tables={t:list(indexes[t].values()) for t in CATALOGS if t in EDGES}
    raw_tables['pg_ts_config_map']=list(indexes['pg_ts_config_map'].values())
    # `close_dependencies` expects exact OID-indexed source rows and includes all
    # cross-type family callbacks and complete text-search dictionary maps.
    closure=close_dependencies(raw_tables,roots)
    closure.setdefault('pg_enum',[])
    ids=_build_identities(indexes,members)
    # Catalog rows anchoring namespaces and installed extensions are exact profile
    # dependencies even though these catalogs are outside the generic edge walker.
    namespace_ids={oid(r[field]) for table,fields in OID_FIELDS.items() for r in closure.get(table,[])
                   for field,target in fields.items() if target=='pg_namespace' and field in r and oid(r[field],zero=True)}
    namespace_ids.update(oid(e['extnamespace']) for e in indexes['pg_extension'].values() if e['extname'] in enabled)
    closure['pg_namespace']=[indexes['pg_namespace'][i] for i in sorted(namespace_ids)]
    closure['pg_extension']=[r for r in indexes['pg_extension'].values() if r.get('extname') in enabled]
    closure.setdefault('pg_enum',[])
    pg_catalog_oid=next(oid(r['oid']) for r in indexes['pg_namespace'].values() if r['nspname']=='pg_catalog')
    for table,namespace_field in (('pg_type','typnamespace'),('pg_proc','pronamespace'),
        ('pg_operator','oprnamespace'),('pg_opclass','opcnamespace'),('pg_opfamily','opfnamespace'),
        ('pg_collation','collnamespace'),('pg_ts_config','cfgnamespace'),('pg_ts_dict','dictnamespace'),
        ('pg_ts_parser','prsnamespace'),('pg_ts_template','tmplnamespace')):
        for row in closure.get(table,[]):
            rowid=oid(row.get('oid',row.get('rngtypid',0)))
            ext_owned=(table,rowid) in members
            if table=='pg_type' and not ext_owned:
                elem=oid(row.get('typelem',0),zero=True)
                ext_owned=('pg_type',elem) in members
            if oid(row.get(namespace_field))!=pg_catalog_oid and not ext_owned:
                raise ProfileError(f'unowned non-pg_catalog {table} dependency')
    for row in closure.get('pg_proc',[]):
        if oid(row['pronamespace'])!=pg_catalog_oid and ('pg_proc',oid(row['oid'])) not in members:
            raise ProfileError('unowned function entered internal dependency closure')
    # Stable extension tokens are mandatory for every selected extension object.
    normalized=_normalize_rows(closure,ids)
    if sum(len(rows) for rows in normalized.values())>MAX_ROWS:
        raise ProfileError('total profile row budget exceeded')
    row_counts=tuple(len(normalized[table]) for table in CATALOGS)
    if row_counts!=EXPECTED_PROFILE_ROW_COUNTS[(major,tuple(sorted(enabled)))]:
        raise ProfileError('normalized dependency closure counts differ from the reviewed major/module set')
    extension_data,hashes=_extension_metadata(reference,indexes,members,ids,enabled)
    ns={oid(r['oid']):r['nspname'] for r in indexes['pg_namespace'].values()}
    pgcat=next(i for i,name in ns.items() if name=='pg_catalog')
    names={r['typname']:i for i,r in indexes['pg_type'].items() if oid(r['typnamespace'])==pgcat}
    def output_identity(table: str, ident: int) -> int | str:
        stable=ids[table][ident]
        if stable.startswith(('$extension:','$builtin:')) or table=='pg_extension': return stable
        if table=='pg_range': return oid(indexes['pg_range'][ident]['rngtypid'])
        return ident
    root_rows=sorted(({'catalog':table,'identity':output_identity(table,i)} for table,i in roots),key=lambda r:(r['catalog'],str(r['identity'])))
    projection_names={'bool','bytea','int8','int2','int4','text','float4','float8','bpchar','varchar',
        'date','time','timestamp','timestamptz','interval','timetz','numeric','uuid','jsonb',
        '_int4','_date','_numeric','_text'}
    projection_types={names[n] for n in projection_names}
    return {
        'format':PROFILE_FORMAT,
        'enabled_extensions':sorted(enabled),
        'namespace_authority':'actor-namespace-authority/v1',
        'provenance':{'postgres_major':major,'source_image':image,'server_version':reference['server_version'],
            'server_version_num':reference['server_version_num'],'platform':reference['platform'],'capture_id':reference['capture_id']},
        'roots':root_rows,
        'extensions':extension_data,
        'module_sha256':hashes,
        'catalog':normalized,
        'client_functions':[],
        'projection_types':sorted(projection_types),
    }

def write_profile_variants(reference: dict, output_dir: Path) -> list[dict]:
    """Write all four reviewed module subsets without retaining raw capture data."""
    variants=(('core',()),('pg-trgm',('pg_trgm',)),('btree-gist',('btree_gist',)),
              ('both',('btree_gist','pg_trgm')))
    output_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    output_dir.chmod(0o700)
    results=[]
    for suffix,enabled in variants:
        profile=build_profile(reference,enabled)
        encoded=(json.dumps(profile,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
        path=output_dir/f'read-dependency-profile-pg{reference["postgres_major"]}-{suffix}.json'
        path.write_bytes(encoded)
        path.chmod(0o600)
        results.append({'path':str(path),'sha256':hashlib.sha256(encoded).hexdigest(),
                        'enabled_extensions':list(enabled),
                        'catalog_row_counts':{table:len(rows) for table,rows in profile['catalog'].items()}})
    return results
