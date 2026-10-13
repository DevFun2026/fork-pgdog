import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import read_policy_profiles as profile

REFERENCE_DIR=ROOT/'.agent/.runs/fullread'

class FullProfileTests(unittest.TestCase):
    def test_namespace_authority_policy_is_explicit_in_reviewed_artifact(self):
        result=profile.build_profile(self.reference(12))
        self.assertEqual(result.get('namespace_authority'), 'actor-namespace-authority/v1')
        # The original ACL is still retained; this policy is no ACL allowlist.
        source=self.reference(12)
        expected={int(r['oid']):r['nspacl'] for r in source['tables']['pg_namespace']}
        for row in result['catalog']['pg_namespace']:
            self.assertEqual(row['fields']['nspacl'],expected[row['identity']])
    @unittest.skipUnless(REFERENCE_DIR.exists(), 'requires owner-controlled offline reference captures')
    def reference(self,major):
        return json.loads((REFERENCE_DIR/f'reference-extended-pg{major}.json').read_text())

    def test_builds_deterministic_profiles_bound_to_the_owned_major_and_image(self):
        for major in (12,18):
            source=self.reference(major)
            result=profile.build_profile(source)
            self.assertEqual(result['provenance']['postgres_major'],major)
            self.assertEqual(result['provenance']['source_image'],profile.pinned_image(major))
            self.assertEqual(set(result['catalog']),set(profile.CATALOGS))
            self.assertEqual(result['catalog']['pg_enum'],[])
            self.assertEqual(result['client_functions'],[])
            self.assertEqual(set(result['projection_types']),{16,17,20,21,23,25,700,701,1042,1043,1082,1083,1114,1184,1186,1266,1700,2950,3802,1009,1231,1182,1007})
            self.assertEqual(set(result['module_sha256']),{'pg_trgm','btree_gist'})
            self.assertEqual(set(result['provenance']),{'postgres_major','source_image','server_version','server_version_num','platform','capture_id'})
            self.assertTrue(all(type(row['identity']) is int for table,rows in result['catalog'].items() if table not in {'pg_extension','pg_ts_config_map'} for row in rows if not isinstance(row['identity'],str)))
            self.assertTrue(all('fields' in extension and 'extowner' in extension['fields'] and 'derived_members' in extension for extension in result['extensions']))
            self.assertTrue(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:pg_trgm:') for row in result['catalog']['pg_proc']))
            self.assertTrue(any(row['fields']['provariadic'] == 0 for row in result['catalog']['pg_proc'] if type(row['identity']) is int))
            self.assertEqual(result,json.loads(json.dumps(result,sort_keys=True)))
            self.assertEqual(result,profile.build_profile(source))

    def test_dependency_module_profiles_are_deterministic_strict_subsets(self):
        source=self.reference(18)
        core=profile.build_profile(source, enabled_extensions=[])
        trgm=profile.build_profile(source, enabled_extensions=['pg_trgm'])
        gist=profile.build_profile(source, enabled_extensions=['btree_gist'])
        both=profile.build_profile(source, enabled_extensions=['btree_gist','pg_trgm'])

        for result, enabled in ((core,[]),(trgm,['pg_trgm']),(gist,['btree_gist']),
                                (both,['btree_gist','pg_trgm'])):
            self.assertEqual(result['format'],'pgdog-read-dependency-profile/v2')
            self.assertEqual(result['enabled_extensions'],enabled)
            self.assertEqual([row['name'] for row in result['extensions']],enabled)
            self.assertEqual(sorted(result['module_sha256']),enabled)
            self.assertEqual(result,profile.build_profile(source,enabled_extensions=enabled))
            self.assertEqual(result,json.loads(json.dumps(result,sort_keys=True)))

        self.assertEqual(core['extensions'],[])
        self.assertEqual(core['module_sha256'],{})
        self.assertEqual(core['catalog']['pg_enum'],[])
        self.assertTrue(any(root['catalog']=='pg_type' and root['identity']==3802
                            for root in core['roots']), 'core JSONB remains available')
        self.assertTrue(any(root['catalog']=='pg_type' and root['identity']==1009
                            for root in core['roots']), 'core arrays remain available')
        self.assertFalse(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:')
                             for rows in core['catalog'].values() for row in rows))
        self.assertTrue(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:pg_trgm:')
                            for rows in trgm['catalog'].values() for row in rows))
        self.assertFalse(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:btree_gist:')
                             for rows in trgm['catalog'].values() for row in rows))
        self.assertTrue(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:btree_gist:')
                            for rows in gist['catalog'].values() for row in rows))
        self.assertFalse(any(isinstance(row['identity'],str) and row['identity'].startswith('$extension:pg_trgm:')
                             for rows in gist['catalog'].values() for row in rows))

    def test_core_gist_range_ops_has_complete_range_family_closure(self):
        for major in (12,18):
            source=self.reference(major)
            result=profile.build_profile(source,enabled_extensions=[])
            raw=source['tables']
            anyrange=next(row for row in raw['pg_type']
                          if row['typname']=='anyrange' and row['typnamespace']=='11')
            gist=next(row for row in raw['pg_am'] if row['amname']=='gist')
            opclasses=[row for row in raw['pg_opclass']
                       if row['opcnamespace']=='11' and row['opcname']=='range_ops'
                       and row['opcmethod']==gist['oid'] and row['opcintype']==anyrange['oid']]
            self.assertEqual(len(opclasses),1)
            opclass=opclasses[0]
            family=next(row for row in raw['pg_opfamily'] if row['oid']==opclass['opcfamily'])
            self.assertEqual(family['opfname'],'range_ops')
            profile_opclass=next(row for row in result['catalog']['pg_opclass']
                                 if row['identity']==int(opclass['oid']))
            profile_family=next(row for row in result['catalog']['pg_opfamily']
                                if row['identity']==int(family['oid']))
            self.assertEqual(profile_opclass['fields']['oid'],int(opclass['oid']))
            self.assertEqual(profile_family['fields']['oid'],int(family['oid']))
            indexes,members=profile._source_indexes(source)
            identities=profile._build_identities(indexes,members)
            for table,family_field in (('pg_amop','amopfamily'),('pg_amproc','amprocfamily')):
                raw_family=[row for row in raw[table] if row[family_field]==family['oid']]
                expected={row['identity']:row['fields'] for row in profile._normalize_rows(
                    {table:raw_family},identities)[table]}
                actual={row['identity']:row['fields'] for row in result['catalog'][table]
                        if row['fields'][family_field]==int(family['oid'])}
                self.assertEqual(actual,{oid:row for oid,row in expected.items()},
                                 f'PG{major} full {table} closure for range_ops')
            self.assertIn(3888,{int(row['fields']['amopopr']) for row in result['catalog']['pg_amop']
                               if row['fields']['amopfamily']==int(family['oid'])})

    def test_extension_subset_selection_rejects_ambiguous_or_unreviewed_inputs(self):
        source=self.reference(12)
        for selection in (['pg_trgm','pg_trgm'], ['unexpected'], ['plpgsql'], 'pg_trgm', None):
            if selection is None:
                continue  # None is the backwards-compatible default selecting both.
            with self.assertRaises(profile.ProfileError):
                profile.build_profile(source, enabled_extensions=selection)

    def test_extension_inventory_and_selected_family_callbacks_are_pinned(self):
        source=self.reference(18)
        missing=copy.deepcopy(source)
        missing['extension_members'].remove(next(
            item for item in missing['extension_members']
            if item['extname']=='pg_trgm' and item['catalog']=='pg_proc'))
        with self.assertRaises(profile.ProfileError):
            profile.build_profile(missing,enabled_extensions=['pg_trgm'])

        unexpected=copy.deepcopy(source)
        unexpected['extension_members'].append({
            'catalog':'pg_proc','extname':'pg_trgm',
            'objid':next(row['oid'] for row in source['tables']['pg_proc']
                         if row['proname']=='lower' and row['pronamespace']=='11'),
            'objsubid':0,
        })
        with self.assertRaises(profile.ProfileError):
            profile.build_profile(unexpected,enabled_extensions=['pg_trgm'])

        callback=copy.deepcopy(source)
        family_oid=next(item['objid'] for item in source['extension_members']
                        if item['extname']=='pg_trgm' and item['catalog']=='pg_opfamily')
        family_row=next(row for row in callback['tables']['pg_amop']
                        if row['amopfamily']==family_oid)
        extra=dict(family_row)
        extra['oid']=str(max(int(row['oid']) for row in callback['tables']['pg_amop'])+1)
        extra['amopstrategy']=str(int(extra['amopstrategy'])+100)
        callback['tables']['pg_amop'].append(extra)
        with self.assertRaises(profile.ProfileError):
            profile.build_profile(callback,enabled_extensions=['pg_trgm'])

    def test_variant_artifact_writer_is_deterministic_and_contains_only_redacted_functions(self):
        source=self.reference(12)
        with tempfile.TemporaryDirectory() as raw:
            out=Path(raw)/'profiles'
            first=profile.write_profile_variants(source,out)
            saved={Path(item['path']).name:Path(item['path']).read_bytes() for item in first}
            second=profile.write_profile_variants(source,out)
            self.assertEqual(first,second)
            self.assertEqual(saved,{Path(item['path']).name:Path(item['path']).read_bytes() for item in second})
            for item in second:
                artifact=json.loads(Path(item['path']).read_text())
                self.assertEqual(artifact['format'],'pgdog-read-dependency-profile/v2')
                for row in artifact['catalog']['pg_proc']:
                    for field in ('prosrc','prosqlbody'):
                        if field in row['fields'] and row['fields'][field] is not None:
                            self.assertEqual(set(row['fields'][field]),{'sha256_utf8'})
                            self.assertRegex(row['fields'][field]['sha256_utf8'],r'^[0-9a-f]{64}$')

    def test_missing_roots_unknown_extension_and_unsafe_known_name_deny(self):
        source=self.reference(18)
        missing=copy.deepcopy(source)
        missing['tables']['pg_type']=[r for r in missing['tables']['pg_type'] if r['typname']!='jsonb']
        with self.assertRaises(profile.ProfileError):profile.build_profile(missing)

        unknown=copy.deepcopy(source)
        unknown['tables']['pg_extension'].append(dict(unknown['tables']['pg_extension'][0],extname='unexpected'))
        with self.assertRaises(profile.ProfileError):profile.build_profile(unknown)

        unsafe=copy.deepcopy(source)
        lower=next(r for r in unsafe['tables']['pg_proc'] if r['proname']=='lower')
        lower['pronamespace']=next(r['oid'] for r in unsafe['tables']['pg_namespace'] if r['nspname']=='public')
        with self.assertRaises(profile.ProfileError):profile.build_profile(unsafe)

    def test_duplicate_canonical_function_identity_denies(self):
        source=self.reference(18)
        overloads=[row for row in source['tables']['pg_proc'] if row['proname']=='lower' and row['pronamespace']=='11']
        self.assertGreaterEqual(len(overloads),2)
        first,second=overloads[:2]
        for key in ('proargtypes','prorettype','prokind'):
            second[key]=first[key]
        with self.assertRaises(profile.ProfileError):profile.build_profile(source)

    def test_function_source_is_represented_only_by_utf8_sha256_markers(self):
        source=self.reference(18)
        result=profile.build_profile(source)
        raw=next(row for row in source['tables']['pg_proc'] if row['prosrc'] is not None)
        actual=next(row for row in result['catalog']['pg_proc'] if row['identity']==int(raw['oid']))
        self.assertEqual(actual['fields']['prosrc'],{'sha256_utf8':hashlib.sha256(raw['prosrc'].encode('utf-8')).hexdigest()})
        self.assertNotEqual(actual['fields']['prosrc'],raw['prosrc'])
        if raw['prosqlbody'] is not None:
            self.assertEqual(actual['fields']['prosqlbody'],{'sha256_utf8':hashlib.sha256(raw['prosqlbody'].encode('utf-8')).hexdigest()})

        changed=copy.deepcopy(source)
        changed_row=next(row for row in changed['tables']['pg_proc'] if row['oid']==raw['oid'])
        changed_row['prosrc'] += '_different'
        changed_profile=profile.build_profile(changed)
        changed_actual=next(row for row in changed_profile['catalog']['pg_proc'] if row['identity']==int(raw['oid']))
        self.assertNotEqual(actual['fields']['prosrc'],changed_actual['fields']['prosrc'])

    def test_initdb_assigned_text_search_rows_use_exact_builtin_tokens(self):
        source=self.reference(18)
        result=profile.build_profile(source)
        expected={
            '$builtin:pg_ts_config:pg_catalog.english',
            '$builtin:pg_ts_config:pg_catalog.simple',
            '$builtin:pg_ts_dict:pg_catalog.english_stem',
            '$builtin:pg_ts_dict:pg_catalog.simple',
            '$builtin:pg_ts_template:pg_catalog.simple',
            '$builtin:pg_ts_template:pg_catalog.snowball',
            '$builtin:pg_proc:pg_catalog.dsnowball_init(pg_catalog.internal)->pg_catalog.internal/f',
            '$builtin:pg_proc:pg_catalog.dsnowball_lexize(pg_catalog.internal,pg_catalog.internal,pg_catalog.internal,pg_catalog.internal)->pg_catalog.internal/f',
        }
        actual={row['identity'] for rows in result['catalog'].values() for row in rows
                if isinstance(row['identity'],str) and row['identity'].startswith('$builtin:')}
        self.assertEqual(actual,expected)
        by_token={row['identity']:row['fields'] for rows in result['catalog'].values() for row in rows
                  if isinstance(row['identity'],str) and row['identity'].startswith('$builtin:')}
        for identity,fields in by_token.items():
            self.assertEqual(fields['oid'],identity)
        snowball='$builtin:pg_ts_template:pg_catalog.snowball'
        english_stem='$builtin:pg_ts_dict:pg_catalog.english_stem'
        self.assertEqual(by_token[english_stem]['dicttemplate'],snowball)

    def test_heap_table_access_method_is_an_internal_root_with_its_handler(self):
        source=self.reference(18)
        result=profile.build_profile(source)
        heap=next((row for row in result['catalog']['pg_am'] if row['fields']['amname']=='heap'),None)
        self.assertIsNotNone(heap,'heap table AM and its handler must be in the profile closure')
        self.assertIn({'catalog':'pg_am','identity':heap['identity']},result['roots'])
        handler=heap['fields']['amhandler']
        self.assertTrue(any(row['identity']==handler for row in result['catalog']['pg_proc']))

        broken=copy.deepcopy(source)
        heap_row=next(row for row in broken['tables']['pg_am'] if row.get('amname')=='heap')
        handler_oid=str(heap_row['amhandler'])
        heap_row['amhandler']='0'
        broken['tables']['pg_proc']=[row for row in broken['tables']['pg_proc'] if row['oid']!=handler_oid]
        with self.assertRaises(profile.ProfileError):profile.build_profile(broken)

class ClosureTests(unittest.TestCase):
    def catalog(self):
        return {
            'pg_type':[{'oid':23,'typelem':0,'typinput':42,'typoutput':43,'typreceive':0,'typsend':0}],
            'pg_proc':[{'oid':42,'prorettype':23,'proargtypes':'','prosupport':44},
                       {'oid':43,'prorettype':23,'proargtypes':'23','prosupport':0},
                       {'oid':44,'prorettype':23,'proargtypes':'','prosupport':0}],
            'pg_operator':[{'oid':50,'oprleft':23,'oprright':23,'oprresult':23,'oprcode':42,'oprrest':43,'oprjoin':44,'oprcom':50,'oprnegate':0}],
            'pg_am':[], 'pg_opclass':[], 'pg_opfamily':[], 'pg_amop':[], 'pg_amproc':[],
            'pg_cast':[], 'pg_range':[], 'pg_aggregate':[], 'pg_collation':[],
            'pg_ts_config':[], 'pg_ts_config_map':[], 'pg_ts_dict':[], 'pg_ts_template':[], 'pg_ts_parser':[],
        }
    def test_includes_direct_operator_and_planner_support_edges_without_pg_depend(self):
        rows=profile.close_dependencies(self.catalog(),{('pg_operator',50)})
        self.assertEqual({r['oid'] for r in rows['pg_proc']},{42,43,44})
        self.assertEqual({r['oid'] for r in rows['pg_type']},{23})
    def test_missing_callback_is_not_an_empty_safe_closure(self):
        c=self.catalog();c['pg_proc']=[r for r in c['pg_proc'] if r['oid']!=44]
        with self.assertRaises(profile.ProfileError):profile.close_dependencies(c,{('pg_operator',50)})
    def test_includes_extra_cross_type_family_members_for_exact_runtime_comparison(self):
        c=self.catalog();c['pg_am']=[{'oid':403,'amhandler':42}]
        c['pg_opclass']=[{'oid':60,'opcmethod':403,'opcfamily':61,'opcintype':23,'opckeytype':0}]
        c['pg_opfamily']=[{'oid':61,'opfmethod':403}]
        c['pg_amop']=[{'oid':62,'amopfamily':61,'amoplefttype':23,'amoprighttype':23,'amopopr':50,'amopmethod':403,'amopsortfamily':0}]
        c['pg_amproc']=[{'oid':63,'amprocfamily':61,'amproclefttype':23,'amprocrighttype':23,'amproc':44}]
        rows=profile.close_dependencies(c,{('pg_opclass',60)})
        self.assertEqual([r['oid'] for r in rows['pg_amop']],[62])
        self.assertEqual([r['oid'] for r in rows['pg_amproc']],[63])
    def test_duplicate_and_invalid_identities_deny(self):
        for broken in (0,True,2**32,'bad'):
            c=self.catalog();c['pg_type'][0]['oid']=broken
            with self.assertRaises(profile.ProfileError):profile.close_dependencies(c,{('pg_operator',50)})
        c=self.catalog();c['pg_proc'].append(dict(c['pg_proc'][0]))
        with self.assertRaises(profile.ProfileError):profile.close_dependencies(c,{('pg_operator',50)})

    def test_variadic_types_are_dependencies_not_unchecked_signature_fields(self):
        c=self.catalog();c['pg_proc'][0]['provariadic']=999
        with self.assertRaises(profile.ProfileError):profile.close_dependencies(c,{('pg_operator',50)})

    def test_required_builtin_array_metadata_is_closed(self):
        c=self.catalog();c['pg_type'][0]['typarray']=999
        with self.assertRaises(profile.ProfileError):profile.close_dependencies(c,{('pg_operator',50)})

if __name__=='__main__':unittest.main()
