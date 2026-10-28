"""Portable v2 literals; never evaluates Nix or opens a native backend."""
import copy
import hashlib
import json
import unittest
import test_worker_distribution as baseline

class WorkerDepotV2Tests(unittest.TestCase):
    def fixture(self):
        f = baseline.DistributionTests(); f.setUp(); self.addCleanup(f.doCleanups)
        old = copy.deepcopy(f.graph); old['revision'] = '9'*40
        inputs = {'schema':'qcl-negf.julia-depot-inputs.v1','system':'x86_64-linux',
            'julia':{'version':'1.13.0','drv':'/nix/store/'+'1'*32+'-julia.drv',
                     'output':'/nix/store/'+'2'*32+'-julia','profile':'production-build','test_workers':2},
            'files':[{'path':'julia/Manifest.toml','sha256':f.files['records/locks/Manifest.toml']['sha256']}],
            'selector_policy':'locked-external-native-default-v1'}
        digest = lambda x: hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        ih = digest(inputs)
        depot = {'format':'qcl-negf.julia-depot.v2','sources':old,'julia':'1.13.0',
                 'juliaManifest':inputs['files'][0]['sha256'],'url':'https://example.invalid/depot.tar',
                 'hash':'sha256-'+'C'*43+'=', 'compatibility':{'schema':'qcl-negf.julia-depot-compatibility.v1',
                 'inputs':inputs,'inputs_sha256':ih,'native':{'schema':'qcl-negf.julia-depot-native.v1',
                 'inputs_sha256':ih,'julia_drv':inputs['julia']['drv'],'julia_output':inputs['julia']['output'],
                 'observed_platform':'x86_64-linux-gnu','preferences_sha256':'1'*64,
                 'selector_closure_sha256':'2'*64,'artifact_selection_sha256':'3'*64,'receipt_sha256':'4'*64}}}
        raw = json.dumps(depot,separators=(',',':')).encode()
        ref = f.put('records/depot.json',raw); f.m['runtime_evidence']['depot']=ref
        build = json.loads((f.source/'records/image-build.json').read_bytes())
        build['schema']='qcl-negf-worker-build-projection-v2';build['depot_sha256']=ref['sha256']
        build['depot_compatibility']={'schema':'qcl-negf-worker-depot-binding-v1',
            'producer_source_graph_sha256':digest(old),
            'selected_source_graph_record_sha256':f.m['source_graph']['sha256'],
            'inputs_sha256':ih,'consumed_metadata_sha256':ref['sha256'],'consumed_metadata_bytes':ref['bytes']}
        f.m['image']['build_evidence']=f.put('records/image-build.json',build);f.refresh()
        return f,build,depot

    def test_v2_original_producer_graph_is_preserved(self):
        f,_,_=self.fixture();f.assemble()
        self.assertEqual(json.loads((f.out/'records/depot.json').read_bytes())['sources']['revision'],'9'*40)

    def test_every_native_and_consumed_join_fails_closed(self):
        for key in ('inputs_sha256','consumed_metadata_sha256','selected_source_graph_record_sha256',
                    'producer_source_graph_sha256','consumed_metadata_bytes'):
            with self.subTest(key=key):
                f,b,_=self.fixture();b['depot_compatibility'][key]=1 if key.endswith('bytes') else 'f'*64
                f.m['image']['build_evidence']=f.put('records/image-build.json',b);f.refresh()
                with self.assertRaises(ValueError):f.assemble()

    def test_cross_pair_and_extra_native_key_rejected(self):
        for how in ('old-build','extra-native','wrong-factory'):
            with self.subTest(how=how):
                f,b,d=self.fixture()
                if how=='old-build':b['schema']='qcl-negf-worker-build-projection-v1'
                else:
                    if how=='extra-native':d['compatibility']['native']['extra']=True
                    else:d['compatibility']['native']['julia_drv']='/nix/store/'+'3'*32+'-other.drv'
                    raw=json.dumps(d,separators=(',',':')).encode();ref=f.put('records/depot.json',raw)
                    f.m['runtime_evidence']['depot']=ref;b['depot_sha256']=ref['sha256']
                    b['depot_compatibility']['consumed_metadata_sha256']=ref['sha256'];b['depot_compatibility']['consumed_metadata_bytes']=ref['bytes']
                f.m['image']['build_evidence']=f.put('records/image-build.json',b);f.refresh()
                with self.assertRaises(ValueError):f.assemble()
