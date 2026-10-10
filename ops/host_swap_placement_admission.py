"""Pure bounded placement-record oracle; native discovery belongs to its collector."""
import hashlib
import json
import re

SCHEMA = "qcl.host-swap.placement-admission.v1"
LIFETIME = "protected-host-infrastructure"
WINDOW_SCOPE = ['file-content','cached-workers','direct-paths','hooks','vm-transitions','automation']
CONSUMER_SCOPE = ['fd','cwd','root','maps','loop-backing','mount-namespaces','direct-paths','hooks','automation']


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_decode(raw):
    def object_pairs(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('duplicate JSON key')
            out[key]=value
        return out
    def refuse(_):raise ValueError('float/nonfinite JSON')
    try:return json.loads(raw,object_pairs_hook=object_pairs,parse_float=refuse,parse_constant=refuse)
    except (UnicodeError,RecursionError,json.JSONDecodeError) as error:raise ValueError('strict JSON') from error


def text(value):
    if type(value) is not str or not value or '\x00' in value:raise ValueError('Text')
    return value


def uint(value,positive=False):
    if type(value) is not int or not 0<=value<=9223372036854775807 or (positive and value==0):raise ValueError('UInt/Positive')
    return value


def hex64(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:raise ValueError('Hex64')
    return value


def parts(value):
    text(value)
    if not value.startswith('/') or (value!='/' and any(p in ('','.','..') for p in value[1:].split('/'))):raise ValueError('canonical Path')
    return () if value=='/' else tuple(value[1:].split('/'))


def overlap(a,b):
    aa,bb=parts(a),parts(b)
    return aa[:len(bb)]==bb or bb[:len(aa)]==aa


def device(value):
    if type(value) is not list or len(value)!=2:raise ValueError('Device')
    return tuple(uint(v) for v in value)


def unit(value):
    text(value)
    if any(c in value for c in '/*?[]'):raise ValueError('UnitName')
    return value


def exact(value,keys):
    if type(value) is not dict or set(value)!=set(keys.split()):raise ValueError('exact dictionary keys')
    return value


class Gate:
    def __init__(self,limit,tick):
        self.limit=uint(limit,True);self.count=0;self.tick=tick
        if self.limit>65536:raise ValueError('entry cap')
    def array(self,values,nonempty=False):
        self.tick()
        if type(values) is not list or (nonempty and not values):raise ValueError('Array')
        keys=[]
        for value in values:
            self.tick();self.count+=1
            if self.count>self.limit:raise ValueError('variable record count')
            keys.append(canonical(value))
        if keys!=sorted(keys) or len(keys)!=len(set(keys)):raise ValueError('sorted unique Array')
        return values
    def ids(self,rows,key='id'):
        seen=set()
        for row in rows:
            self.tick();value=text(row[key])
            if value in seen:raise ValueError('duplicate ID')
            seen.add(value)
        return seen


def protected_requests(w,fragment):
    paths=[w['placement_admission']['path'],w['parent'],w['path'],w['receipts'],fragment]
    directories=[False,True,False,True,False]
    parents=['/'+ '/'.join(parts(path)[:-1]) for path in paths]
    return list(zip(paths,directories))+list(zip(parents,[True]*5))


def _validate(raw,expected,*,maximum_bytes,maximum_entries,tick):
    """Check chosen proof linkage/physical overlap; never acquire native admission."""
    uint(maximum_bytes,True)
    if maximum_bytes>1048576 or type(raw) is not bytes or len(raw)>maximum_bytes:raise ValueError('record byte cap')
    tick();record=strict_decode(raw)
    if canonical(record)!=raw:raise ValueError('noncanonical record bytes')
    exact(record,'schema accepted identity context_sha256 receipts window pve consumers wipe backing')
    if record['schema']!=SCHEMA or record['accepted'] is not True:raise ValueError('accepted schema')
    h,w=expected['h'],expected['w'];g=Gate(maximum_entries,tick);fs=device(expected['fs_pair'])
    host=text(expected['host_namespace']);fragment=expected['fragment_path'];parts(fragment)
    for value in (w['path'],w['parent'],w['receipts'],w['mount']['path']):parts(value)
    parentparts,mountparts=parts(w['parent']),parts(w['mount']['path'])
    if parentparts[:len(mountparts)]!=mountparts or len(parentparts)<=len(mountparts) or parts(w['path'])[:-1]!=parentparts:raise ValueError('strict exact parent')
    if w['lifetime']!=LIFETIME:raise ValueError('protected lifetime')
    context=hex64(expected['context_sha256'])
    if hex64(record['context_sha256'])!=context or record['receipts']!=w['receipts']:raise ValueError('context/receipts')
    wanted_identity=dict(source=h['accepted_source'],host_id=h['host_id'],boot_id=h['boot_id'],attempt_id=h['attempt_id'],operation_owner=h['admission']['operation_owner'],admission_receipt=h['admission']['receipt'],original_receipt=h['original_receipt'],expires_at_epoch=h['admission']['expires_at_epoch'],cutover_receipt=w['mount']['cutover_receipt'])
    identity=exact(record['identity'],'source host_id boot_id attempt_id operation_owner admission_receipt original_receipt expires_at_epoch cutover_receipt')
    for key,value in identity.items():
        if key=='expires_at_epoch':
            if uint(value,True)>9223372036:raise ValueError('Epoch')
        else:text(value)
    if identity!=wanted_identity or identity['attempt_id']!=expected['attempt_id'] or identity['operation_owner']!=h['attempt_id']:raise ValueError('placement identity')
    window=exact(record['window'],'held owner expires_at_epoch scope')
    if window['held'] is not True or window['owner']!=identity['operation_owner'] or type(window['expires_at_epoch']) is not int or window['expires_at_epoch']!=identity['expires_at_epoch'] or window['scope']!=WINDOW_SCOPE:raise ValueError('held exact window')
    consumers=exact(record['consumers'],'complete namespace_complete host_namespace scope mount_namespaces references aliases')
    if consumers['complete'] is not True or consumers['namespace_complete'] is not True or consumers['scope']!=CONSUMER_SCOPE or consumers['host_namespace']!=host:raise ValueError('complete namespace capture')
    views=g.array(consumers['mount_namespaces'],True);names=g.ids(views)
    for row in views:
        exact(row,'id representative_pid view_sha256 complete');uint(row['representative_pid'],True);hex64(row['view_sha256'])
        if row['complete'] is not True:raise ValueError('complete namespace view')
    if host not in names:raise ValueError('host namespace absent')
    def location(row):
        exact(row,'namespace_id path device mount_target fsroot root_relative_path exists inode')
        if text(row['namespace_id']) not in names:raise ValueError('unknown namespace')
        p,m,f,r=map(parts,(row['path'],row['mount_target'],row['fsroot'],row['root_relative_path']))
        if p[:len(m)]!=m or r!=f+p[len(m):]:raise ValueError('physical mapping algebra')
        device(row['device'])
        if type(row['exists']) is not bool:raise ValueError('exists Bool')
        if row['exists']:uint(row['inode'],True)
        elif row['inode'] is not None:raise ValueError('absent inode')
        return row
    def resource(row,allow_unit=False):
        if type(row) is not dict:raise ValueError('Resource')
        kind=row.get('kind')
        if kind=='path':exact(row,'kind location');location(row['location'])
        elif kind=='block':exact(row,'kind rdev');device(row['rdev'])
        elif kind=='unit' and allow_unit:exact(row,'kind name fragment');unit(row['name']);location(row['fragment'])
        else:raise ValueError('Resource discriminator')
        return row
    def references(rows):
        rows=g.array(rows);g.ids(rows)
        for row in rows:exact(row,'id origin resource');text(row['origin']);resource(row['resource'])
        return rows
    consumer_refs=references(consumers['references']);aliases=g.array(consumers['aliases']);g.ids(aliases)
    for row in aliases:exact(row,'id location');location(row['location'])
    if consumer_refs or aliases:raise ValueError('relevant consumer/alias')
    pve=exact(record['pve'],'complete configuration_frozen configuration_set_sha256 configurations managed_roots volume_references absolute_references backing_references')
    if pve['complete'] is not True or pve['configuration_frozen'] is not True:raise ValueError('complete frozen PVE')
    configurations=g.array(pve['configurations']);pairs=set()
    for row in configurations:
        exact(row,'kind id sha256');text(row['id']);hex64(row['sha256'])
        if row['kind'] not in ('storage','vm','ct','job','hook','automation') or (row['kind'],row['id']) in pairs:raise ValueError('configuration association')
        pairs.add((row['kind'],row['id']))
    if not any(kind=='storage' for kind,_ in pairs) or hex64(pve['configuration_set_sha256'])!=digest(configurations):raise ValueError('configuration set hash/storage')
    roots=g.array(pve['managed_roots']);pairs=set()
    for row in roots:
        exact(row,'storage_id content_type location');key=(text(row['storage_id']),text(row['content_type']))
        if key in pairs:raise ValueError('duplicate managed root')
        pairs.add(key);location(row['location'])
    pve_refs=[]
    for key in ('volume_references','absolute_references','backing_references'):pve_refs+=references(pve[key])
    wipe=exact(record['wipe'],'complete d04_accepted d04_receipt_sha256 executor_sha256 exact_set_sha256 targets excluded')
    if wipe['complete'] is not True or wipe['d04_accepted'] is not True:raise ValueError('complete D04')
    for key in ('d04_receipt_sha256','executor_sha256','exact_set_sha256'):hex64(wipe[key])
    targets=g.array(wipe['targets']);g.ids(targets)
    for row in targets:exact(row,'id resource');resource(row['resource'],True)
    if wipe['exact_set_sha256']!=digest(targets):raise ValueError('frozen wipe set hash')
    admission=exact(w['placement_admission'],'path sha256');parts(admission['path']);hex64(admission['sha256'])
    admission_path=admission['path']
    if hashlib.sha256(raw).hexdigest()!=admission['sha256']:raise ValueError('placement raw SHA')
    if overlap(admission_path,w['mount']['path']) or overlap(admission_path,w['receipts']) or overlap(admission_path,w['parent']) or admission_path==fragment:raise ValueError('placement reference location')
    wanted_excluded=dict(final_filesystem=dict(mount_path=w['mount']['path'],mount_unit=w['mount']['unit'],fs_uuid=w['mount']['fs_uuid'],rdev=list(fs),lv_uuid=w['mount']['lv_uuid'],vg_uuid=w['mount']['vg_uuid'],pool_uuid=w['mount']['pool_uuid'],lifetime=LIFETIME),parent=dict(path=w['parent'],lifetime=LIFETIME),file=dict(path=w['path'],lifetime=LIFETIME),receipts=dict(path=w['receipts'],lifetime=LIFETIME),unit=dict(name=w['unit'],fragment_path=fragment,lifetime=LIFETIME),placement_admission=dict(path=admission_path,lifetime=LIFETIME))
    if wipe['excluded']!=wanted_excluded:raise ValueError('exact wipe exclusions')
    device(wipe['excluded']['final_filesystem']['rdev'])
    backing=exact(record['backing'],'receipt receipt_sha256 protected_node_id nodes edges isolated_peers')
    br=exact(backing['receipt'],'schema accepted complete identity_sha256 window_sha256 context_sha256 graph_sha256 evidence')
    if br['schema']!='qcl.host-swap.backing-capture.v1' or br['accepted'] is not True or br['complete'] is not True:raise ValueError('complete backing receipt')
    evidence=g.array(br['evidence']);eids=g.ids(evidence);ekinds={}
    for row in evidence:
        exact(row,'id kind sha256');hex64(row['sha256'])
        if row['kind'] not in ('lvm','block-topology','native-thin-mapping','native-support'):raise ValueError('backing evidence kind')
        ekinds[row['id']]=row['kind']
    if set(ekinds.values())!={'lvm','block-topology','native-thin-mapping','native-support'}:raise ValueError('complete evidence kinds')
    graph={key:backing[key] for key in ('protected_node_id','nodes','edges','isolated_peers')}
    for key,value in [('identity_sha256',digest(identity)),('window_sha256',digest(window)),('context_sha256',context),('graph_sha256',digest(graph))]:
        if hex64(br[key])!=value:raise ValueError('backing linked hash')
    if hex64(backing['receipt_sha256'])!=digest(br):raise ValueError('backing receipt hash')
    def cite(row,required=()):
        ids=g.array(row['evidence_ids'],True)
        for value in ids:
            if text(value) not in eids:raise ValueError('unknown evidence ID')
        if not set(required)<=set(ekinds[value] for value in ids):raise ValueError('required evidence kinds')
    nodes=g.array(backing['nodes'],True);g.ids(nodes);byid={};bydev={};lvids=set()
    for node in nodes:
        exact(node,'id kind rdev device_class device_id pv_uuid lv_uuid vg_uuid pool_uuid fs_uuid thin_id evidence_ids');byid[node['id']]=node
        for key in ('device_id','pv_uuid','lv_uuid','vg_uuid','pool_uuid','fs_uuid'):
            if node[key] is not None:text(node[key])
        if node['rdev'] is not None:
            pair=device(node['rdev'])
            if pair in bydev:raise ValueError('duplicate block rdev')
            bydev[pair]=node['id']
        if node['thin_id'] is not None:uint(node['thin_id'])
        if node['kind']=='device':
            if node['rdev'] is None or node['device_class'] not in ('disk','partition') or node['device_id'] is None or any(node[k] is not None for k in ('lv_uuid','pool_uuid','thin_id')) or (node['pv_uuid'] is None)!=(node['vg_uuid'] is None):raise ValueError('device identity')
            cite(node,('block-topology','native-support')+(() if node['pv_uuid'] is None else ('lvm',)))
        elif node['kind']=='lvm-lv':
            if any(node[k] is None for k in ('rdev','lv_uuid','vg_uuid')) or any(node[k] is not None for k in ('device_class','device_id','pv_uuid')) or (node['pool_uuid'] is None)!=(node['thin_id'] is None):raise ValueError('LV identity')
            cite(node,('lvm','block-topology','native-support')+(() if node['thin_id'] is None else ('native-thin-mapping',)))
        elif node['kind']=='thin-pool':
            if any(node[k] is None for k in ('lv_uuid','vg_uuid','pool_uuid')) or node['lv_uuid']!=node['pool_uuid'] or any(node[k] is not None for k in ('device_class','device_id','pv_uuid','fs_uuid','thin_id')):raise ValueError('pool identity')
            cite(node,('lvm','block-topology','native-thin-mapping','native-support'))
        else:raise ValueError('BlockNode discriminator')
        if node['kind']!='device':
            pair=(node['vg_uuid'],node['lv_uuid'])
            if pair in lvids:raise ValueError('duplicate LV UUID')
            lvids.add(pair)
    protected=text(backing['protected_node_id'])
    if protected not in byid:raise ValueError('protected endpoint')
    n=byid[protected]
    if n['kind']!='lvm-lv' or n['thin_id'] is None or device(n['rdev'])!=fs or any(n[key]!=w['mount'][key] for key in ('lv_uuid','vg_uuid','pool_uuid','fs_uuid')):raise ValueError('exact protected LV')
    edges=g.array(backing['edges']);seen=set();incoming={key:[] for key in byid};outgoing={key:[] for key in byid}
    def nonthin(node):return node['kind']=='lvm-lv' and node['thin_id'] is None
    for edge in edges:
        exact(edge,'from to kind evidence_ids');cite(edge);a,b=map(text,(edge['from'],edge['to']))
        if a==b or a not in byid or b not in byid or (a,b,edge['kind']) in seen:raise ValueError('graph endpoint/duplicate edge')
        seen.add((a,b,edge['kind']));left,right=byid[a],byid[b];kind=edge['kind']
        if kind=='partition':valid=left['kind']==right['kind']=='device' and left['device_class']=='disk' and right['device_class']=='partition'
        elif kind=='mapping':valid=(left['kind']=='device' and left['pv_uuid'] is not None or nonthin(left)) and nonthin(right) and left['vg_uuid']==right['vg_uuid']
        elif kind in ('thin-data','thin-metadata'):valid=nonthin(left) and right['kind']=='thin-pool' and left['vg_uuid']==right['vg_uuid']
        elif kind=='thin-volume':valid=left['kind']=='thin-pool' and right['kind']=='lvm-lv' and right['thin_id'] is not None and left['vg_uuid']==right['vg_uuid'] and left['pool_uuid']==right['pool_uuid']
        else:valid=False
        if not valid:raise ValueError('directional graph layer')
        incoming[b].append(edge);outgoing[a].append(b)
    pool_parent={};thinids=set()
    for key,node in byid.items():
        tick();ins=incoming[key];kinds=[e['kind'] for e in ins]
        if node['kind']=='device':valid=not ins if node['device_class']=='disk' else kinds==['partition']
        elif nonthin(node):valid=bool(ins) and all(k=='mapping' for k in kinds)
        elif node['kind']=='thin-pool':valid=sorted(kinds)==['thin-data','thin-metadata'] and len({e['from'] for e in ins})==2
        else:
            valid=kinds==['thin-volume']
            if valid:
                pool_parent[key]=ins[0]['from'];unique=(node['pool_uuid'],node['vg_uuid'],node['thin_id'])
                if unique in thinids:raise ValueError('duplicate native thin ID')
                thinids.add(unique)
        if not valid:raise ValueError('incomplete incoming raw layer')
    degrees={key:len(ins) for key,ins in incoming.items()};queue=[key for key,n in degrees.items() if n==0];visited=0
    while queue:
        tick();key=queue.pop();visited+=1
        for child in outgoing[key]:
            tick();degrees[child]-=1
            if degrees[child]==0:queue.append(child)
    if visited!=len(byid):raise ValueError('cyclic graph')
    peers=g.array(backing['isolated_peers']);g.ids(peers,'node_id');isolated=set()
    for peer in peers:
        exact(peer,'node_id protection evidence_ids');cite(peer,('native-thin-mapping','native-support'));key=peer['node_id']
        if key==protected or key not in byid or peer['protection']!='kernel-thin-id-isolation':raise ValueError('isolated peer discriminator')
        peer_node=byid[key]
        if peer_node['kind']!='lvm-lv' or peer_node['thin_id'] is None or peer_node['lv_uuid']==n['lv_uuid'] or peer_node['thin_id']==n['thin_id'] or peer_node['vg_uuid']!=n['vg_uuid'] or peer_node['pool_uuid']!=n['pool_uuid'] or pool_parent.get(key)!=pool_parent[protected]:raise ValueError('exact isolated thin peer')
        isolated.add(key)
    def ancestors(key):
        result=set();queue=[key]
        while queue:
            tick();current=queue.pop()
            if current in result:continue
            result.add(current)
            for edge in incoming[current]:tick();queue.append(edge['from'])
        return result
    protected_targets={protected}
    observations=expected['protected_objects'];requests=protected_requests(w,fragment)
    if type(observations) is not list or len(observations)!=len(requests):raise ValueError('complete current protected object frame')
    for obj,(wanted,is_directory) in zip(observations,requests):
        tick();exact(obj,'path observed_path exists device inode')
        if obj['path']!=wanted or type(obj['exists']) is not bool:raise ValueError('protected path/absence frame')
        observed_parts,wanted_parts=parts(obj['observed_path']),parts(wanted)
        if obj['exists']:
            if observed_parts!=wanted_parts:raise ValueError('existing protected path')
        elif len(observed_parts)>=len(wanted_parts) or wanted_parts[:len(observed_parts)]!=observed_parts:raise ValueError('closest canonical ancestor frame')
        uint(obj['inode'],True);pair=device(obj['device'])
        if pair not in bydev:raise ValueError('unknown protected filesystem association')
        carrier=byid[bydev[pair]]
        if carrier['kind'] not in ('device','lvm-lv') or carrier['fs_uuid'] is None:raise ValueError('supported protected filesystem carrier')
        protected_targets.add(carrier['id'])
    protected_ancestors=set()
    for target in protected_targets:tick();protected_ancestors.update(ancestors(target))
    def block_ref(row):
        pair=device(row['rdev'])
        if pair not in bydev:raise ValueError('unresolved historical block association')
        key=bydev[pair]
        if key in protected_ancestors:raise ValueError('raw ancestor exposure')
        if ancestors(key)&protected_ancestors and key not in isolated:raise ValueError('overlapping mediation lacks isolation')
    parent_relative='/'+ '/'.join(parentparts[len(mountparts):])
    observed=expected['protected_objects']
    def path_ref(loc,wiping=False):
        if device(loc['device'])==fs and overlap(loc['root_relative_path'],parent_relative):raise ValueError('protected physical tree overlap')
        if loc['namespace_id']==host and overlap(loc['path'],w['parent']):raise ValueError('host direct-path overlap')
        for obj in observed:
            tick()
            if obj.get('exists') is True and loc['exists'] and device(loc['device'])==device(obj['device']) and loc['inode']==obj['inode']:raise ValueError('protected same inode reference')
        if wiping and any(overlap(loc['path'],p) for p in (w['parent'],w['path'],w['receipts'],fragment,admission_path)):raise ValueError('exact frozen wipe name overlap')
    for row in roots:tick();path_ref(row['location'])
    for row in pve_refs+consumer_refs:
        tick();r=row['resource'];block_ref(r) if r['kind']=='block' else path_ref(r['location'])
    for row in targets:
        tick();r=row['resource']
        if r['kind']=='block':block_ref(r)
        elif r['kind']=='path':path_ref(r['location'],True)
        else:
            if r['name']==w['unit']:raise ValueError('protected unit wipe')
            path_ref(r['fragment'],True)
    tick()
    return dict(context_sha256=context,entry_count=g.count,host_namespace=host)


def validate(raw,expected,*,maximum_bytes,maximum_entries,tick=lambda:None):
    try:return _validate(raw,expected,maximum_bytes=maximum_bytes,maximum_entries=maximum_entries,tick=tick)
    except (KeyError,TypeError,RecursionError) as error:raise ValueError('placement shape/type') from error
