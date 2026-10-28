#!/usr/bin/env python3
"""Bounded local private engineering worker packet assembler/verifier.

No build, installation, Nix, network, enrollment or scientific execution. Receipt
projections are assertions from original evidence, not measurements by this tool.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import sys
import time
from urllib.parse import urlsplit, unquote

import application_release
import image_stage

SCHEMA = 'qcl-negf-worker-distribution-v1'
LIMIT = 1024 * 1024
RESERVE = 64 * LIMIT
CHUNK = 65536
SHA = re.compile(r'[0-9a-f]{64}')
REV = re.compile(r'[0-9a-f]{40}')
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+')
NAR = re.compile(r'sha256-[A-Za-z0-9+/]{43}=')
HOST = {'host_adapter': 'Arch Linux x86_64; measured versions required',
        'virtualization': 'KVM', 'network': 'existing LAN bridge; no NAT',
        'libvirt_provider': 'dmacvicar/libvirt=0.9.9', 'opentofu': '>=1.10,<2.0',
        'scratch': 'separate stable-identity disk; actual capacity/reserve required'}
CONTROLLER = {'release_schema': 'qcl-negf-release-v1',
              'enrollment': 'existing protected enrollment v1; provisioned separately',
              'first_boot': 'DRAIN/no-submit before trust+release+health'}
IMAGE = {'producer_role': 'arch-worker', 'format': 'qcow2', 'boot_mode': 'legacy-bios',
         'hyperv_generation': None, 'partition_table': 'legacy',
         'root_filesystem': 'ext4', 'root_bus': 'virtio'}
KIT_PREFIX = 'recipes/platform/'
KIT_RECEIPT = KIT_PREFIX + 'source-kit.json'
KIT_REQUIRED = {'docs/linux-workers.md', 'ansible/arch-libvirt.yml', 'ansible/requirements.yml',
                'tofu/arch-libvirt/main.tf', 'tofu/arch-libvirt/variables.tf',
                'tofu/arch-libvirt/versions.tf', 'tofu/arch-libvirt/outputs.tf',
                'tofu/arch-libvirt/site-base.json.example',
                'examples/private-site/flake.nix.template',
                'ops/worker_distribution.py', 'ops/application_release.py', 'ops/image_stage.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value)
            and set(value) <= set(required) | set(optional), 'Unknown or missing object keys')


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def positive(value):
    return type(value) is int and value > 0


def check_time(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('Worker packet exceeded its finite wall-time budget')


def decode_json(data):
    require(isinstance(data, bytes) and 0 < len(data) <= LIMIT, 'Metadata exceeds 1 MiB budget')

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, 'Duplicate JSON key')
            obj[key] = value
        return obj

    def nonfinite(_):
        raise ValueError('Nonfinite JSON value')

    def finite_float(raw):
        value = float(raw)
        require(math.isfinite(value), 'Nonfinite JSON value')
        return value

    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Malformed UTF-8/JSON metadata') from error


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')


def relative(name):
    require(isinstance(name, str) and 0 < len(name) <= 240
            and re.fullmatch(r'[A-Za-z0-9._+/-]+', name) is not None
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))
            and str(PurePosixPath(name)) == name, 'Require normalized relative POSIX path')
    return name


def ref(value):
    keys(value, ('path', 'bytes', 'sha256'))
    relative(value['path'])
    require(positive(value['bytes']) and matches(SHA, value['sha256']), 'Invalid FileRef')
    return value


def refs(values):
    require(isinstance(values, list) and 0 < len(values) <= 4096, 'Require bounded nonempty FileRef list')
    result = {}
    for item in values:
        ref(item)
        require(item['path'] not in result, 'Duplicate FileRef')
        result[item['path']] = item
    return result


def root_path(root):
    root = Path(root).absolute()
    require(root.resolve(strict=True) == root and root.is_dir(), 'Root must be a real canonical directory')
    return root


def open_regular(root, name):
    """Walk every component with O_NOFOLLOW; never follow a swapped parent link."""
    relative(name)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(fd)
            raise ValueError('Payload must be regular, without symlinks/hardlinks/devices/FIFO')
        return os.fdopen(fd, 'rb')
    except OSError as error:
        raise ValueError('Unsafe or missing packet path: ' + name) from error
    finally:
        os.close(directory)


def tree_files(root):
    found = set()
    directories = 0
    for directory, children, files in os.walk(root, followlinks=False):
        directories += 1
        require(directories <= 8192, 'Too many packet directories')
        for name in children:
            path = Path(directory) / name
            require(stat.S_ISDIR(path.lstat().st_mode), 'Linked or special packet directory')
            relative(path.relative_to(root).as_posix())
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Linked or special packet file')
            found.add(relative(path.relative_to(root).as_posix()))
            require(len(found) <= 4098, 'Too many packet files')
    return found


def read_small(root, name, deadline, limit=LIMIT):
    check_time(deadline)
    with open_regular(root, name) as handle:
        require(0 < os.fstat(handle.fileno()).st_size <= limit, 'Metadata/source exceeds byte budget')
        data = handle.read(limit + 1)
    require(0 < len(data) <= limit, 'Metadata/source exceeds byte budget')
    check_time(deadline)
    return data


def file_digest(root, item, deadline, *, header=False):
    digest = hashlib.sha256()
    total = 0
    with open_regular(root, item['path']) as handle:
        before = os.fstat(handle.fileno())
        require(before.st_size == item['bytes'], 'File byte count differs')
        while block := handle.read(CHUNK):
            check_time(deadline)
            if header and total == 0:
                image_stage.validate_header(block[:8])
            total += len(block)
            require(total <= item['bytes'], 'File grew during read')
            digest.update(block)
        after = os.fstat(handle.fileno())
    require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Source changed during read')
    require(total == item['bytes'] and digest.hexdigest() == item['sha256'], 'File SHA/bytes differ')


def graph(value):
    keys(value, ('format', 'revision', 'components'))
    require(value['format'] == 'qcl-negf.git-graph.v1' and matches(REV, value['revision']), 'Invalid source graph')
    require(isinstance(value['components'], list) and 0 < len(value['components']) <= 64, 'Invalid component count')
    names = set()
    for row in value['components']:
        keys(row, ('path', 'revision', 'url'))
        require(isinstance(row['path'], str) and re.fullmatch(r'components/[A-Za-z0-9][A-Za-z0-9.-]*', row['path'])
                and row['path'] not in names and matches(REV, row['revision'])
                and isinstance(row['url'], str)
                and re.fullmatch(r'https://github.com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+(?:\.git)?', row['url']),
                'Invalid or duplicate source component')
        names.add(row['path'])
    return value


def canonical_hash(value):
    # Cross-language contract: ASCII proof fields, sorted object keys, no newline.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def depot_v2(depot, binding, source_ref, depot_ref):
    keys(depot, ('format', 'sources', 'julia', 'juliaManifest', 'url', 'hash', 'compatibility'))
    graph(depot['sources'])
    c = depot['compatibility']
    keys(c, ('schema', 'inputs', 'inputs_sha256', 'native'))
    i = c['inputs']
    keys(i, ('schema', 'system', 'julia', 'files', 'selector_policy'))
    require(i['schema'] == 'qcl-negf.julia-depot-inputs.v1' and i['system'] == 'x86_64-linux'
            and i['selector_policy'] == 'locked-external-native-default-v1', 'Unsupported depot profile')
    j = i['julia']
    keys(j, ('version', 'drv', 'output', 'profile', 'test_workers'))
    require(j['version'] == '1.13.0' and matches(STORE, j['drv']) and j['drv'].endswith('.drv')
            and matches(STORE, j['output']) and not j['output'].endswith('.drv') and j['profile'] in ('production-build', 'local-debug')
            and (j['test_workers'] is None or positive(j['test_workers']) and j['test_workers'] <= 9007199254740991)
            and (j['profile'] != 'local-debug' or j['test_workers'] == 2), 'Invalid Julia factory')
    require(isinstance(i['files'], list) and 0 < len(i['files']) <= 128, 'Invalid input file count')
    prior = ''
    for row in i['files']:
        keys(row, ('path', 'sha256'))
        relative(row['path'])
        require(row['path'] > prior and (row['sha256'] is None or matches(SHA, row['sha256'])),
                'Invalid sorted input file inventory')
        prior = row['path']
    require(any(r['path'] == 'julia/Manifest.toml' and r['sha256'] == depot['juliaManifest']
                for r in i['files']), 'Native Manifest input differs')
    require(c['schema'] == 'qcl-negf.julia-depot-compatibility.v1'
            and c['inputs_sha256'] == canonical_hash(i), 'Dependency identity differs')
    n = c['native']
    keys(n, ('schema', 'inputs_sha256', 'julia_drv', 'julia_output', 'observed_platform',
             'preferences_sha256', 'selector_closure_sha256', 'artifact_selection_sha256', 'receipt_sha256'))
    require(n['schema'] == 'qcl-negf.julia-depot-native.v1' and n['inputs_sha256'] == c['inputs_sha256']
            and n['julia_drv'] == j['drv'] and n['julia_output'] == j['output']
            and isinstance(n['observed_platform'], str)
            and re.fullmatch(r'[!-~]{1,1024}', n['observed_platform'])
            and all(matches(SHA, n[k]) for k in ('preferences_sha256', 'selector_closure_sha256',
                     'artifact_selection_sha256', 'receipt_sha256')), 'Native qualification binding differs')
    keys(binding, ('schema', 'producer_source_graph_sha256', 'selected_source_graph_record_sha256',
                   'inputs_sha256', 'consumed_metadata_sha256', 'consumed_metadata_bytes'))
    require(binding['schema'] == 'qcl-negf-worker-depot-binding-v1'
            and binding['producer_source_graph_sha256'] == canonical_hash(depot['sources'])
            and binding['selected_source_graph_record_sha256'] == source_ref['sha256']
            and binding['inputs_sha256'] == c['inputs_sha256']
            and binding['consumed_metadata_sha256'] == depot_ref['sha256']
            and type(binding['consumed_metadata_bytes']) is int
            and binding['consumed_metadata_bytes'] == depot_ref['bytes'] <= 65536,
            'Original/current/consumed depot binding differs')


def texts(value):
    require(isinstance(value, list) and 0 < len(value) <= 128
            and all(isinstance(x, str) and 0 < len(x) <= 4096
                    and not any(ord(c) < 32 for c in x) for x in value), 'Missing bounded observations')


def native_contract(value):
    keys(value, ('source_sha256', 'test_sha256', 'factory_sha256', 'profile', 'args',
                 'julia', 'blas', 'phases', 'imports'))
    for field in ('source_sha256', 'test_sha256', 'factory_sha256'):
        require(matches(SHA, value[field]), 'Native contract hash missing')
    for field in ('profile', 'julia', 'blas'):
        texts([value[field]])
    require(isinstance(value['args'], list) and len(value['args']) <= 128, 'Invalid native args')
    if value['args']:
        texts(value['args'])
    texts(value['phases'])
    texts(value['imports'])


def native_observations(value, contract):
    keys(value, ('phases', 'imports'))
    for field in ('phases', 'imports'):
        rows = value[field]
        require(isinstance(rows, list) and len(rows) == len(contract[field]),
                'Missing native phase/import evidence')
        names = []
        for row in rows:
            keys(row, ('name', 'status', 'receipt_sha256'))
            require(row['status'] == 'passed' and matches(SHA, row['receipt_sha256']),
                    'Native phase/import has no original passing receipt')
            names.append(row['name'])
        require(names == contract[field] and len(set(names)) == len(names),
                'Native observations differ from exact test/import contract')


def shape(m):
    keys(m, ('schema', 'purpose', 'profile', 'architecture', 'role', 'backend', 'release_id',
             'source_graph', 'release_manifest', 'image_manifest', 'image', 'runtime_evidence',
             'installation_kit', 'controller', 'host_requirements', 'acceptance', 'files'))
    for field, expected in {'schema': SCHEMA, 'purpose': 'private_engineering_candidate',
            'profile': 'site_bound_private', 'architecture': 'x86_64-linux',
            'role': 'worker', 'backend': 'arch-libvirt'}.items():
        require(m[field] == expected, 'Unsupported packet profile/backend/schema')
    require(matches(SHA, m['release_id']), 'Invalid release ID')
    inventory = refs(m['files'])
    require('worker-distribution.json' not in inventory and 'SHA256SUMS' not in inventory,
            'Manifest/checksum cannot be payload references')

    def bound(item):
        ref(item)
        require(inventory.get(item['path']) == item, 'FileRef is not in exact payload inventory')

    for field, name in (('source_graph', 'source-graph'), ('release_manifest', 'release'),
                        ('image_manifest', 'images')):
        bound(m[field])
        require(m[field]['path'] == 'records/' + name + '.json', 'Noncanonical record path')
    image = m['image']
    keys(image, (*IMAGE, 'file', 'derivation', 'output', 'nar_hash', 'build_evidence', 'content_evidence'))
    for field, expected in IMAGE.items():
        require(image[field] == expected, 'Wrong image boot/format/role contract')
    for field, name in (('file', 'images/worker-root.qcow2'), ('build_evidence', 'records/image-build.json'),
                        ('content_evidence', 'records/image-content.json')):
        bound(image[field])
        require(image[field]['path'] == name, 'Noncanonical image record path')
    require(matches(STORE, image['derivation']) and image['derivation'].endswith('.drv')
            and matches(STORE, image['output']) and matches(NAR, image['nar_hash']), 'Missing immutable image build identity')
    runtime = m['runtime_evidence']
    keys(runtime, ('lock_artifacts', 'depot', 'native_reuse', 'native_status'))
    locks = refs(runtime['lock_artifacts'])
    require({'records/locks/flake.lock', 'records/locks/uv.lock', 'records/locks/Manifest.toml'} <= set(locks),
            'Original Root/Julia locks required')
    for item in locks.values():
        bound(item)
        require(item['path'].startswith('records/locks/'), 'Lock outside original artifact directory')
    bound(runtime['depot'])
    require(runtime['depot']['path'] == 'records/depot.json', 'Noncanonical depot path')
    if runtime['native_reuse'] is None:
        require(runtime['native_status'] == 'not_measured', 'Missing native receipt cannot pass')
    else:
        bound(runtime['native_reuse'])
        require(runtime['native_reuse']['path'] == 'records/native-reuse.json'
                and runtime['native_status'] == 'verified_for_exact_contract', 'Invalid native receipt status')
    kit = m['installation_kit']
    keys(kit, ('platform_revision', 'files', 'guide', 'template', 'recipe'))
    require(matches(REV, kit['platform_revision']), 'Exact published toolkit commit required')
    kit_files = refs(kit['files'])
    require(all(KIT_PREFIX + name in kit_files for name in KIT_REQUIRED), 'Incomplete installation source kit')
    require(sum(item['bytes'] for item in kit_files.values()) <= RESERVE, 'Source kit exceeds 64 MiB')
    for item in kit_files.values():
        bound(item)
        require(item['path'].startswith(KIT_PREFIX) and item['path'] != KIT_RECEIPT, 'Invalid toolkit source path')
        lower = item['path'].lower()
        require(not any(word in lower for word in ('tfvars', 'tfstate', 'known_hosts', 'enrollment',
                    'id_rsa', 'id_ed25519', '.pem', '.key', '/.git/', '/inventory.ini')),
                'Private/runtime material is forbidden in source kit')
    require(kit['guide'] == KIT_PREFIX + 'docs/linux-workers.md'
            and kit['template'] == KIT_PREFIX + 'examples/private-site/flake.nix.template'
            and kit['recipe'] == KIT_PREFIX + 'tofu/arch-libvirt/main.tf', 'Wrong canonical installation entries')
    require(m['controller'] == {**CONTROLLER, 'release_id': m['release_id']}
            and m['host_requirements'] == HOST, 'Controller/host contract mismatch')
    acceptance = m['acceptance']
    keys(acceptance, ('image_first_boot', 'backend_install', 'final_source', 'final_ci', 'full_release'))
    extra_receipts = set()
    for field in ('image_first_boot', 'backend_install'):
        cell = acceptance[field]
        keys(cell, ('status', 'receipt'))
        if cell['receipt'] is None:
            require(cell['status'] == 'not_measured', 'Missing native observation cannot be measured')
        else:
            bound(cell['receipt'])
            require(cell['status'] == 'measured' and cell['receipt']['path'] == 'records/' + field + '.json',
                    'Invalid measured receipt path/status')
            extra_receipts.add(cell['receipt']['path'])
    require(all(acceptance[k] == 'not_claimed' for k in ('final_source', 'final_ci', 'full_release')),
            'Engineering packet cannot claim final acceptance')
    expected_files = {'README.md', KIT_RECEIPT, *kit_files, *locks, *extra_receipts,
                      m['source_graph']['path'], m['release_manifest']['path'], m['image_manifest']['path'],
                      image['file']['path'], image['build_evidence']['path'], image['content_evidence']['path'],
                      runtime['depot']['path']}
    if runtime['native_reuse'] is not None:
        expected_files.add(runtime['native_reuse']['path'])
    require(set(inventory) == expected_files, 'Unexpected or missing payload entry')
    return inventory


def joins(root, m, inventory, deadline):
    def record(item):
        data = read_small(root, item['path'], deadline)
        require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
                'Parsed receipt bytes differ from bound FileRef')
        return decode_json(data)

    sources = graph(record(m['source_graph']))
    release = record(m['release_manifest'])
    keys(release, ('schema', 'release_id', 'sources', 'application_path', 'solver_executable', 'closures'), ('cache_uri',))
    application_release.manifest(release)
    application_release.prefetch_controller_closures(release, validate_only=True)
    for row in release['closures']:
        keys(row, ('path', 'narHash'))
    require(release['sources'] == sources and release['release_id'] == m['release_id'], 'Release/source join differs')
    images = record(m['image_manifest'])
    keys(images, ('storage', 'control', 'compute', 'ci', 'arch-worker'))
    for row in images.values():
        keys(row, ('image_path', 'image_sha256', 'image_bytes'))
        image_stage.validate_image(row)
    selected = images['arch-worker']
    image = m['image']
    require(selected['image_bytes'] == image['file']['bytes']
            and selected['image_sha256'] == image['file']['sha256']
            and str(PurePosixPath(selected['image_path']).parent) == image['output'], 'Selected producer image differs')
    identity = {'release_id': m['release_id'], 'source_graph_sha256': m['source_graph']['sha256'],
                'release_manifest_sha256': m['release_manifest']['sha256'],
                'image_sha256': image['file']['sha256'], 'image_bytes': image['file']['bytes'],
                'derivation': image['derivation'], 'output': image['output'],
                'nar_hash': image['nar_hash'], 'closures': release['closures']}
    runtime = m['runtime_evidence']
    build = record(image['build_evidence'])
    v2 = build.get('schema') == 'qcl-negf-worker-build-projection-v2'
    keys(build, ('schema', 'original_receipt_sha256', 'identity', 'depot_sha256',
                 'lock_artifacts', 'julia_manifest_sha256', 'native_contract',
                 *(('depot_compatibility',) if v2 else ())))
    require(build['schema'] in ('qcl-negf-worker-build-projection-v1', 'qcl-negf-worker-build-projection-v2')
            and matches(SHA, build['original_receipt_sha256']) and build['identity'] == identity
            and build['depot_sha256'] == runtime['depot']['sha256']
            and refs(build['lock_artifacts']) == refs(runtime['lock_artifacts']), 'Original build/source/closure/lock join differs')
    native_contract(build['native_contract'])
    require(build['native_contract']['source_sha256'] == m['source_graph']['sha256'], 'Native contract source differs')
    depot = record(runtime['depot'])
    if v2:
        require(depot.get('format') == 'qcl-negf.julia-depot.v2', 'V2 build needs V2 depot')
        depot_v2(depot, build['depot_compatibility'], m['source_graph'], runtime['depot'])
    else:
        keys(depot, ('format', 'sources', 'julia', 'juliaManifest', 'url', 'hash'))
        require(depot['format'] == 'qcl-negf.julia-depot.v1' and depot['sources'] == sources,
                'Legacy depot needs exact current graph')
    require(depot['julia'] == '1.13.0'
            and depot['juliaManifest'] == inventory['records/locks/Manifest.toml']['sha256']
            and build['julia_manifest_sha256'] == depot['juliaManifest'] and matches(NAR, depot['hash']),
            'Original depot/Julia lock/source join differs')
    require(build['native_contract']['julia'] == depot['julia'], 'Native Julia contract differs from depot')
    require(isinstance(depot['url'], str) and len(depot['url']) <= 4096, 'Invalid depot archive route')
    url = urlsplit(depot['url'])
    require(url.scheme in ('file', 'https') and url.password is None and url.username is None
            and not any(ord(c) <= 32 for c in depot['url']), 'Unsafe depot archive route')
    content = record(image['content_evidence'])
    content_fields = ('format', 'boot_mode', 'partition_table', 'root_filesystem', 'root_bus')
    absent_fields = ('external_backing', 'external_data_file', 'secret_bytes', 'machine_id',
                     'ssh_host_keys', 'enrollment', 'runtime_ready')
    keys(content, ('schema', 'original_receipt_sha256', 'identity', *content_fields, *absent_fields,
                   'runtime_closures_present', 'observations'))
    require(content['schema'] == 'qcl-negf-worker-content-projection-v1'
            and matches(SHA, content['original_receipt_sha256']) and content['identity'] == identity,
            'Content inspection is not bound to original image/build/source')
    require(all(content[k] == IMAGE[k] for k in content_fields)
            and all(content[k] is False for k in absent_fields)
            and content['runtime_closures_present'] is True, 'Content/secret/inherited identity inspection failed')
    texts(content['observations'])
    if runtime['native_reuse'] is not None:
        native = record(runtime['native_reuse'])
        keys(native, ('schema', 'original_receipt_sha256', 'identity', 'native_contract', 'observations', 'measurements'))
        require(native['schema'] == 'qcl-negf-worker-native-projection-v1'
                and matches(SHA, native['original_receipt_sha256']) and native['identity'] == identity
                and native['native_contract'] == build['native_contract'], 'Native reuse requires identical full original contract')
        texts(native['observations'])
        native_observations(native['measurements'], build['native_contract'])
    for kind in ('image_first_boot', 'backend_install'):
        cell = m['acceptance'][kind]
        if cell['receipt'] is not None:
            receipt = record(cell['receipt'])
            keys(receipt, ('schema', 'original_receipt_sha256', 'identity', 'kind', 'target', 'observations'))
            require(receipt['schema'] == 'qcl-negf-worker-install-projection-v1'
                    and matches(SHA, receipt['original_receipt_sha256'])
                    and receipt['identity'] == identity and receipt['kind'] == kind, 'Native observation identity differs')
            texts([receipt['target']])
            texts(receipt['observations'])
    toolkit = record(inventory[KIT_RECEIPT])
    keys(toolkit, ('schema', 'platform_revision', 'files', 'original_receipt_sha256',
                   'public_tracked_only', 'secrets_absent'))
    require(toolkit['schema'] == 'qcl-negf-worker-source-kit-v1'
            and toolkit['platform_revision'] == m['installation_kit']['platform_revision']
            and matches(SHA, toolkit['original_receipt_sha256'])
            and toolkit['public_tracked_only'] is True and toolkit['secrets_absent'] is True
            and refs(toolkit['files']) == refs(m['installation_kit']['files']), 'Published toolkit export identity differs')
    # Resolve local Markdown assets before delivery, including links in linked docs.
    kit_files = refs(m['installation_kit']['files'])
    for name in kit_files:
        if not name.endswith('.md'):
            continue
        raw = read_small(root, name, deadline)
        require(len(raw) == kit_files[name]['bytes']
                and hashlib.sha256(raw).hexdigest() == kit_files[name]['sha256'], 'Guide changed during read')
        data = raw.decode('utf-8')
        for target in re.findall(r'\]\(([^\s)]+)(?:\s+[^)]*)?\)', data):
            target = target.strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith('#'):
                continue
            require(not parsed.netloc and not target.startswith('/'), 'Nonlocal guide asset')
            local = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(parsed.path)))
            require(local.startswith(KIT_PREFIX) and local in kit_files, 'Missing local guide asset: ' + local)


def checksums(inventory, manifest_sha):
    values = {name: item['sha256'] for name, item in inventory.items()}
    values['worker-distribution.json'] = manifest_sha
    return ''.join(values[name] + '  ' + name + '\n' for name in sorted(values)).encode('ascii')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    with path.open('xb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def copy_file(source, output, item, deadline, *, header=False):
    destination = output / item['path']
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256()
    total = 0
    with open_regular(source, item['path']) as src, destination.open('xb') as dst:
        before = os.fstat(src.fileno())
        require(before.st_size == item['bytes'], 'Source file byte count differs')
        while block := src.read(CHUNK):
            check_time(deadline)
            if header and total == 0:
                image_stage.validate_header(block[:8])
            total += len(block)
            require(total <= item['bytes'], 'Copy exceeds admitted file size')
            digest.update(block)
            dst.write(block)
        after = os.fstat(src.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Source changed during copy')
        require(total == item['bytes'] and digest.hexdigest() == item['sha256'], 'Copy source SHA/bytes differ')
        dst.flush()
        os.fsync(dst.fileno())
    file_digest(output, item, deadline, header=header)
    sync_directory(destination.parent)


def assemble(source, manifest, output, *, disk_budget_bytes, timeout_seconds):
    """Copy one prepared, exact input set; failure retains an unadvertised partial directory."""
    require(positive(disk_budget_bytes) and positive(timeout_seconds) and timeout_seconds <= 3600,
            'Explicit positive disk bytes and finite 1..3600 second timeout required')
    deadline = time.monotonic() + timeout_seconds
    # Roundtrip applies strict JSON/type/size limits also to in-process callers.
    manifest_bytes = encode(manifest)
    m = decode_json(manifest_bytes)
    inventory = shape(m)
    source = root_path(source)
    output = Path(output).absolute()
    root_path(output.parent)
    require(output.parent.resolve() == output.parent and not output.is_symlink(), 'Noncanonical output')
    if output.exists():
        raise FileExistsError('Output already exists; reconcile instead of overwriting')
    require(source != output and source not in output.parents and output not in source.parents,
            'Input and output must be separate directories')
    require(tree_files(source) == set(inventory), 'Input file set differs from manifest')
    for name, item in inventory.items():
        if name != m['image']['file']['path']:
            require(item['bytes'] <= LIMIT, 'Non-image file exceeds 1 MiB')
            file_digest(source, item, deadline)
        else:
            with open_regular(source, name) as handle:
                require(os.fstat(handle.fileno()).st_size == item['bytes'], 'Image bytes differ')
    joins(source, m, inventory, deadline)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    sums = checksums(inventory, manifest_sha)
    needed = sum(item['bytes'] for item in inventory.values()) + len(manifest_bytes) + len(sums) + RESERVE
    require(needed <= disk_budget_bytes and shutil.disk_usage(output.parent).free >= needed,
            'Insufficient admitted destination bytes including 64 MiB reserve')
    check_time(deadline)
    output.mkdir(mode=0o700)  # exclusive reservation; never reuse a prior attempt
    write_new(output / '.incomplete', b'Incomplete worker packet; preserve for reconciliation.\n')
    sync_directory(output)
    try:
        for name in sorted(inventory):
            copy_file(source, output, inventory[name], deadline, header=name == m['image']['file']['path'])
        # Validate copied metadata, not only the original paths.
        joins(output, m, inventory, deadline)
        write_new(output / 'SHA256SUMS', sums)
        write_new(output / '.manifest.partial', manifest_bytes)
        for directory, _, _ in os.walk(output, topdown=False):
            sync_directory(directory)
        check_time(deadline)
        (output / '.incomplete').unlink()
        sync_directory(output)
        os.replace(output / '.manifest.partial', output / 'worker-distribution.json')
        sync_directory(output)
        sync_directory(output.parent)
    except BaseException:
        # Even a publication/fsync failure cannot leave a completed artifact advertised.
        if (output / 'worker-distribution.json').exists():
            (output / 'worker-distribution.json').rename(output / '.manifest.partial')
        if not (output / '.incomplete').exists():
            write_new(output / '.incomplete', b'Failed worker packet; preserve for reconciliation.\n')
        raise
    return manifest_sha


def verify(bundle, expected_manifest_sha256, *, timeout_seconds=600):
    require(matches(SHA, expected_manifest_sha256), 'Independently supplied manifest SHA-256 required')
    require(positive(timeout_seconds) and timeout_seconds <= 3600, 'Finite verify timeout required')
    deadline = time.monotonic() + timeout_seconds
    root = root_path(bundle)
    raw = read_small(root, 'worker-distribution.json', deadline)
    require(hashlib.sha256(raw).hexdigest() == expected_manifest_sha256, 'Trusted manifest SHA differs')
    m = decode_json(raw)
    inventory = shape(m)
    require(tree_files(root) == set(inventory) | {'worker-distribution.json', 'SHA256SUMS'},
            'Bundle exact file set differs')
    for name, item in inventory.items():
        require(name == m['image']['file']['path'] or item['bytes'] <= LIMIT, 'Non-image file exceeds 1 MiB')
        file_digest(root, item, deadline, header=name == m['image']['file']['path'])
    require(read_small(root, 'SHA256SUMS', deadline, limit=2*LIMIT) ==
            checksums(inventory, expected_manifest_sha256), 'Checksum inventory bytes differ')
    joins(root, m, inventory, deadline)
    return m


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('assemble', help='Copy explicit FileRef inputs; no build/install side effects')
    create.add_argument('--manifest', required=True, help='Bounded proposed JSON with explicit artifact FileRefs')
    create.add_argument('--source', required=True, help='New prepared nonsecret input directory; exact files only')
    create.add_argument('--output', required=True, help='New exclusive private destination')
    create.add_argument('--disk-budget-bytes', required=True, type=int)
    create.add_argument('--timeout-seconds', required=True, type=int)
    check = sub.add_parser('verify', help='Read only; never executes bundled code')
    check.add_argument('bundle')
    check.add_argument('--expected-manifest-sha256', required=True)
    check.add_argument('--timeout-seconds', required=True, type=int)
    args = parser.parse_args()
    if args.action == 'assemble':
        path = Path(args.manifest).absolute()
        raw = read_small(root_path(path.parent), path.name, time.monotonic() + args.timeout_seconds)
        value = assemble(args.source, decode_json(raw), args.output,
                         disk_budget_bytes=args.disk_budget_bytes, timeout_seconds=args.timeout_seconds)
        print(json.dumps({'manifest_sha256': value, 'purpose': 'private_engineering_candidate',
                          'delivery': 'not_claimed', 'full_release': 'not_claimed'}))
    else:
        value = verify(args.bundle, args.expected_manifest_sha256, timeout_seconds=args.timeout_seconds)
        print(json.dumps({'manifest_sha256': args.expected_manifest_sha256,
                          'native_status': value['runtime_evidence']['native_status'],
                          'acceptance': value['acceptance'], 'delivery': 'not_claimed'}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TimeoutError, KeyError, TypeError) as error:
        print('Worker packet failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
