"""Strict artifact qualification values; no activation or scientific state.

These receipts are trusted only when read through the protected namespace API.
A digest binds contents to the expected key; it is not a signature or a source
of trust. The node's protected store/receipt ownership is the authority.
"""
import hashlib
import json
import re

from release_identity import identity_value, normalized_uuid

CONTRACT_VERSION = 'qcl-negf-native-artifact-v1'
STORE = re.compile(r'/nix/store/[a-zA-Z0-9][a-zA-Z0-9+._?-]*\Z')
NAR_HASH = re.compile(r'sha256-[A-Za-z0-9+/]{43}=\Z')
PERMANENT = ('schema', 'role', 'hostname', 'node_name', 'machine_uuid', 'machine_id')


def qualification_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                      ensure_ascii=True).encode()).hexdigest()


def environment_value(value):
    fields = {'kernel_release', 'kernel_path', 'modules_path', 'restore_epoch'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Missing/unknown qualification environment')
    if (not isinstance(value['kernel_release'], str) or not value['kernel_release']
            or len(value['kernel_release']) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in value['kernel_release'])):
        raise ValueError('Invalid qualification kernel release')
    for field in ('kernel_path', 'modules_path'):
        path = value[field]
        if (not isinstance(path, str) or len(path) > 4096
                or not re.fullmatch(r'/nix/store/[a-zA-Z0-9][a-zA-Z0-9+._?-]*(?:/[a-zA-Z0-9+._?-]+)*', path)
                or any(part in ('.', '..') for part in path.split('/'))):
            raise ValueError('Missing immutable qualification kernel/modules path')
    return {**value, 'restore_epoch': normalized_uuid(value['restore_epoch'])}


def qualification_key(node_identity, artifact, environment, *, enrollment_id,
                      contract_version=CONTRACT_VERSION):
    node = identity_value(dict(node_identity))
    if (not isinstance(contract_version, str) or
            not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', contract_version)):
        raise ValueError('Invalid native qualification contract version')
    if not isinstance(artifact, dict) or set(artifact) not in (
            {'path', 'nar_hash', 'drv_path'}, {'path', 'nar_hash', 'drv_path', 'kind'}):
        raise ValueError('Unknown artifact qualification identity')
    selected = {**artifact, 'kind': artifact.get('kind', 'solver')}
    if selected['kind'] not in ('solver', 'application'):
        raise ValueError('Unknown artifact qualification kind')
    if not isinstance(selected['path'], str) or not STORE.fullmatch(selected['path']):
        raise ValueError('Invalid qualified artifact path')
    if not isinstance(selected['nar_hash'], str) or not NAR_HASH.fullmatch(selected['nar_hash']):
        raise ValueError('Missing qualified artifact narHash')
    drv = selected['drv_path']
    if drv is not None and (not isinstance(drv, str) or not STORE.fullmatch(drv) or not drv.endswith('.drv')):
        raise ValueError('Invalid qualified artifact derivation')
    return {'schema': 'qcl-negf-artifact-qualification-key-v1',
            'node_identity': {field: node[field] for field in PERMANENT},
            'enrollment_id': normalized_uuid(enrollment_id), 'artifact': selected,
            'contract_version': contract_version, 'environment': environment_value(environment)}


def _validated_key(key):
    if not isinstance(key, dict) or set(key) != {'schema', 'node_identity', 'enrollment_id',
            'artifact', 'contract_version', 'environment'} or key['schema'] != 'qcl-negf-artifact-qualification-key-v1':
        raise ValueError('Malformed artifact qualification key')
    node = key['node_identity']
    if not isinstance(node, dict) or set(node) != set(PERMANENT):
        raise ValueError('Malformed permanent qualification identity')
    normalized = qualification_key({**node, 'boot_id': '11111111-1111-1111-1111-111111111111'},
        key['artifact'], key['environment'], enrollment_id=key['enrollment_id'],
        contract_version=key['contract_version'])
    if normalized != key:
        raise ValueError('Noncanonical qualification key')
    return key


def qualification_receipt(key, evidence):
    _validated_key(key)
    expected = {'integrity': True, 'solver_self_check': key['artifact']['kind'] == 'solver'}
    if not isinstance(evidence, dict) or set(evidence) != set(expected) or any(evidence[k] is not v for k, v in expected.items()):
        raise ValueError('Artifact qualification evidence is incomplete')
    return {'schema': 'qcl-negf-artifact-qualification-v1', 'status': 'qualified',
            'key': key, 'key_sha256': qualification_digest(key), 'evidence': dict(evidence)}


def require_qualification(receipt, key):
    _validated_key(key)
    if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'status', 'key', 'key_sha256', 'evidence'}
            or receipt['schema'] != 'qcl-negf-artifact-qualification-v1'
            or receipt['status'] != 'qualified' or receipt['key'] != key
            or receipt['key_sha256'] != qualification_digest(key)):
        raise ValueError('Artifact qualification receipt missing, corrupt or for another identity')
    if qualification_receipt(key, receipt['evidence']) != receipt:
        raise ValueError('Artifact qualification evidence differs')
    return receipt
