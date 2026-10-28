"""Cheap current service health, separate from immutable artifact proofs."""


def check_role_services(role, run, *, before=lambda: None):
    if role not in ('controller', 'worker'):
        raise ValueError('Unknown release health role')
    units = ['slurmd.service'] if role == 'worker' else ['qcl-negf-aiida.service', 'qcl-negf-api.service']
    for unit in units:
        before()
        run(['systemctl', 'is-active', '--quiet', unit])
    return units


def activation_health(node_identity, revision):
    from release_identity import identity_value, normalized_uuid
    node = identity_value(dict(node_identity))
    return {'schema': 'qcl-negf-activation-health-v1',
            'activation_revision': normalized_uuid(revision), 'role': node['role'],
            'boot_id': node['boot_id']}


def require_activation_health(value, node_identity):
    if not isinstance(value, dict) or set(value) != {'schema', 'activation_revision', 'role', 'boot_id'}:
        raise ValueError('Missing activation health binding')
    if value != activation_health(node_identity, value['activation_revision']):
        raise ValueError('Activation health belongs to another node or boot generation')
    return value
