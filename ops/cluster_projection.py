"""Bounded read-only cluster view. Resource authority remains the public P20 API."""
import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import time

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / 'schemas'


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    schema = json.loads((SCHEMA_DIRECTORY / 'cluster-projection.schema.json').read_text())
    native = json.loads((SCHEMA_DIRECTORY / 'host-resource-native-projection.schema.json').read_text())
    registry = Registry().with_resource('https://qcl.invalid/schemas/host-resource-native-projection.schema.json', Resource.from_contents(native))
    return Draft202012Validator(schema, registry=registry)


def validate_cluster_projection(document):
    try:
        _validator().validate(document)
    except Exception as error:
        raise ValueError('invalid_cluster_projection') from error
    return document


class ClusterProjection:
    def __init__(self, config, observe, *, clock=time.time):
        from monitoring_runtime import validate_config
        self.config = validate_config(copy.deepcopy(config))
        if config['role'] != 'controller':
            raise ValueError('controller_role_required')
        self.observe = observe
        self.clock = clock
        self.generation = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def read(self, *, request_id=None, cursor=None, limit=64):
        from monitoring_runtime import validate_query, encode_token, decode_token, reason, _normalize_observer_packet
        query = validate_query(dict(schema='qcl.cluster-query.v1', request_id=request_id, cursor=None, limit=limit))
        targets = self.config['targets']
        offset = 0
        inner = None
        expected = None
        if cursor is not None:
            token = decode_token(cursor)
            if (set(token) != {'registry', 'offset', 'inner', 'sample', 'resource', 'request_id'}
                    or token['registry'] != self.generation or token['request_id'] != request_id
                    or type(token['offset']) is not int or not 0 <= token['offset'] < len(targets)):
                raise ValueError('stale_cursor')
            offset, inner, expected = token['offset'], token['inner'], token
        now = int(self.clock())
        rows, sources, next_cursor = [], [], None
        deadline = time.monotonic() + self.config['bounds']['sample_seconds']
        for index in range(offset, min(len(targets), offset + limit)):
            target = targets[index]
            source_id = target['host_id']
            row = dict(host_id=source_id, resource=None, native=None, services=[], storage=None,
                       graph_links=[{k: x[k] for k in ('label', 'href')} for x in self.config['graph_links'] if x['host_id'] == source_id], reasons=[])
            try:
                if time.monotonic() >= deadline:
                    raise ValueError('read_deadline')
                packet = self.observe(target, {**query, 'cursor': inner if index == offset else None})
                if set(packet) != {'resource', 'native', 'services', 'storage'}:
                    raise ValueError('invalid_observer_packet')
                packet = _normalize_observer_packet(packet, now=now, fresh_seconds=self.config['bounds']['fresh_seconds'])
                native, resource = packet['native'], packet['resource']
                if resource is not None and resource.get('host') is not None and resource['host']['host_id'] != source_id:
                    raise ValueError('resource_identity_mismatch')
                if native is not None and native['host_id'] != source_id:
                    raise ValueError('native_identity_mismatch')
                if expected is not None and inner is not None and index == offset:
                    if ((native or {}).get('sample_generation') != expected['sample']
                            or (resource or {}).get('state_generation') != expected['resource']):
                        raise ValueError('stale_cursor')
                row.update(packet)
                if resource is None:
                    row['reasons'].append(reason('resource_not_available', source_id))
                validate_cluster_projection(dict(schema='qcl.cluster-projection.v1', read_at=now, status='ok',
                    registry_generation=self.generation, hosts=[row], complete=True, next_cursor=None,
                    coverage=dict(sources=[], reasons=[])))
                if native is not None:
                    coverage = native['coverage']
                    sources.append(copy.deepcopy(coverage))
                if resource is not None and not resource['complete']:
                    next_cursor = encode_token(dict(registry=self.generation, offset=index, inner=resource['next_cursor'],
                        sample=(native or {}).get('sample_generation'), resource=resource['state_generation'], request_id=request_id))
                elif index + 1 < len(targets) and index + 1 >= offset + limit:
                    next_cursor = encode_token(dict(registry=self.generation, offset=index+1, inner=None,
                        sample=None, resource=None, request_id=request_id))
            except Exception as error:
                if isinstance(error, ValueError) and str(error) == 'stale_cursor':
                    raise
                row.update(resource=None, native=None, services=[], storage=None)
                row['reasons'] = [reason('observer_unavailable', source_id)]
                from native_monitoring import coverage
                sources.append(coverage(source_id, reasons=row['reasons']))
                # Failed host is still a bounded row; later hosts remain observable.
                if index + 1 < len(targets) and index + 1 >= offset + limit:
                    next_cursor = encode_token(dict(registry=self.generation, offset=index+1, inner=None,
                        sample=None, resource=None, request_id=request_id))
            rows.append(row)
            if len(json.dumps(rows).encode()) > self.config['bounds']['output_bytes']:
                raise ValueError('output_bound')
            if next_cursor is not None:
                break
        measured = sum(x['resource'] is not None or x['native'] is not None and x['native']['observed_at'] is not None for x in rows)
        view = dict(schema='qcl.cluster-projection.v1', read_at=now,
                    status='unknown' if not measured else ('partial' if measured < len(rows) or any(x['reasons'] or x['native'] is None or x['native']['coverage']['status'] != 'fresh' or not x['native']['coverage']['complete'] for x in rows) else 'ok'),
                    registry_generation=self.generation, hosts=rows, complete=next_cursor is None,
                    next_cursor=next_cursor, coverage=dict(sources=sources, reasons=[]))
        validate_cluster_projection(view)
        if len(json.dumps(view).encode()) > self.config['bounds']['output_bytes']:
            raise ValueError('output_bound')
        return view


def read_cluster_projection(*, request_id=None, cursor=None, limit=64):
    from monitoring_runtime import load_config, observe_remote
    return ClusterProjection(load_config(), observe_remote).read(request_id=request_id, cursor=cursor, limit=limit)
