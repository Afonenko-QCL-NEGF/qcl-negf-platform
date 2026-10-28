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
    def __init__(self, config, observe, *, clock=time.time, current_context=None, cached_cursors=None, cache_coverages=None, cache_generation=None):
        from monitoring_runtime import validate_config
        self.config = validate_config(copy.deepcopy(config))
        if config['role'] != 'controller':
            raise ValueError('controller_role_required')
        from slurm_context import empty_context
        self.current_context = copy.deepcopy(current_context) if current_context is not None else empty_context(config,now=int(clock()))
        self.cached_cursors = cached_cursors
        self.cache_coverages = cache_coverages or {}
        self.observe = observe
        self.clock = clock
        self.generation = hashlib.sha256(json.dumps([config,self.current_context['sample_generation'],cache_generation], sort_keys=True, separators=(',', ':')).encode()).hexdigest()

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
        from slurm_context import normalize_context
        context = normalize_context(self.current_context,now=now,fresh_seconds=self.config['bounds']['fresh_seconds'])
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
                validate_cluster_projection(dict(schema='qcl.cluster-projection.v2', read_at=now, status='ok',
                    registry_generation=self.generation, hosts=[row], complete=True, next_cursor=None,
                    coverage=dict(sources=[], reasons=[]),current_context=context))
                if native is not None:
                    coverage = native['coverage']
                    sources.append(copy.deepcopy(coverage))
                if resource is not None and not resource['complete'] and self.cached_cursors is not None and resource['next_cursor'] not in self.cached_cursors.get(source_id,set()):
                    row['reasons'].append(reason('resource_snapshot_partial',source_id))
                if resource is not None and not resource['complete'] and (self.cached_cursors is None or resource['next_cursor'] in self.cached_cursors.get(source_id,set())):
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
            if source_id in self.cache_coverages:
                from native_monitoring import _normalize_coverage
                cache_cov = copy.deepcopy(self.cache_coverages[source_id])
                _normalize_coverage(cache_cov,measurement_at=cache_cov['observed_at'],now=now,fresh_seconds=self.config['bounds']['fresh_seconds'])
                sources.append(cache_cov)
            rows.append(row)
            if len(json.dumps(rows).encode()) > self.config['bounds']['output_bytes']:
                raise ValueError('output_bound')
            if next_cursor is not None:
                break
        measured = sum(x['resource'] is not None or x['native'] is not None and x['native']['observed_at'] is not None for x in rows)
        if not rows:
            status = 'ok' if context['status'] == 'fresh' else ('partial' if context['status'] == 'partial' else 'unknown')
        elif not measured:
            status = 'partial' if context['status'] in ('fresh','partial') else 'unknown'
        else:
            incomplete = measured < len(rows) or any(x['reasons'] or x['native'] is None or
                x['native']['coverage']['status'] != 'fresh' or not x['native']['coverage']['complete'] for x in rows)
            incomplete = incomplete or self.config['context']['enabled'] and context['status'] != 'fresh'
            status = 'partial' if incomplete else 'ok'
        view = dict(schema='qcl.cluster-projection.v2', read_at=now, status=status,
                    registry_generation=self.generation, hosts=rows, complete=next_cursor is None and not any(any(r['code']=='resource_snapshot_partial' for r in row['reasons']) for row in rows),
                    next_cursor=next_cursor, coverage=dict(sources=sources, reasons=[]),current_context=context)
        validate_cluster_projection(view)
        if len(json.dumps(view).encode()) > self.config['bounds']['output_bytes']:
            raise ValueError('output_bound')
        return view


def read_cluster_projection(*, request_id=None, cursor=None, limit=64):
    """Production polling performs protected local cache reads only, never observer RPC."""
    from monitoring_runtime import load_config, read_cache
    from native_monitoring import coverage
    config = load_config(); cache = read_cache(config)
    hosts = {host['host_id']:host for host in cache['host_packets']} if cache else {}
    def cached(target,query):
        host = hosts.get(target['host_id'])
        if host is None:
            raise ValueError('host_not_cached')
        selected = [p['packet'] for p in host['pages'] if p['cursor'] == query['cursor']]
        if len(selected) != 1:
            raise ValueError('stale_cursor' if query['cursor'] is not None else 'host_not_cached')
        packet = copy.deepcopy(selected[0])
        if query['request_id'] is not None:
            # Exact-request archive lookup belongs to B, not to a cache-only view.
            packet['resource'] = None
        return packet
    coverages = {}
    for name,host in hosts.items():
        cov = coverage('controller-cache:'+hashlib.sha256(name.encode()).hexdigest(),host['fetched_at'],boot=cache['sampler_boot_id'],generation=hashlib.sha256(json.dumps(host,sort_keys=True).encode()).hexdigest(),status='fresh' if host['pages'] and host['fetched_at'] is not None else 'not_measured')
        cov['complete'] = bool(host['pages'])
        coverages[name] = cov
    return ClusterProjection(config,cached,current_context=cache['current_context'] if cache else None,
        cached_cursors={name:{p['cursor'] for p in host['pages']} for name,host in hosts.items()},
        cache_coverages=coverages,cache_generation=hashlib.sha256(json.dumps(cache,sort_keys=True).encode()).hexdigest()).read(request_id=request_id,cursor=cursor,limit=limit)
