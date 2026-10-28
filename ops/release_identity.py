"""Permanent enrolled-node and boot-bound observation validation."""
import re
import uuid
from types import MappingProxyType

IDENTITY_SCHEMA = "qcl-negf-node-identity-v1"
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")
TARGET = re.compile(r"(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*\Z")

def normalized_uuid(value):
    if not isinstance(value, str):
        raise ValueError("Missing UUID")
    try:
        result = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("Invalid UUID") from error
    if result.int == 0:
        raise ValueError("Nil UUID")
    return str(result)


def identity_value(value):
    if not isinstance(value, dict) or value.get("schema") != IDENTITY_SCHEMA:
        raise ValueError("Expected observed node identity")
    result = {key: value.get(key) for key in ("schema", "role", "hostname", "node_name", "machine_uuid", "machine_id", "boot_id")}
    if result["role"] not in ("controller", "worker") or not isinstance(result["hostname"], str) or not TARGET.fullmatch(result["hostname"]) or "@" in result["hostname"]:
        raise ValueError("Invalid observed role/hostname")
    if result["role"] == "controller":
        if result["node_name"] is not None:
            raise ValueError("Controller must have node_name null")
    elif not isinstance(result["node_name"], str) or not IDENTIFIER.fullmatch(result["node_name"]):
        raise ValueError("Invalid observed NodeName")
    for key in ("machine_uuid", "boot_id"):
        result[key] = normalized_uuid(result[key])
    if not isinstance(result["machine_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", result["machine_id"]) or int(result["machine_id"], 16) == 0:
        raise ValueError("Missing/invalid observed machine-id")
    return result



def bind_node_observation(binding, observation, *, prior_boot=None):
    actual = identity_value(observation)
    for key in ("role", "hostname", "node_name", "machine_uuid", "machine_id"):
        if actual[key] != binding.get(key):
            raise ValueError("Node identity " + key + " mismatch: expected " + str(binding.get(key)) + ", observed " + str(actual[key]))
    if prior_boot is not None and actual["boot_id"] != normalized_uuid(prior_boot):
        raise ValueError("Node boot_id changed")
    return MappingProxyType({**binding, "identity": MappingProxyType(actual)})
