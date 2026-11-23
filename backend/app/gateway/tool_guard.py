"""Tool-level guards: strict argument validation and tool-poisoning detection.

* :func:`validate_arguments` checks tool-call arguments against the tool's
  registered JSON schema *before* any authorization decision is made. Unknown
  arguments are rejected (``additionalProperties`` defaults to false), so a
  model cannot smuggle extra parameters (``tenant_id``, ``action``, ``path``...)
  past the gateway to the upstream tool.
* :func:`scan_tool_definition` looks for prompt-injection payloads hidden in a
  tool's description or parameter descriptions ("tool poisoning"). Tools that
  match are registered *quarantined*: hidden from ``tools/list`` and not
  callable until an administrator reviews them.

This is a deliberately small, dependency-free subset of JSON Schema (type,
required, properties, additionalProperties, enum, min/max, maxLength,
pattern, items) - enough for MCP tool schemas.
"""
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

MAX_ARGUMENTS_BYTES = 16 * 1024
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
RISK_LEVELS = ("low", "medium", "high", "critical")

_JSON_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}

# Prompt-injection markers seen in published MCP tool-poisoning attacks.
_POISONING_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)", re.I),
     "instruction override"),
    (re.compile(r"<\s*/?\s*(important|system|instructions?|secret)\s*>", re.I), "hidden instruction tag"),
    (re.compile(r"do\s+not\s+(tell|inform|mention|reveal|show)\b.{0,60}\b(user|human|operator)", re.I),
     "concealment from the user"),
    (re.compile(r"(read|send|upload|exfiltrate|include|attach|forward)\b.{0,80}"
                r"(\.ssh|id_rsa|\.env\b|passwords?|secrets?|credentials?|api[_\s-]?keys?|tokens?)", re.I),
     "credential exfiltration"),
    (re.compile(r"(before|instead of|after)\s+(using|calling|invoking)\s+(this|any|other)\s+tools?", re.I),
     "cross-tool hijacking"),
    (re.compile(r"system\s+prompt", re.I), "system prompt reference"),
    (re.compile(r"[​-‏‪-‮⁦-⁩﻿]"), "invisible unicode characters"),
]


def validate_arguments(schema: Dict[str, Any], arguments: Any) -> Optional[str]:
    """Returns ``None`` if ``arguments`` satisfy ``schema``, else the first violation."""
    if not isinstance(arguments, dict):
        return "arguments must be a JSON object"
    try:
        size = len(json.dumps(arguments, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return "arguments are not JSON-serialisable"
    if size > MAX_ARGUMENTS_BYTES:
        return f"arguments exceed {MAX_ARGUMENTS_BYTES} bytes"
    return _validate(schema or {"type": "object", "properties": {}}, arguments, "arguments")


def _validate(schema: Dict[str, Any], value: Any, path: str) -> Optional[str]:
    expected = schema.get("type")
    if expected:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_JSON_TYPES.get(t, lambda _v: False)(value) for t in types):
            return f"{path} must be of type {expected}"
    if "enum" in schema and value not in schema["enum"]:
        return f"{path} must be one of {schema['enum']}"
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return f"{path} is longer than {schema['maxLength']} characters"
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            return f"{path} does not match the required pattern"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return f"{path} is below the minimum {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"{path} is above the maximum {schema['maximum']}"
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for idx, item in enumerate(value):
            err = _validate(schema["items"], item, f"{path}[{idx}]")
            if err:
                return err
    if isinstance(value, dict) and (expected == "object" or "properties" in schema):
        props: Dict[str, Any] = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                return f"{path}.{name} is required"
        if not schema.get("additionalProperties", False):
            unknown = sorted(set(value) - set(props))
            if unknown:
                return f"{path} contains undeclared parameters {unknown} (argument smuggling blocked)"
        for name, sub in props.items():
            if name in value and isinstance(sub, dict):
                err = _validate(sub, value[name], f"{path}.{name}")
                if err:
                    return err
    return None


def _schema_texts(schema: Any) -> List[str]:
    texts: List[str] = []
    if isinstance(schema, dict):
        for key, val in schema.items():
            if key in ("description", "title", "default") and isinstance(val, str):
                texts.append(val)
            else:
                texts.extend(_schema_texts(val))
    elif isinstance(schema, list):
        for item in schema:
            texts.extend(_schema_texts(item))
    return texts


def scan_tool_definition(name: str, description: str, parameters_schema: Dict[str, Any]) -> List[str]:
    """Returns the list of poisoning indicators found (empty list = clean)."""
    findings: List[str] = []
    for text in [name, description or ""] + _schema_texts(parameters_schema):
        for pattern, label in _POISONING_PATTERNS:
            if pattern.search(text) and label not in findings:
                findings.append(label)
    return findings


def upstream_origin(endpoint: str) -> Optional[str]:
    """``scheme://host[:port]`` of an http(s) endpoint, else None."""
    parts = urlsplit(endpoint or "")
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def upstream_allowed(endpoint: str, allowlist: List[str]) -> bool:
    """mock:// endpoints use the in-process demo upstream; http(s) must be allowlisted."""
    if (endpoint or "").startswith("mock://"):
        return True
    origin = upstream_origin(endpoint)
    return origin is not None and origin in {o.rstrip("/").lower() for o in allowlist}
