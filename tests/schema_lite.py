"""A small JSON Schema (2020-12) validator for the keywords Farrier's event schema uses, so tests can check
events against events/schema/renewal-event.schema.json without adding a dependency. Uses the real
``jsonschema`` package when it is installed."""
from __future__ import annotations

import re


def _type_ok(t, v) -> bool:
    return {"object": isinstance(v, dict), "array": isinstance(v, list), "string": isinstance(v, str),
            "integer": isinstance(v, int) and not isinstance(v, bool), "null": v is None,
            "boolean": isinstance(v, bool), "number": isinstance(v, (int, float)) and not isinstance(v, bool)}[t]


def errors(schema: dict, value, root: dict | None = None, path: str = "$") -> list[str]:
    root = root or schema
    out: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/"), ref
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        out += errors(node, value, root, path)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(t, value) for t in types):
            return out + [f"{path}: expected {schema['type']}"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{path}: {value!r} not in enum")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{path}: {value!r} does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10 ** 9):
            out.append(f"{path}: bad length")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", -10 ** 18) or value > schema.get("maximum", 10 ** 18):
            out.append(f"{path}: out of range")
    if isinstance(value, dict):
        for k in schema.get("required", []):
            if k not in value:
                out.append(f"{path}: missing {k}")
        for k, sub in schema.get("properties", {}).items():
            if k in value:
                out += errors(sub, value[k], root, f"{path}.{k}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(f"{path}: too few items")
        if "items" in schema:
            for i, v in enumerate(value):
                out += errors(schema["items"], v, root, f"{path}[{i}]")
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not errors(s, value, root, path))
        if n != 1:
            out.append(f"{path}: matches {n} of oneOf")
    if "if" in schema and not errors(schema["if"], value, root, path) and "then" in schema:
        out += errors(schema["then"], value, root, path)
    return out


def validate(schema: dict, value) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return errors(schema, value)
    return [e.message for e in jsonschema.Draft202012Validator(schema).iter_errors(value)]
