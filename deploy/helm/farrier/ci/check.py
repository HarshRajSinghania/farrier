#!/usr/bin/env python3
"""Static checks for the Farrier Helm chart that need no Helm binary.

  python deploy/helm/farrier/ci/check.py

1. Every non-template YAML file (Chart.yaml, values.yaml, ci/values-*.yaml, examples/values-*.yaml)
   parses.
2. values.schema.json is valid JSON and a valid draft-07 schema (jsonschema when installed).
3. values.yaml and values.yaml merged with each ci/ and examples/ values file validate against the schema
   (jsonschema when installed, else a built-in validator for the keywords the schema uses).
4. A few must-fail inputs are rejected by the schema.
5. Every template has balanced {{ }} delimiters and balanced block actions
   (if/range/with/define ... end).

`helm lint` and `helm template` remain the authoritative render checks.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent.parent
failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"FAIL {msg}")


def ok(msg: str) -> None:
    print(f"ok   {msg}")


def deep_merge(base: dict, override: dict) -> dict:
    """Helm-style merge: maps merge recursively, everything else is replaced."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# ------------------------------------------------------------------ minimal draft-07 validator
class MiniValidator:
    """Enough of draft-07 for this chart's schema, used when jsonschema is not installed."""

    TYPES = {
        "object": dict, "array": list, "string": str, "boolean": bool, "null": type(None),
    }

    def __init__(self, schema: dict):
        self.root = schema

    def resolve(self, ref: str) -> dict:
        node = self.root
        for part in ref.lstrip("#/").split("/"):
            node = node[part]
        return node

    def type_ok(self, value, t: str) -> bool:
        if t == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if t == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, self.TYPES[t])

    def errors(self, value, schema: dict, path: str = "$"):
        if "$ref" in schema:
            yield from self.errors(value, self.resolve(schema["$ref"]), path)
            return
        t = schema.get("type")
        if t is not None:
            types = t if isinstance(t, list) else [t]
            if not any(self.type_ok(value, x) for x in types):
                yield f"{path}: {value!r} is not of type {t}"
                return
        if "enum" in schema and value not in schema["enum"]:
            yield f"{path}: {value!r} not in {schema['enum']}"
        if "const" in schema and value != schema["const"]:
            yield f"{path}: {value!r} != {schema['const']!r}"
        if isinstance(value, str):
            if "pattern" in schema and not re.search(schema["pattern"], value):
                yield f"{path}: {value!r} does not match {schema['pattern']}"
            if len(value) < schema.get("minLength", 0):
                yield f"{path}: shorter than {schema['minLength']}"
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                yield f"{path}: longer than {schema['maxLength']}"
        if self.type_ok(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                yield f"{path}: {value} < {schema['minimum']}"
            if "maximum" in schema and value > schema["maximum"]:
                yield f"{path}: {value} > {schema['maximum']}"
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                yield f"{path}: fewer than {schema['minItems']} items"
            if "items" in schema:
                for i, item in enumerate(value):
                    yield from self.errors(item, schema["items"], f"{path}[{i}]")
        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    yield f"{path}: missing required {key!r}"
            props = schema.get("properties", {})
            for key, item in value.items():
                if key in props:
                    yield from self.errors(item, props[key], f"{path}.{key}")
                elif schema.get("additionalProperties") is False:
                    yield f"{path}: unexpected key {key!r}"
                elif isinstance(schema.get("additionalProperties"), dict):
                    yield from self.errors(item, schema["additionalProperties"], f"{path}.{key}")
                if "propertyNames" in schema:
                    yield from self.errors(key, schema["propertyNames"], f"{path}.<{key}>")
        for sub in schema.get("allOf", []):
            yield from self.errors(value, sub, path)
        if "oneOf" in schema:
            matches = sum(1 for sub in schema["oneOf"] if not list(self.errors(value, sub, path)))
            if matches != 1:
                yield f"{path}: {value!r} matches {matches} of oneOf (needs exactly 1)"
        if "if" in schema and not list(self.errors(value, schema["if"], path)):
            if "then" in schema:
                yield from self.errors(value, schema["then"], path)


def make_validator(schema: dict):
    try:
        import jsonschema  # type: ignore
    except ImportError:
        print("note jsonschema not installed: using the built-in draft-07 subset validator")
        mini = MiniValidator(schema)
        return lambda data: list(mini.errors(data, schema))
    jsonschema.Draft7Validator.check_schema(schema)
    ok("values.schema.json is a valid draft-07 schema (jsonschema)")
    v = jsonschema.Draft7Validator(schema)
    return lambda data: [f"{'/'.join(map(str, e.path)) or '$'}: {e.message}" for e in v.iter_errors(data)]


# ------------------------------------------------------------------ checks
def check_yaml_files() -> dict:
    docs = {}
    values_files = [*sorted((CHART / "ci").glob("values-*.yaml")), *sorted((CHART / "examples").glob("values-*.yaml"))]
    for path in [CHART / "Chart.yaml", CHART / "values.yaml", *values_files]:
        try:
            docs[path.relative_to(CHART).as_posix()] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            ok(f"{path.relative_to(CHART)} parses")
        except yaml.YAMLError as exc:
            fail(f"{path.relative_to(CHART)}: {exc}")
    chart = docs.get("Chart.yaml", {})
    for key, want in {"apiVersion": "v2", "version": "0.2.0", "appVersion": "0.2.0"}.items():
        if str(chart.get(key)) != want:
            fail(f"Chart.yaml {key}={chart.get(key)!r}, want {want!r}")
    return docs


def check_schema(docs: dict) -> None:
    try:
        schema = json.loads((CHART / "values.schema.json").read_text(encoding="utf-8"))
        ok("values.schema.json is valid JSON")
    except json.JSONDecodeError as exc:
        fail(f"values.schema.json: {exc}")
        return
    refs = re.findall(r'"\$ref":\s*"([^"]+)"', json.dumps(schema))
    mini = MiniValidator(schema)
    for ref in set(refs):
        try:
            mini.resolve(ref)
        except KeyError:
            fail(f"values.schema.json: unresolved $ref {ref}")
    validate = make_validator(schema)
    defaults = docs["values.yaml"]

    def expect(name: str, values: dict, valid: bool) -> None:
        errs = validate(values)
        if valid and errs:
            fail(f"{name} should validate: " + "; ".join(errs[:5]))
        elif not valid and not errs:
            fail(f"{name} should be rejected by the schema")
        else:
            ok(f"{name} {'validates' if valid else 'is rejected'}")

    expect("values.yaml", defaults, True)
    for name, doc in docs.items():
        if "/values-" in name:
            expect(f"values.yaml + {name}", deep_merge(defaults, doc), True)

    bad = {
        "unknown database type": {"database": {"type": "oracle"}},
        "postgresql without url": {"database": {"type": "postgresql"}},
        "unknown secrets mode": {"secrets": {"mode": "plaintext"}},
        "typo in engine key": {"engine": {"replicacount": 2}},
        "engine replicas 0": {"engine": {"replicaCount": 0}},
        "bad KMS reference": {"engine": {"masterKey": {"kms": "vault:foo"}}},
        "bad storage URL": {"engine": {"storage": {"url": "ftp://x"}}},
        "privileged container": {"web": {"containerSecurityContext": {"privileged": True}}},
        "oidc without issuer": {"web": {"auth": {"mode": "oidc"}}},
        "httpRoute without parentRefs": {"web": {"httpRoute": {"enabled": True}}},
        "externalSecrets without store": {"secrets": {"mode": "externalSecrets"}},
        "bad digest": {"engine": {"image": {"digest": "latest"}}},
        "bad CIDR": {"engine": {"networkPolicy": {"database": {"cidrs": ["db.internal"]}}}},
        "alert threshold 0 days": {"engine": {"metrics": {"prometheusRule": {"enabled": True, "expiringDays": 0}}}},
        "unknown cloud provider": {"cloud": {"provider": "openshift"}},
        "identity without provider": {"cloud": {"identity": "irsa"}},
        "gke with irsa": {"cloud": {"provider": "gke", "identity": "irsa"}},
        "aks with pod-identity": {"cloud": {"provider": "aks", "identity": "pod-identity"}},
        "eks with workload-identity": {"cloud": {"provider": "eks", "identity": "workload-identity"}},
        "extraObjects not objects": {"extraObjects": ["kind: ConfigMap"]},
    }
    for name, override in bad.items():
        expect(f"[{name}]", deep_merge(defaults, override), False)


BLOCK_OPEN = re.compile(r"^-?\s*(if|range|with|define|block)\b")
BLOCK_END = re.compile(r"^-?\s*end\s*-?$")


def check_templates() -> None:
    for path in sorted((CHART / "templates").rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", "", text, flags=re.S)  # comments
        rel = path.relative_to(CHART)
        if text.count("{{") != text.count("}}"):
            fail(f"{rel}: {text.count('{{')} '{{{{' vs {text.count('}}')} '}}}}'")
            continue
        depth = 0
        for action in re.findall(r"\{\{(.*?)\}\}", text, flags=re.S):
            action = action.strip()
            if BLOCK_OPEN.match(action):
                depth += 1
            elif BLOCK_END.match(action):
                depth -= 1
                if depth < 0:
                    break
        if depth != 0:
            fail(f"{rel}: unbalanced block actions (depth {depth})")
        else:
            ok(f"{rel} delimiters and blocks balance")


def main() -> int:
    docs = check_yaml_files()
    if "values.yaml" in docs:
        check_schema(docs)
    check_templates()
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
