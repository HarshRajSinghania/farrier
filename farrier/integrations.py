"""Certificate authorities, DNS accounts and alert channels configured from the dashboard.

Dashboard entries live in the ``config_items`` table (migration 4), so every replica sees them; a
``config_version`` counter is bumped on each change and every engine reloads when it sees a new value
(farrier.engine.Engine.check_config, run each tick). Files keep working and win on a name clash:

    issuers.json            -> issuers, source "file" (no file: the built-in local CA, source "builtin")
    dns.json                -> DNS accounts, source "file"
    settings.json notifiers -> alert channels settings-1, settings-2..., source "file"

Dashboard entries never hold a secret value: credentials are vault:/env:/file: references, checked
here and resolved only at the moment of use.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .db import now_iso
from .publishers import EVENT_TYPES
from .vault import SecretRefused, check_secret_refs, is_ref

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KINDS = ("issuer", "dns", "notifier", "alert_rule")
VAULT_REF = re.compile(r"^vault:(.+)$")


class Invalid(ValueError):
    """A config the API refuses (HTTP 400)."""


class Conflict(ValueError):
    """A change that clashes with existing configuration (HTTP 409)."""


# ---- storage ---------------------------------------------------------------------------------------
class ConfigItems:
    def __init__(self, store):
        self.store = store

    def all(self, kind: str) -> dict[str, dict]:
        rows = self.store.q("SELECT name, body FROM config_items WHERE kind=? ORDER BY name", (kind,))
        return {r["name"]: json.loads(r["body"]) for r in rows}

    def get(self, kind: str, name: str) -> dict | None:
        r = self.store.q1("SELECT body FROM config_items WHERE kind=? AND name=?", (kind, name))
        return json.loads(r["body"]) if r else None

    def put(self, kind: str, name: str, body: dict, actor: str | None = None) -> None:
        data, t = json.dumps(body, sort_keys=True), now_iso()
        with self.store.transaction():
            n = self.store._run("UPDATE config_items SET body=?, updated_at=?, updated_by=? WHERE kind=? AND name=?",
                                (data, t, actor, kind, name))[1]
            if not n:
                self.store.x("INSERT INTO config_items(kind, name, body, updated_at, updated_by) VALUES (?,?,?,?,?)",
                             (kind, name, data, t, actor))
            self.bump()

    def delete(self, kind: str, name: str) -> bool:
        with self.store.transaction():
            n = self.store._run("DELETE FROM config_items WHERE kind=? AND name=?", (kind, name))[1]
            if n:
                self.bump()
        return n > 0

    def version(self) -> int:
        r = self.store.q1("SELECT version FROM config_version WHERE id=1")
        return int(r["version"]) if r else 0

    def bump(self) -> None:
        self.store.x("UPDATE config_version SET version = version + 1 WHERE id=1")


# ---- file sources ----------------------------------------------------------------------------------
def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def file_issuers(engine) -> tuple[dict, str]:
    """(entries, source) where source is "file" or "builtin" (no issuers.json)."""
    path = Path(engine.data_dir) / "issuers.json"
    if path.exists():
        return _read_json(path), "file"
    return {"default": {"type": "local_ca"}}, "builtin"


def file_dns(engine) -> dict:
    from .dns.accounts import RESERVED
    return {k: v for k, v in _read_json(Path(engine.data_dir) / "dns.json").items()
            if k not in RESERVED and isinstance(v, dict)}


def file_notifiers(settings: dict) -> dict[str, dict]:
    out = {}
    for i, c in enumerate(settings.get("notifiers") or [], 1):
        if isinstance(c, dict):
            out[f"settings-{i}"] = c
    return out


def issuer_configs(engine) -> dict[str, tuple[str, dict]]:
    """Every effective issuer entry: name -> (source, entry)."""
    files, source = file_issuers(engine)
    ui = engine.items.all("issuer")
    out = {n: (source, c) for n, c in files.items() if not (source == "builtin" and n in ui)}
    for n, c in ui.items():
        if n not in out:
            out[n] = ("ui", c)
    return out


def dns_configs(engine) -> dict[str, tuple[str, dict]]:
    out = {n: ("file", c) for n, c in file_dns(engine).items()}
    for n, c in engine.items.all("dns").items():
        out.setdefault(n, ("ui", c))
    return out


def notifier_configs(engine) -> dict[str, tuple[str, dict]]:
    out = {n: ("file", c) for n, c in file_notifiers(engine.settings).items()}
    for n, c in engine.items.all("notifier").items():
        out.setdefault(n, ("ui", c))
    return out


def file_owner(engine, kind: str, name: str) -> str | None:
    """The file that manages this name, if any (PUT/DELETE then answer 409)."""
    if kind == "issuer":
        files, source = file_issuers(engine)
        return "issuers.json" if source == "file" and name in files else None
    if kind == "dns":
        from .dns.accounts import RESERVED
        if name in RESERVED or name in file_dns(engine):
            return "dns.json"
        return None
    if kind == "notifier":
        return "settings.json" if name in file_notifiers(engine.settings) or name.startswith("settings-") else None
    return None


def load_dns_accounts(engine):
    """dns.json plus dashboard accounts, as one DnsAccounts (a file account wins on a name clash)."""
    from .dns import DnsAccounts
    from .dns.base import DnsConfigError
    path = Path(engine.data_dir) / "dns.json"
    cfg: dict = {}
    if path.exists():
        try:
            cfg = json.loads(path.read_text())
        except ValueError as e:
            raise DnsConfigError(f"dns.json is not valid JSON: {e}") from None
        if not isinstance(cfg, dict):
            raise DnsConfigError("dns.json must be an object of named accounts")
    cfg = dict(cfg)
    for n, c in engine.items.all("dns").items():
        cfg.setdefault(n, c)
    return DnsAccounts.from_config(cfg)


def notifier_list(engine) -> list[dict]:
    """Configs for farrier.notify.Notifier, each with its channel name."""
    return [{**c, "name": n} for n, (_, c) in notifier_configs(engine).items()]


# ---- secrets: references and usage -----------------------------------------------------------------
def vault_refs(obj) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for v in obj.values():
            out |= vault_refs(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= vault_refs(v)
    elif isinstance(obj, str) and (m := VAULT_REF.match(obj)):
        out.add(m.group(1))
    return out


def used_by(engine) -> dict[str, list[str]]:
    """secret name -> ["issuer:le", "dns:cf-prod", "notifier:ops", "endpoint:web-1", ...]."""
    uses: dict[str, list[str]] = {}

    def add(label: str, obj):
        for name in sorted(vault_refs(obj)):
            uses.setdefault(name, []).append(label)

    for n, (_, c) in issuer_configs(engine).items():
        add(f"issuer:{n}", c)
    for n, (_, c) in dns_configs(engine).items():
        add(f"dns:{n}", c)
    for n, (_, c) in notifier_configs(engine).items():
        add(f"notifier:{n}", c)
    for e in engine.store.q("SELECT name, connector_config FROM endpoints ORDER BY name"):
        add(f"endpoint:{e['name']}", e["connector_config"])
    return uses


def check_refs(engine, obj) -> None:
    """Guardrails for every reference in a config: allowed at all, and vault: names that exist."""
    try:
        check_secret_refs(obj)
    except SecretRefused as e:
        raise Invalid(f"secret reference refused: {e}") from None
    missing = sorted(n for n in vault_refs(obj) if not engine.secrets.exists(n))
    if missing:
        raise Invalid(f"no stored secret named {', '.join(missing)}; add it under Secrets first "
                      "(PUT /api/secrets/{name})")


def guard(body: dict, allow_commands: bool, allow_inline: bool) -> None:
    """The API's existing rules: no command/hook keys, no inline secrets."""
    from .api import _command_keys, _inline_secrets
    cmds = _command_keys(body)
    if cmds and not allow_commands:
        raise Invalid(f"{', '.join(cmds)} would run commands on the Farrier host; set them in a config file, "
                      "or set FARRIER_ALLOW_API_COMMANDS=1")
    inline = _inline_secrets(body)
    if inline and not allow_inline:
        raise Invalid(f"{', '.join(inline)} must reference a secret (vault:NAME, env:NAME or file:/path), "
                      "not contain it")


def _ref_view(v) -> str | None:
    if v in (None, ""):
        return None
    return v if is_ref(v) else "set (inline)"


# ---- catalog ---------------------------------------------------------------------------------------
_WORDS = {"api": "API", "id": "ID", "url": "URL", "tls": "TLS", "ttl": "TTL", "ip": "IP", "arn": "ARN",
          "tsig": "TSIG", "ote": "OTE", "smtp": "SMTP", "dns": "DNS"}


def _label(key: str) -> str:
    words = [_WORDS.get(w, w) for w in key.replace("-", "_").split("_")]
    words[0] = words[0][:1].upper() + words[0][1:]
    return " ".join(words)


def _field(key, label=None, secret=False, required=False, help=""):
    return {"key": key, "label": label or _label(key), "secret": secret, "required": required, "help": help}


DNS_LABELS = {
    "cloudflare": "Cloudflare", "route53": "AWS Route 53", "azure": "Azure DNS", "google": "Google Cloud DNS",
    "digitalocean": "DigitalOcean", "powerdns": "PowerDNS", "linode": "Linode (Akamai Cloud)", "gandi": "Gandi",
    "ovh": "OVHcloud", "namecheap": "Namecheap", "arvancloud": "ArvanCloud", "infomaniak": "Infomaniak",
    "acme-dns": "acme-dns", "duckdns": "Duck DNS", "vultr": "Vultr", "dnsmadeeasy": "DNS Made Easy", "ns1": "NS1",
    "hetzner": "Hetzner DNS", "hetzner-cloud": "Hetzner Cloud DNS", "porkbun": "Porkbun", "godaddy": "GoDaddy",
    "hurricane": "Hurricane Electric", "dynu": "Dynu", "akamai": "Akamai Edge DNS", "desec": "deSEC",
    "scaleway": "Scaleway", "rfc2136": "RFC 2136 (BIND, nsupdate)", "solidserver": "EfficientIP SOLIDserver",
    "script": "Custom script",
}
# Non-secret DNS options that every provider accepts (dns.accounts.COMMON_OPTIONS)
COMMON_DNS_OPTIONS = [_field("ttl", "TTL", help="TTL of the challenge TXT record in seconds"),
                      _field("verify_tls", "Verify TLS", help="true (default) or false; only for a private API "
                                                              "endpoint with a self-signed certificate")]

CA_LABELS = {
    "letsencrypt": "Let's Encrypt", "letsencrypt-staging": "Let's Encrypt (staging)", "zerossl": "ZeroSSL",
    "google": "Google Trust Services", "google-staging": "Google Trust Services (staging)", "buypass": "Buypass Go SSL",
    "buypass-staging": "Buypass Go SSL (staging)", "sslcom": "SSL.com (ECDSA)", "sslcom-rsa": "SSL.com (RSA)",
    "digicert": "DigiCert", "sectigo": "Sectigo",
}

NOTIFIER_FIELDS: dict[str, tuple[str, list[dict]]] = {
    "webhook": ("Webhook", [
        _field("url", "Webhook URL", secret=True, required=True, help="Receives a JSON POST for each event"),
        _field("label", "Label", help="Shown in the dashboard instead of the URL"),
    ]),
    "slack": ("Slack", [
        _field("url", "Incoming webhook URL", secret=True, required=True, help="https://hooks.slack.com/services/..."),
        _field("channel", "Channel", help="Shown in the dashboard, e.g. #ops"),
    ]),
    "teams": ("Microsoft Teams", [
        _field("url", "Incoming webhook URL", secret=True, required=True,
               help="A Teams incoming webhook or Power Automate \"post to a channel\" URL"),
        _field("channel", "Channel", help="Shown in the dashboard, e.g. PKI / Alerts"),
    ]),
    "email": ("Email (SMTP)", [
        _field("host", "SMTP host", required=True, help="e.g. smtp.sendgrid.net"),
        _field("port", "Port", help="587 for STARTTLS (default), 465 for TLS"),
        _field("username", "Username"),
        _field("password", "Password", secret=True),
        _field("from", "From", required=True, help="Sender address"),
        _field("to", "To", required=True, help="One or more recipient addresses"),
        _field("tls", "TLS", help="starttls (default), ssl, or none (internal relay only; never with a password)"),
    ]),
    "ses": ("Amazon SES", [
        _field("region", "AWS region", required=True, help="e.g. eu-west-1"),
        _field("username", "SMTP username", secret=True, required=True, help="SES SMTP credentials, not IAM keys"),
        _field("password", "SMTP password", secret=True, required=True),
        _field("from", "From", required=True, help="A verified sender address"),
        _field("to", "To", required=True, help="One or more recipient addresses"),
    ]),
    # Event buses: CloudEvents for automation. Identity comes from the platform (IRSA, Workload Identity,
    # managed identity); only Event Grid can take a key instead.
    "eventbridge": ("Amazon EventBridge", [
        _field("bus", "Event bus", required=True, help="Bus name (e.g. default) or ARN"),
        _field("region", "AWS region", help="Required for a bus name unless AWS_REGION is set; taken from an ARN"),
    ]),
    "pubsub": ("Google Cloud Pub/Sub", [
        _field("topic", "Topic", required=True, help="projects/<project>/topics/<topic>"),
    ]),
    "eventgrid": ("Azure Event Grid", [
        _field("endpoint", "Topic endpoint", required=True,
               help="https://<topic>.<region>-1.eventgrid.azure.net/api/events"),
        _field("key", "Access key", secret=True,
               help="Leave empty to use the workload or managed identity (Event Grid Data Sender role)"),
    ]),
}


def catalog(allow_commands: bool = False) -> dict:
    import sys

    from .alerts import RULE_TYPES
    from .dns.accounts import ALTERNATIVES
    from .dns.providers import PROVIDERS, provider_class
    from .issuers import PRESETS

    providers = []
    for pid in PROVIDERS:
        if pid == "script" and not allow_commands:
            continue  # its only setting is a shell command, which the API refuses
        cls = provider_class(pid)
        alts = ALTERNATIVES.get(pid)
        alt_help = ("Set one of: " + "; or ".join(" + ".join(a) for a in alts)) if alts else ""
        fields = [_field(k, secret=True, required=not alts and k in cls.required, help=alt_help)
                  for k in dict.fromkeys([*cls.required, *cls.optional])]
        fields += [_field(k, help=("A shell command (needs FARRIER_ALLOW_API_COMMANDS)" if k == "dns_hook" else ""))
                   for k in cls.options_known]
        fields += [f for f in COMMON_DNS_OPTIONS if f["key"] not in cls.options_known]
        doc = (sys.modules[cls.__module__].__doc__ or "").strip().splitlines()
        providers.append({"id": pid, "label": DNS_LABELS.get(pid, pid), "fields": fields,
                          "help": doc[0] if doc else ""})
    presets = [{"id": k, "label": CA_LABELS.get(k, k), "eab": bool(p["eab"]),
                "needs_directory_url": p["directory_url"] is None, "staging": "staging" in k}
               for k, p in PRESETS.items()]
    return {
        "dns_providers": providers,
        "ca_presets": presets,
        "notifier_types": [{"id": k, "label": label, "fields": fields} for k, (label, fields) in NOTIFIER_FIELDS.items()],
        "alert_rule_types": [{"id": k, "label": label} for k, label in RULE_TYPES.items()],
    }


# ---- issuers ---------------------------------------------------------------------------------------
def issuer_view(name: str, source: str, c: dict) -> dict:
    from .issuers import PRESETS
    c = c if isinstance(c, dict) else {}
    preset = c.get("preset")
    url = c.get("directory_url") or ((PRESETS.get(str(preset).lower()) or {}).get("directory_url") if preset else None)
    kind = c.get("type") or ("acme" if preset or url else "local_ca")
    return {"name": name, "source": source, "type": kind, "preset": preset, "directory_url": url,
            "email": c.get("email"), "dns": c.get("dns") or ("hook" if c.get("dns_hook") else None),
            "profile": c.get("profile"), "preferred_chain": c.get("preferred_chain"),
            "eab_kid": _ref_view(c.get("eab_kid")), "eab_hmac_key": _ref_view(c.get("eab_hmac_key"))}


def validate_issuer(engine, name: str, body, allow_commands: bool, allow_inline: bool) -> dict:
    from .dns.base import DnsConfigError
    from .issuers import ACME_KEYS, LOCAL_CA_KEYS, build_issuer
    if not isinstance(body, dict) or not body:
        raise Invalid("send an issuers.json entry, e.g. {\"preset\": \"letsencrypt\", \"email\": ..., \"dns\": \"auto\"}")
    guard(body, allow_commands, allow_inline)
    if str(body.get("preset", "")).lower() in ("local_ca", "local-ca"):   # the UI's name for the private CA
        body = {k: v for k, v in body.items() if k != "preset"} | {"type": "local_ca"}
    for k in ("eab_kid", "eab_hmac_key"):
        if body.get(k) not in (None, "") and not is_ref(body[k]):
            raise Invalid(f"{k} must reference a secret (vault:NAME, env:NAME or file:/path), not contain it")
    body = {k: v for k, v in body.items() if v not in (None, "")}
    kind = body.get("type") or ("acme" if "preset" in body or "directory_url" in body else None)
    if kind not in ("acme", "local_ca"):
        raise Invalid(f"issuer {name}: set \"preset\" (an ACME CA) or \"type\": \"acme\" or \"local_ca\"")
    allowed = ACME_KEYS if kind == "acme" else LOCAL_CA_KEYS
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise Invalid(f"issuer {name}: unknown keys {unknown} for type {kind} (allowed: {sorted(allowed)})")
    if kind == "acme" and not body.get("dns") and not body.get("dns_hook"):
        raise Invalid(f"issuer {name}: set \"dns\" (\"auto\" or a DNS account name) so Farrier can answer DNS-01")
    if kind == "acme" and body.get("directory_url"):
        u = urlparse(str(body["directory_url"]))
        if u.scheme != "https" or not u.hostname:
            raise Invalid(f"issuer {name}: directory_url must be an https:// URL")
    check_refs(engine, body)
    try:
        build_issuer(name, body, engine.data_dir, lambda: load_dns_accounts(engine))
    except (ValueError, DnsConfigError) as e:
        raise Invalid(str(e)) from None
    except KeyError as e:
        raise Invalid(f"issuer {name}: {e.args[0] if e.args else e}") from None
    except TypeError as e:
        raise Invalid(f"issuer {name}: {e}") from None
    return body


def test_issuer(engine, name: str) -> dict:
    from .issuers import build_issuer
    found = issuer_configs(engine).get(name)
    if not found:
        raise KeyError(name)
    try:
        iss = build_issuer(name, found[1], engine.data_dir, lambda: load_dns_accounts(engine))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"configuration: {e}"}
    if not hasattr(iss, "ensure_account"):
        return {"ok": True, "detail": "private CA ready (no network needed)"}
    host = urlparse(iss.directory_url).hostname
    try:
        iss.directory  # noqa: B018 - fetches the directory
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"could not fetch the ACME directory at {host}: {type(e).__name__}: {e}"[:400]}
    try:
        iss.ensure_account()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"directory reachable, but the account was refused: {e}"[:400]}
    eab = " with External Account Binding" if iss.eab_kid else ""
    return {"ok": True, "detail": f"account ready at {host}{eab}"}


# ---- DNS accounts ----------------------------------------------------------------------------------
_INT_OPTIONS = {"ttl", "timeout", "port"}
_BOOL_OPTIONS = {"verify_tls", "private_zones", "wait_insync", "sandbox", "ote", "tcp"}


def _coerce_options(opts: dict) -> dict:
    """Form fields arrive as strings; give numbers and booleans their type."""
    out = {}
    for k, v in opts.items():
        if v in (None, ""):
            continue
        if k in _INT_OPTIONS and isinstance(v, str) and v.strip().isdigit():
            v = int(v)
        elif k in _BOOL_OPTIONS and isinstance(v, str) and v.strip().lower() in ("true", "false", "1", "0", "yes", "no"):
            v = v.strip().lower() in ("true", "1", "yes")
        out[k] = v
    return out


def dns_view(name: str, source: str, c: dict) -> dict:
    return {"name": name, "source": source, "provider": c.get("provider"), "zones": c.get("zones") or [],
            "credentials": {k: _ref_view(v) for k, v in (c.get("credentials") or {}).items()},
            "options": c.get("options") or {}}


def keep_dns_refs(old: dict | None, body):
    """An edit of a dashboard DNS account may leave out credentials it does not replace: keep the stored
    references (the rule alert channels follow). Only for the same provider."""
    from .dns.base import DnsConfigError
    from .dns.providers import canonical
    if not old or not isinstance(body, dict) or not isinstance(old.get("credentials"), dict):
        return body
    try:
        same = canonical(body.get("provider", "")) == canonical(old.get("provider", ""))
    except DnsConfigError:
        return body
    creds = body.get("credentials")
    if not same or not (creds is None or isinstance(creds, dict)):
        return body
    kept = {k: v for k, v in old["credentials"].items() if v not in (None, "")}
    kept.update({k: v for k, v in (creds or {}).items() if v not in (None, "")})
    return {**body, "credentials": kept}


def validate_dns(engine, name: str, body, allow_commands: bool, allow_inline: bool) -> dict:
    from .dns.accounts import validate_account
    from .dns.base import DnsConfigError
    from .dns.providers import provider_class
    if not isinstance(body, dict):
        raise Invalid("send {provider, credentials, options, zones}")
    guard({k: v for k, v in body.items() if k != "credentials"}, allow_commands, allow_inline)
    body = dict(body)
    body["credentials"] = {k: v for k, v in (body.get("credentials") or {}).items() if v not in (None, "")} \
        if isinstance(body.get("credentials"), dict) else body.get("credentials")
    if isinstance(body.get("options"), dict):
        body["options"] = _coerce_options(body["options"])
    try:
        acc = validate_account(name, body)
    except DnsConfigError as e:
        raise Invalid(str(e)) from None
    check_refs(engine, body)
    try:
        provider_class(acc["provider"])(name, acc["credentials"], acc["options"], acc["zones"])
    except (DnsConfigError, ValueError, TypeError) as e:
        raise Invalid(str(e)) from None
    out = {"provider": acc["provider"], "credentials": acc["credentials"], "options": acc["options"],
           "zones": acc["zones"]}
    for k in ("propagation_check", "propagation_timeout", "propagation_seconds", "description"):
        if k in body:
            out[k] = body[k]
    return out


def test_dns(engine, name: str) -> dict:
    """Authenticate and find each configured zone. Read-only: no record is written."""
    from .dns.accounts import validate_account
    from .dns.base import DnsError, Provider
    from .dns.providers import provider_class
    found = dns_configs(engine).get(name)
    if not found:
        raise KeyError(name)
    try:
        acc = validate_account(name, found[1])
        p = provider_class(acc["provider"])(name, acc["credentials"], acc["options"], acc["zones"])
        for k in acc["credentials"]:
            p.secret(k)                     # every reference resolves
    except DnsError as e:
        return {"ok": False, "detail": str(e)}
    try:
        try:
            listed = [z.name for z in p.list_zones()]
        except NotImplementedError:
            listed = None
        if listed is not None:
            missing = [z for z in acc["zones"] if z not in listed]
            if missing:
                return {"ok": False, "detail": f"signed in, but these zones are not in the account: {', '.join(missing)}",
                        "zones": listed}
            return {"ok": True, "detail": f"signed in; {len(listed)} zone(s) visible", "zones": listed}
        if acc["zones"] and type(p).zone_id is not Provider.zone_id:
            for z in acc["zones"]:
                p.zone_id(z)
            return {"ok": True, "detail": "signed in; every configured zone found", "zones": acc["zones"]}
        return {"ok": True, "detail": f"credentials resolve; {acc['provider']} cannot be checked without writing a "
                                      "record, so the first renewal is the real test", "zones": acc["zones"]}
    except DnsError as e:
        return {"ok": False, "detail": p.redact(str(e))}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": type(e).__name__}
    finally:
        p.close()


# ---- notifiers -------------------------------------------------------------------------------------
def notifier_target(c: dict) -> str:
    kind = c.get("type", "webhook")
    if kind == "eventbridge":
        return f"{c.get('bus')} on EventBridge"
    if kind == "pubsub":
        return f"{c.get('topic')} on Pub/Sub"
    if kind == "eventgrid":
        from urllib.parse import urlparse as _u
        return f"{_u(str(c.get('endpoint'))).hostname} on Event Grid"
    if kind in ("email", "ses"):
        to = c.get("to") or []
        return ", ".join([to] if isinstance(to, str) else to)
    if kind in ("slack", "teams"):
        where = NOTIFIER_FIELDS[kind][0]
        return f"{c['channel']} on {where}" if c.get("channel") else where
    return c.get("label") or "webhook"


def notifier_view(name: str, source: str, c: dict) -> dict:
    """``fields`` pre-fills the edit form: non-secret values, and secret fields only as their reference."""
    from .notify import default_events
    events = c.get("events")
    kind = c.get("type", "webhook")
    fields = {}
    for f in NOTIFIER_FIELDS.get(kind, ("", []))[1]:
        if c.get(f["key"]) not in (None, ""):
            fields[f["key"]] = _ref_view(c[f["key"]]) if f["secret"] else c[f["key"]]
    return {"name": name, "source": source, "type": kind,
            "events": list(default_events(kind)) if events is None else events, "target": notifier_target(c),
            "fields": fields}


def keep_secret_refs(old: dict | None, body):
    """An edit may leave out secret fields the user did not replace: keep the stored references."""
    if not old or not isinstance(body, dict) or body.get("type") != old.get("type"):
        return body
    body = dict(body)
    for f in NOTIFIER_FIELDS.get(old.get("type", "webhook"), ("", []))[1]:
        if f["secret"] and body.get(f["key"]) in (None, "") and old.get(f["key"]):
            body[f["key"]] = old[f["key"]]
    if old.get("headers") and "headers" not in body:
        body["headers"] = old["headers"]
    return body


def validate_notifier(engine, name: str, body, allow_commands: bool, allow_inline: bool) -> dict:
    from .notify import EVENTS, _email_target
    if not isinstance(body, dict):
        raise Invalid("send {type, events?, ...fields}")
    guard(body, allow_commands, allow_inline)
    kind = body.get("type")
    if kind not in NOTIFIER_FIELDS:
        raise Invalid(f"type must be one of {', '.join(NOTIFIER_FIELDS)}")
    fields = {f["key"]: f for f in NOTIFIER_FIELDS[kind][1]}
    extra = {"type", "events"} | ({"headers"} if kind == "webhook" else set())
    body = {k: v for k, v in body.items() if v not in (None, "")}
    unknown = sorted(set(body) - set(fields) - extra)
    if unknown:
        raise Invalid(f"unknown fields {unknown} for {kind} (known: {sorted(set(fields) | extra)})")
    for k, f in fields.items():
        if f["required"] and not body.get(k):
            raise Invalid(f"{f['label']} ({k}) is required for {kind}")
        if f["secret"] and k in body and not is_ref(body[k]) and not allow_inline:
            raise Invalid(f"{k} is a secret: store it under Secrets and reference it as vault:NAME "
                          "(or env:NAME / file:/path)")
    if "headers" in body:
        h = body["headers"]
        if not isinstance(h, dict) or not all(isinstance(v, str) and is_ref(v) for v in h.values()):
            raise Invalid("headers must map header names to secret references (vault:NAME, env:NAME or file:/path)")
    if "events" in body:
        ev = body["events"]
        if not isinstance(ev, list) or not all(isinstance(e, str) for e in ev) or set(ev) - (EVENTS - {"test"}):
            raise Invalid(f"events must be a list drawn from {sorted(EVENTS - {'test'})}")
    if kind in ("email", "ses"):
        to = body.get("to")
        to = [to] if isinstance(to, str) else to
        if not isinstance(to, list) or not to or not all(isinstance(a, str) and "@" in a for a in to):
            raise Invalid("to must be one or more email addresses")
        body["to"] = [a.strip() for a in to]
        if "@" not in str(body.get("from", "")):
            raise Invalid("from must be an email address")
        if "port" in body:
            try:
                body["port"] = int(body["port"])
            except (TypeError, ValueError):
                raise Invalid("port must be a number") from None
            if not 1 <= body["port"] <= 65535:
                raise Invalid("port must be between 1 and 65535")
        if body.get("tls", "starttls") not in ("starttls", "ssl", "none"):
            raise Invalid("tls must be starttls, ssl or none")
        if body.get("tls") == "none" and body.get("password"):
            raise Invalid("a password is never sent without TLS; use starttls or ssl")
        try:
            _email_target(body)
        except (ValueError, KeyError) as e:
            raise Invalid(str(e)) from None
    elif kind in EVENT_TYPES:
        from .publishers import check
        try:
            check(body)
        except ValueError as e:
            raise Invalid(f"{kind}: {e}") from None
    else:
        u = body["url"]
        if not is_ref(u) and urlparse(u).scheme not in ("https", "http"):
            raise Invalid("url must be an http(s) URL")
    check_refs(engine, body)
    return body


def test_notifier(engine, name: str) -> dict:
    from .notify import Notifier, failure_detail, payload
    found = notifier_configs(engine).get(name)
    if not found:
        raise KeyError(name)
    p = payload("test", None, None, engine.notifier.dashboard_url) | {"condition": f"test of alert channel {name}"}
    try:
        Notifier.deliver_one(found[1], p)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": failure_detail(e)}
    return {"ok": True, "detail": f"delivered to {notifier_target(found[1])}"}
