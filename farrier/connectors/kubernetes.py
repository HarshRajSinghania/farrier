"""A Kubernetes TLS Secret (Ingress, Gateway API, any workload that mounts it), through the API server.

Flow: copy the current Secret to <secret>-farrier-previous (so the old key never sits in Farrier's
database) -> write the new tls.crt (full chain) and tls.key, creating the Secret if needed -> optionally
restart Deployments, StatefulSets or DaemonSets that read it only at start-up. Rollback restores the copy.

config:
  namespace    e.g. "web"
  secret       e.g. "app1-tls"
  url          API server; default the in-cluster address (Farrier running in the cluster)
  token        "env:K8S_TOKEN" or "file:/path"; default the pod's service account token
  verify_tls   True | False | CA bundle path; default the in-cluster CA
  restart      optional list, e.g. ["deployment/web", "statefulset/kafka"]

RBAC: get, create, update on secrets in the namespace; patch on the workloads named in restart.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from farrier.connectors.base import Bundle, Connector, DeployError, check

SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")
KINDS = {"deployment": "deployments", "statefulset": "statefulsets", "daemonset": "daemonsets"}


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class KubernetesConnector(Connector):
    kind = "kubernetes"
    required = ("namespace", "secret")

    def __init__(self, config: dict, data_dir: Path):
        super().__init__(config, data_dir)
        self.cfg.setdefault("url", "https://kubernetes.default.svc")
        if "verify_tls" not in self.cfg and (SA / "ca.crt").exists():
            self.cfg["verify_tls"] = str(SA / "ca.crt")
        for target in self.cfg.get("restart") or []:
            kind, _, name = str(target).partition("/")
            if kind not in KINDS or not name:
                raise ValueError(f"kubernetes connector restart {target!r}: use deployment/, statefulset/ or "
                                 "daemonset/<name>")

    def _client(self):
        token = self.cfg.get("token")
        if not token:
            try:
                token = (SA / "token").read_text().strip()
            except OSError:
                raise DeployError("kubernetes connector: set token (no in-cluster service account found)") from None
        return self.http(headers={"Authorization": f"Bearer {token}"})

    def _path(self, name: str | None = None) -> str:
        return f"/api/v1/namespaces/{self.cfg['namespace']}/secrets" + (f"/{name}" if name else "")

    def _put(self, c, name: str, data: dict, current: dict | None, kind: str = "kubernetes.io/tls"):
        """Write ``data`` into Secret ``name``. An existing Secret keeps its type, labels, annotations and
        owner (Helm, Argo CD...); only its data changes. A new one gets ``kind`` and Farrier's label."""
        if current:
            body = {**current, "data": data, "metadata": {k: v for k, v in (current.get("metadata") or {}).items()
                                                          if k != "managedFields"}}
            body.pop("stringData", None)
            check(c.put(self._path(name), json=body), f"update secret {name}")
        else:
            body = {"apiVersion": "v1", "kind": "Secret", "type": kind,
                    "metadata": {"name": name, "namespace": self.cfg["namespace"],
                                 "labels": {"app.kubernetes.io/managed-by": "farrier"}}, "data": data}
            check(c.post(self._path(), json=body), f"create secret {name}")

    def _get(self, c, name: str) -> dict | None:
        r = c.get(self._path(name))
        return None if r.status_code == 404 else check(r, f"read secret {name}").json()

    def _restart(self, c):
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        for target in self.cfg.get("restart") or []:
            kind, _, name = target.partition("/")
            check(c.patch(f"/apis/apps/v1/namespaces/{self.cfg['namespace']}/{KINDS[kind]}/{name}",
                          headers={"Content-Type": "application/strategic-merge-patch+json"},
                          json={"spec": {"template": {"metadata": {"annotations": {
                              "kubectl.kubernetes.io/restartedAt": stamp}}}}}), f"restart {target}")

    def deploy(self, b: Bundle) -> dict:
        name, backup = self.cfg["secret"], f"{self.cfg['secret']}-farrier-previous"
        with self._client() as c:
            cur = self._get(c, name)
            if cur:   # Opaque: holds whatever keys the original had
                self._put(c, backup, cur.get("data") or {}, self._get(c, backup), kind="Opaque")
            data = {**((cur or {}).get("data") or {}), "tls.crt": _b64(b.fullchain_pem), "tls.key": _b64(b.key_pem)}
            if b.chain_pem.strip():
                data["ca.crt"] = _b64(b.chain_pem)
            self._put(c, name, data, cur)
            self._restart(c)
        return {"backup": backup if cur else None}

    def rollback(self, token: dict) -> None:
        with self._client() as c:
            if token.get("backup"):
                prev = self._get(c, token["backup"])
                if not prev:
                    raise DeployError(f"backup secret {token['backup']} is gone; cannot roll back")
                self._put(c, self.cfg["secret"], prev.get("data") or {}, self._get(c, self.cfg["secret"]))
            else:   # the Secret did not exist before Farrier created it
                r = c.delete(self._path(self.cfg["secret"]))
                if r.status_code != 404:
                    check(r, "delete secret")
            self._restart(c)
