# Farrier Helm chart

Runs [Farrier](https://github.com/gagankarthik/farrier) on Kubernetes 1.27+:

- **engine**: the API and renewal loop (`farrier serve`, port 8740). A ClusterIP Service only: it is
  never exposed. With PostgreSQL or MySQL it is a Deployment (2 replicas by default; one elected
  leader runs the renewal loop, every replica serves the API). With SQLite it is a single-replica
  StatefulSet with its data on a PVC.
- **web**: the dashboard (Next.js, port 3000), a stateless Deployment behind an Ingress or a Gateway
  API HTTPRoute, with optional autoscaling.

Secure by default: restricted Pod Security Standard on every pod, read-only root filesystems, no
Kubernetes API token mounted, default-deny NetworkPolicies, secrets only from Kubernetes Secrets
(the database password as a file), and a PodDisruptionBudget plus zone/node spread wherever more
than one replica runs.

## Prerequisites

- Kubernetes 1.27+ and Helm 3.12+.
- A namespace that enforces the **restricted** Pod Security Standard (every pod in this chart,
  including the test pod, passes it):

  ```bash
  kubectl create namespace farrier
  kubectl label namespace farrier \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted
  ```

- A CNI that enforces NetworkPolicy (Calico, Cilium, AWS VPC CNI with network policies on, GKE
  Dataplane V2, Azure CNI with Azure/Cilium network policy).
- Optional, only for the features that need them: External Secrets Operator (`secrets.mode:
  externalSecrets`), Prometheus Operator (`engine.metrics.serviceMonitor`, `engine.metrics.prometheusRule`),
  the Grafana dashboard sidecar (`engine.metrics.grafanaDashboard`), Gateway API CRDs
  (`web.httpRoute`).

## Install

### Try it (development)

SQLite, a generated Secret, port-forward to the dashboard:

```bash
helm install farrier deploy/helm/farrier -n farrier --set secrets.mode=create
kubectl -n farrier get secret farrier -o jsonpath='{.data.dashboard-password}' | base64 -d
kubectl -n farrier port-forward svc/farrier-web 3000:80
```

`secrets.mode=create` is for development only: the values live in the Helm release history. The
install notes print a warning and the commands to back up the generated master key.

### Production

1. Create the Secrets (or let your secret manager do it, see below):

   ```bash
   kubectl -n farrier create secret generic farrier-engine \
     --from-literal=api-token="$(openssl rand -hex 32)" \
     --from-literal=api-read-token="$(openssl rand -hex 32)" \
     --from-literal=master-key="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
     --from-literal=database-password='...'
   kubectl -n farrier create secret generic farrier-web \
     --from-literal=api-token="<same api-token>" \
     --from-literal=api-read-token="<same api-read-token>" \
     --from-literal=oidc-client-secret='...' \
     --from-literal=session-secret="$(openssl rand -base64 48)"
   ```

   Keep the master key backed up separately from the database: without it, sealed private keys
   are unreadable.

2. Install with your values file (see the examples below):

   ```bash
   helm install farrier deploy/helm/farrier -n farrier -f my-values.yaml
   helm test farrier -n farrier
   ```

## Upgrade

```bash
helm upgrade farrier deploy/helm/farrier -n farrier -f my-values.yaml
```

- Engine pods carry `checksum/config` and `checksum/secret` annotations, so changing a setting
  (or, in `create`/`externalSecrets` mode, a secret reference) rolls them. In `existingSecret`
  mode the chart can't see secret values: after rotating one, run
  `kubectl -n farrier rollout restart deploy/farrier-engine deploy/farrier-web` (or use a reloader).
- With PostgreSQL/MySQL the engine rolls with `maxUnavailable: 0`. On SIGTERM a replica drains
  requests for `engine.shutdownGrace` seconds, finishes its renewal tick within the same budget
  again, and releases the leader lock; `terminationGracePeriodSeconds` is
  `max(grace + 25, 2 * grace + 5)` so the kubelet never kills it mid-tick.
- With SQLite the single replica restarts in place: a short API outage, the dashboard stays up.
- **SQLite to PostgreSQL/MySQL**: run `farrier db migrate --to "<url>"` (inside the engine pod, with
  `FARRIER_DATABASE_PASSWORD` set), then upgrade with `database.type`/`database.url`. The engine
  becomes a Deployment; the old StatefulSet's PVC is retained (`whenDeleted: Retain`) until you
  delete it. Keep the same master key.
- Schema migrations run automatically under a lock, so replicas starting together don't race.

## Secrets

Secret values only ever come from Kubernetes Secrets, by `secretKeyRef` or a mounted file; never
from ConfigMaps or env literals. Choose the source with `secrets.mode`:

| Mode | What the chart renders | Use for |
|---|---|---|
| `existingSecret` (default) | Nothing. Pods read `secrets.existingSecret.engine` and `.web`. | Production: Secrets from your CD pipeline, sealed-secrets, SOPS or the Secrets Store CSI driver. |
| `externalSecrets` | One `ExternalSecret` per component (External Secrets Operator), reading `secrets.externalSecrets.remoteRefs` from a SecretStore/ClusterSecretStore. | Production: AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault. |
| `create` | One Secret from `secrets.create` (tokens, master key and passwords generated if empty and kept across upgrades). | Development only. |

Keys each component needs (names configurable under `secrets.keys`):

| Key | Engine | Web | Notes |
|---|---|---|---|
| `api-token` | yes | yes | Same value in both. |
| `api-read-token` | optional | optional | Required for the ServiceMonitor. |
| `master-key` | yes; with `engine.masterKey.kms` the wrapped key (optional with sqlite) | | Fernet key. |
| `database-password` | postgresql/mysql | | Mounted at `/run/secrets/farrier-db/password`. |
| `dashboard-password` | | `web.auth.mode=basic` | |
| `oidc-client-secret`, `session-secret` | | `web.auth.mode=oidc` | |

The web Secret is separate from the engine's so that dashboard pods can't read the master key or
database password. Device, DNS and notifier credentials go in `engine.deviceSecrets.existingSecret`,
mounted at `/run/secrets/farrier` and referenced from connector configs as
`file:/run/secrets/farrier/<key>`. `FARRIER_SECRET_DIRS` allows exactly that directory.

## Network policy

With `networkPolicy.enabled` (the default) both components are default-deny:

| | Allowed |
|---|---|
| engine ingress | web pods and the `helm test` pod on 8740; Prometheus on 8740 when `engine.networkPolicy.metricsNamespaceSelector` is set. |
| engine egress | cluster DNS; the database (`engine.networkPolicy.database.cidrs`, required with an external database); device management networks (`managementNetworks`: CIDR + ports); TCP 443 to the internet except private ranges and link-local (`internet`); the workload identity endpoint `cloud.provider` needs, and only that; `extraEgress`. |
| web ingress | TCP 3000, from `web.networkPolicy.ingressFrom` when set (e.g. your ingress controller's namespace). |
| web egress | cluster DNS; the engine on 8740; the IdP on 443 in OIDC mode (`web.networkPolicy.idp`); `extraEgress`. |

Cluster-specific additions go in `extraEgress`:

- **Cloud private endpoints** for STS, KMS, Secret Manager, Key Vault or object storage: their subnet on 443.
- **NodeLocal DNSCache**: allow `169.254.20.10/32` on 53 UDP/TCP.
- **In-cluster PostgreSQL or Vault**: a `podSelector`/`namespaceSelector` peer and its port.
- **Internal ACME CA, DNS API or webhook targets** on private addresses: their CIDRs and ports.

## Managed Kubernetes (EKS, GKE, AKS)

`examples/values-eks.yaml`, `values-gke.yaml` and `values-aks.yaml` are complete, commented
installs: managed PostgreSQL with two engine replicas, secrets synced by the External Secrets
Operator, the master key wrapped by the cloud KMS, object storage, workload identity and the cloud's
ingress. `deploy/terraform/{eks,gke,aks}` create the cloud side next to an existing cluster and
print the account-specific values:

```bash
terraform -chdir=deploy/terraform/eks apply                       # 1. identity, KMS, secrets, bucket, database
terraform -chdir=deploy/terraform/eks output -raw kubernetes_manifests | kubectl apply -f -
terraform -chdir=deploy/terraform/eks output -raw helm_values > cloud-values.yaml
helm install farrier deploy/helm/farrier -n farrier   -f deploy/helm/farrier/examples/values-eks.yaml -f cloud-values.yaml   # 2. install
curl -fsS https://<dashboard host>/api/health                           # 3. verify
```

| | EKS | GKE | AKS |
|---|---|---|---|
| `cloud.provider` / `identity` | `eks` / `irsa` or `pod-identity` | `gke` / `workload-identity` | `aks` / `workload-identity` |
| Identity | role ARN annotation (IRSA), or a Pod Identity association | `iam.gke.io/gcp-service-account` annotation, metadata server | `azure.workload.identity/client-id` annotation + pod label, token exchanged at Entra ID |
| Link-local egress opened | none (IRSA); `169.254.170.23`, `fd00:ec2::23` port 80 (Pod Identity) | `169.254.169.254` 80/988, `169.254.169.252` 988 | none |
| Ingress | ALB, IP targets, health check `/api/health` | GCE Ingress + BackendConfig `/api/health` + ManagedCertificate | application routing (`webapprouting.kubernetes.azure.com`) |
| `web.trustedProxyHops` | 1 (the ALB appends one entry) | 2 (Google's load balancer appends two) | 1 (the add-on's NGINX; the Azure LB is layer 4) |
| SQLite storage class | `gp3` (create it) | `standard-rwo` | `managed-csi` |
| Database | RDS PostgreSQL | Cloud SQL (private IP) | Flexible Server |
| Secrets | Secrets Manager via ESO (IRSA) | Secret Manager via ESO (Workload Identity) | Key Vault via ESO (Workload ID) |

- `cloud.provider` keeps every other link-local address (IMDS included) blocked, and rendering
  fails when the identity it needs is missing (an IRSA role ARN, an AKS client ID) or contradicts it.
- `automountServiceAccountToken` stays false: the IRSA, Pod Identity and Workload ID webhooks add
  their own projected, audience-bound token volume, and GKE identifies the pod at its metadata server.
- IRSA, Entra ID and every cloud API are reached on 443 through `engine.networkPolicy.internet`.
  Private endpoints (VPC interface endpoints, Private Service Connect, Key Vault private endpoints)
  have private addresses: allow them in `engine.networkPolicy.extraEgress`.
- With `engine.masterKey.kms` and an external database, the engine Secret's `master-key` holds the
  KMS-wrapped key, so every replica unwraps the same one.

## Examples

### On-prem

PostgreSQL you run, secrets from HashiCorp Vault (Kubernetes auth), MinIO for artifacts,
ingress-nginx restricted to the admin network.

```yaml
database:
  type: postgresql
  url: postgresql://farrier@pg.db.internal:5432/farrier?sslmode=verify-full&sslrootcert=/etc/farrier/db-tls/ca.crt
  tls: { existingSecret: pg-ca }
secrets:
  mode: existingSecret
  existingSecret: { engine: farrier-engine, web: farrier-web }
engine:
  replicaCount: 3
  secretBackend:
    type: hashicorp
    hashicorp: { addr: https://vault.internal:8200, mount: secret, role: farrier }
  storage: { url: s3://farrier/artifacts, s3Endpoint: https://minio.internal:9000 }
  deviceSecrets: { existingSecret: farrier-device-secrets }
  persistence: { storageClass: ceph-rbd }
  networkPolicy:
    database: { cidrs: [10.20.0.10/32] }
    managementNetworks:
      - { cidr: 10.50.0.0/16, ports: [443, 8443, 22] }
    extraEgress:
      - to: [{ ipBlock: { cidr: 10.10.0.20/32 } }]   # Vault and MinIO
        ports: [{ port: 8200, protocol: TCP }, { port: 9000, protocol: TCP }]
web:
  ingress:
    enabled: true
    className: nginx
    annotations:
      nginx.ingress.kubernetes.io/whitelist-source-range: 10.0.0.0/8
    hosts: [{ host: farrier.corp.internal, paths: [{ path: /, pathType: Prefix }] }]
    tls: [{ secretName: farrier-web-tls, hosts: [farrier.corp.internal] }]
  networkPolicy:
    ingressFrom:
      - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: ingress-nginx } }
```

Setting `secretBackend.hashicorp.role` mounts the engine's service-account token (the only case
where the chart does) so it can log in with Vault's Kubernetes auth.

### SQLite (single node)

```yaml
database: { type: sqlite }
secrets:
  mode: existingSecret
  existingSecret: { engine: farrier-engine, web: farrier-web }
engine:
  persistence: { size: 5Gi, storageClass: gp3 }
```

`engine.replicaCount` above 1 with SQLite fails rendering: SQLite has exactly one writer. Back up
the PVC daily.

## Monitoring

With the Prometheus Operator, turn on the scrape, the alerts and the dashboard together:

```yaml
engine:
  metrics:
    serviceMonitor: {enabled: true, labels: {release: kube-prometheus-stack}}
    prometheusRule: {enabled: true, labels: {release: kube-prometheus-stack}}
    grafanaDashboard: {enabled: true}          # ConfigMap labelled grafana_dashboard: "1"
```

The ServiceMonitor sets `honorLabels: true` so Farrier's `endpoint` label (the inventory endpoint) is kept.
The alerts are FarrierCertificateExpiringNoRenewal, FarrierCertificateExpired, FarrierRenewalFailed
(labelled with the reason code), FarrierApprovalsOverdue, FarrierRunnerGroupOffline and FarrierAuditLogBroken;
the troubleshooting guide (https://farrier-erc1.vercel.app/docs/troubleshooting) says what to do for each. The dashboard
JSON is `dashboards/farrier.json` in the chart, for importing by hand.

## Rendering checks without a cluster

```bash
python deploy/helm/farrier/ci/check.py          # YAML, schema, must-fail inputs, template balance
helm lint deploy/helm/farrier -f deploy/helm/farrier/ci/values-sqlite.yaml
helm template t deploy/helm/farrier -n farrier -f deploy/helm/farrier/ci/values-sqlite.yaml
```

## Values

`values.schema.json` validates every value (types, enums, patterns, ranges) and rejects unknown
keys; cross-field rules (SQLite with several replicas, a password in `database.url`, Ingress and
HTTPRoute together, missing secret references) fail rendering with a message naming the value to set.

| Key | Default | Description |
|---|---|---|
| `global.imageRegistry` | `""` | Registry prepended to every image repository, overriding each image's own registry (for a pull-through cache or an air-gapped mirror). Empty keeps the per-image registry. |
| `global.imagePullSecrets` | `[]` | Pull secrets for every pod in the chart, e.g. [{name: regcred}]. |
| `nameOverride` | `""` | Override the chart name used in resource names and the app.kubernetes.io/name label. |
| `fullnameOverride` | `""` | Override the full release-qualified name (default: <release>-farrier, or <release> if it already contains "farrier"). |
| `commonLabels` | `{}` | Labels added to every resource the chart renders. |
| `commonAnnotations` | `{}` | Annotations added to every resource the chart renders. |
| `clusterDomain` | `"cluster.local"` | Cluster DNS domain, used to build the engine URL the dashboard calls. |
| `extraObjects` | `[]` | Extra manifests rendered with the release (e.g. a GKE BackendConfig and ManagedCertificate). |
| `cloud.provider` | `"none"` | none \| eks \| gke \| aks: opens exactly the link-local endpoint that provider's workload identity needs. |
| `cloud.identity` | `""` | eks: irsa (default) or pod-identity; gke, aks: workload-identity (default). Empty with provider none. |
| `database.type` | `"sqlite"` | sqlite \| postgresql \| mysql. sqlite: the engine runs as a single-replica StatefulSet with its database on a PVC. postgresql/mysql: the engine runs as a Deployment with several replicas; one leader runs the renewal loop (advisory lock / GET_LOCK), every replica serves the API. |
| `database.url` | `""` | Connection URL for postgresql/mysql, WITHOUT a password (the engine refuses one in the URL). Use sslmode=verify-full in production, e.g. postgresql://farrier@db.internal:5432/farrier?sslmode=verify-full&sslrootcert=/etc/farrier/db-tls/ca.crt Do not route through PgBouncer in transaction-pooling mode: the leader lock lives on a session. |
| `database.tls.existingSecret` | `""` | Name of an existing Secret with the database CA (and optional client cert/key), mounted read-only at /etc/farrier/db-tls. Reference the files from the URL (sslrootcert=...). |
| `secrets.mode` | `"existingSecret"` | Where the Secrets come from: existingSecret   you create the Secrets (recommended for production; e.g. from your CD pipeline, sealed-secrets or the Secrets Store CSI driver). externalSecrets  the chart renders ExternalSecret objects for the External Secrets Operator, which syncs them from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, ... create           the chart renders a Secret from the values below. DEVELOPMENT ONLY: the values end up in your values files and in the Helm release secret. |
| `secrets.keys.apiToken` | `"api-token"` | Engine admin token (FARRIER_API_TOKEN, engine + web). Required. |
| `secrets.keys.apiReadToken` | `"api-read-token"` | Engine read-only token (FARRIER_API_READ_TOKEN, engine + web + ServiceMonitor). Optional in existingSecret mode; SSO viewers and Prometheus use it. |
| `secrets.keys.masterKey` | `"master-key"` | Fernet master key sealing private keys (FARRIER_MASTER_KEY, engine). With engine.masterKey.kms it holds the KMS-wrapped key instead (optional with sqlite). |
| `secrets.keys.databasePassword` | `"database-password"` | Database password (engine, mounted as a file). Not needed for sqlite. |
| `secrets.keys.dashboardPassword` | `"dashboard-password"` | Dashboard Basic-auth password (FARRIER_DASHBOARD_PASSWORD, web, web.auth.mode=basic). |
| `secrets.keys.oidcClientSecret` | `"oidc-client-secret"` | OIDC client secret (FARRIER_OIDC_CLIENT_SECRET, web, web.auth.mode=oidc). |
| `secrets.keys.sessionSecret` | `"session-secret"` | Session cookie encryption key, 32+ random bytes (FARRIER_SESSION_SECRET, web, oidc). |
| `secrets.existingSecret.engine` | `""` | Secret holding the engine keys (apiToken, apiReadToken, masterKey, databasePassword). Required when mode=existingSecret. |
| `secrets.existingSecret.web` | `""` | Secret holding the web keys (apiToken, apiReadToken, and dashboardPassword or oidcClientSecret + sessionSecret). May be the same Secret as the engine's, but a separate one keeps the master key and database password out of the web pods' reach. |
| `secrets.externalSecrets.apiVersion` | `"external-secrets.io/v1"` | ExternalSecret API version. external-secrets.io/v1 needs ESO >= 0.17; use external-secrets.io/v1beta1 for older operators. |
| `secrets.externalSecrets.refreshInterval` | `"1h"` | How often ESO re-reads the remote secrets. |
| `secrets.externalSecrets.secretStoreRef.name` | `""` | Name of the SecretStore / ClusterSecretStore to read from. Required in this mode. |
| `secrets.externalSecrets.secretStoreRef.kind` | `"ClusterSecretStore"` | SecretStore (namespaced) or ClusterSecretStore. |
| `secrets.externalSecrets.remoteRefs` | `{"apiToken": {"key": "", "property": ""}, "apiReadToken":...` | Remote references per logical key: {key, property, version}. `key` is the secret's name/path in the remote store; `property` selects a JSON field inside it. Only the keys the current configuration needs are rendered, and those must have a `key`. |
| `secrets.create` | `{"apiToken": "", "apiReadToken": "", "masterKey": "", "da...` | Values for mode=create (DEVELOPMENT ONLY). Empty tokens, master key, dashboard password and session secret are generated once and kept across upgrades (looked up from the live Secret). databasePassword and oidcClientSecret must be given when they are needed. |
| `engine.replicaCount` | `null` | Engine replicas. Empty means 2 with postgresql/mysql and 1 with sqlite. With sqlite it must be 1: rendering fails otherwise (SQLite has exactly one writer). |
| `engine.image.registry` | `"ghcr.io"` | Image registry (overridden by global.imageRegistry). |
| `engine.image.repository` | `"gagankarthik/farrier"` | Image repository. |
| `engine.image.tag` | `""` | Image tag. Empty uses the chart's appVersion. |
| `engine.image.digest` | `""` | Image digest (sha256:...). When set the image is pinned as repository:tag@digest. |
| `engine.image.pullPolicy` | `"IfNotPresent"` | Image pull policy. |
| `engine.shutdownGrace` | `20` | Seconds the engine drains requests on SIGTERM (`serve --grace`); the running renewal tick gets as long again. terminationGracePeriodSeconds is max(grace + 25, 2 * grace + 5). |
| `engine.tickSeconds` | `300` | Seconds between scan/plan/advance cycles (`serve --tick`). |
| `engine.leaderKey` | `""` | FARRIER_LEADER_KEY: separates two Farrier installs that share one database server. Empty keeps the engine default. |
| `engine.masterKey.kms` | `""` | FARRIER_MASTER_KEY_KMS: wrap the master key with a cloud KMS instead of reading it from a Secret: aws-kms:<key arn> \| gcp-kms:<key resource name> \| azure-kv:<key url>. Needs a cloud identity (serviceAccount). With postgresql/mysql the masterKey Secret key must hold the wrapped key so every replica unwraps the same one; with sqlite it may be left out (generated and kept wrapped on the PVC). |
| `engine.secretBackend.type` | `"local"` | Where the engine stores credentials entered in the dashboard: local \| aws \| gcp \| azure \| hashicorp (FARRIER_SECRET_BACKEND). |
| `engine.secretBackend.aws.region` | `""` | FARRIER_SECRET_AWS_REGION. |
| `engine.secretBackend.aws.prefix` | `"farrier/"` | FARRIER_SECRET_AWS_PREFIX: name prefix for secrets Farrier creates. |
| `engine.secretBackend.gcp.project` | `""` | FARRIER_SECRET_GCP_PROJECT. |
| `engine.secretBackend.azure.vaultUrl` | `""` | FARRIER_SECRET_AZURE_VAULT_URL, e.g. https://my-vault.vault.azure.net. |
| `engine.secretBackend.hashicorp.addr` | `""` | FARRIER_SECRET_VAULT_ADDR, e.g. https://vault.vault.svc:8200. |
| `engine.secretBackend.hashicorp.mount` | `"secret"` | FARRIER_SECRET_VAULT_MOUNT: KV v2 mount. |
| `engine.secretBackend.hashicorp.role` | `""` | FARRIER_SECRET_VAULT_ROLE: Kubernetes-auth role. When set, the engine's service account token is mounted so the engine can log in to Vault. |
| `engine.storage.url` | `""` | FARRIER_STORAGE_URL: where change packs and artifacts live: file:///... \| s3://bucket/prefix \| gs://bucket/prefix \| azblob://container/prefix. Empty keeps them in the data directory, which with several replicas is per-pod (emptyDir): use object storage there. |
| `engine.storage.s3Endpoint` | `""` | FARRIER_STORAGE_S3_ENDPOINT: S3-compatible endpoint (MinIO, Ceph) for s3:// URLs. |
| `engine.storage.kmsKey` | `""` | FARRIER_STORAGE_KMS_KEY: KMS key for server-side encryption of stored objects. |
| `engine.deviceSecrets.existingSecret` | `""` | Existing Secret with device/DNS/notifier credentials, mounted read-only at /run/secrets/farrier. Reference them from connector configs as file:/run/secrets/farrier/<key>. FARRIER_SECRET_DIRS is set to that directory. |
| `engine.secretEnvPrefix` | `"FARRIER_SECRET_"` | FARRIER_SECRET_ENV_PREFIX: connector configs may only read env vars with this prefix. |
| `engine.config` | `{}` | Extra non-secret settings rendered into the engine ConfigMap as env vars (e.g. FARRIER_TRUST_BUNDLE). Never put secrets here: use extraEnv with secretKeyRef. |
| `engine.extraEnv` | `[]` | Extra env vars (full EnvVar objects, valueFrom allowed). |
| `engine.extraEnvFrom` | `[]` | Extra envFrom sources, e.g. [{secretRef: {name: farrier-device-env}}]. |
| `engine.extraVolumes` | `[]` | Extra volumes for the engine pod. |
| `engine.extraVolumeMounts` | `[]` | Extra volume mounts for the engine container. |
| `engine.persistence.size` | `"2Gi"` | sqlite only: size of the PVC holding the database, sealed keys and change packs. |
| `engine.persistence.storageClass` | `""` | Storage class (block storage, never NFS/EFS/Azure Files). Empty uses the cluster default. EKS: gp3 (create it); GKE: standard-rwo; AKS: managed-csi. |
| `engine.persistence.accessModes` | `["ReadWriteOnce"]` | PVC access modes. |
| `engine.persistence.annotations` | `{}` | Annotations on the PVC template. |
| `engine.dataSizeLimit` | `"1Gi"` | Size limit of the data emptyDir used with postgresql/mysql. |
| `engine.resources` | `{"requests": {"cpu": "100m", "memory": "192Mi"}, "limits"...` | Requests and limits. No CPU limit by default (avoids throttling a latency-sensitive API). |
| `engine.probes.startup` | `{"enabled": true, "periodSeconds": 5, "timeoutSeconds": 3...` | Startup probe: allows up to failureThreshold * periodSeconds for migrations on first start. |
| `engine.probes.liveness` | `{"enabled": true, "periodSeconds": 20, "timeoutSeconds": ...` | Liveness probe on /healthz (which also checks the database). |
| `engine.probes.readiness` | `{"enabled": true, "periodSeconds": 10, "timeoutSeconds": ...` | Readiness probe on /healthz. |
| `engine.service.port` | `8740` | Engine Service port (ClusterIP only; the engine is never exposed outside the cluster). |
| `engine.service.annotations` | `{}` | Service annotations. |
| `engine.serviceAccount.create` | `true` | Create a ServiceAccount for the engine. |
| `engine.serviceAccount.name` | `""` | Name of the ServiceAccount (generated when empty and create is true; "default" when create is false and empty). |
| `engine.serviceAccount.annotations` | `{}` | Extra ServiceAccount annotations. |
| `engine.serviceAccount.automountToken` | `false` | Mount the Kubernetes API token into the pod. IRSA, EKS Pod Identity, GKE and Azure Workload Identity do not need it. Forced on when secretBackend.hashicorp.role is set. |
| `engine.serviceAccount.cloudIdentity.awsRoleArn` | `""` | AWS IRSA: IAM role ARN (eks.amazonaws.com/role-arn). |
| `engine.serviceAccount.cloudIdentity.gcpServiceAccount` | `""` | GKE Workload Identity: GCP service account email (iam.gke.io/gcp-service-account). |
| `engine.serviceAccount.cloudIdentity.azureClientId` | `""` | Azure Workload Identity: managed identity client ID (azure.workload.identity/client-id); also labels the pods azure.workload.identity/use: "true". |
| `engine.podSecurityContext` | `{"runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": ...` | Pod-level security context (restricted Pod Security Standard). |
| `engine.containerSecurityContext` | `{"runAsNonRoot": true, "allowPrivilegeEscalation": false,...` | Container-level security context. |
| `engine.pdb.enabled` | `true` | Render a PodDisruptionBudget (only when more than one replica runs). |
| `engine.pdb.minAvailable` | `1` | minAvailable (ignored when maxUnavailable is set). |
| `engine.pdb.maxUnavailable` | `null` | maxUnavailable; overrides minAvailable when set. |
| `engine.defaultTopologySpread` | `true` | Spread replicas across zones and nodes (ScheduleAnyway) when topologySpreadConstraints is empty. |
| `engine.topologySpreadConstraints` | `[]` | Explicit topologySpreadConstraints; replaces the default spread. |
| `engine.podAnnotations` | `{}` | Pod annotations. |
| `engine.podLabels` | `{}` | Pod labels. |
| `engine.nodeSelector` | `{}` | Node selector. |
| `engine.tolerations` | `[]` | Tolerations. |
| `engine.affinity` | `{}` | Affinity. |
| `engine.priorityClassName` | `""` | PriorityClass name. |
| `engine.revisionHistoryLimit` | `5` | Old ReplicaSets/revisions to keep. |
| `engine.networkPolicy.metricsNamespaceSelector` | `{}` | Namespace labels allowed to scrape /metrics on 8740 (e.g. {kubernetes.io/metadata.name: monitoring}). Empty disables the rule (ServiceMonitor scrapes then need it). |
| `engine.networkPolicy.metricsPodSelector` | `{}` | Pod labels (within metricsNamespaceSelector) allowed to scrape, e.g. {app.kubernetes.io/name: prometheus}. |
| `engine.networkPolicy.database.cidrs` | `[]` | CIDRs of the database (postgresql/mysql). Required when networkPolicy is enabled with an external database, e.g. ["10.20.0.0/24"]. |
| `engine.networkPolicy.database.port` | `null` | Database port (5432 PostgreSQL, 3306 MySQL). Empty picks by database.type. |
| `engine.networkPolicy.managementNetworks` | `[]` | Device management networks the engine deploys certificates to: CIDRs and ports, e.g. [{cidr: 10.50.0.0/16, ports: [443, 8443, 22]}]. |
| `engine.networkPolicy.internet.enabled` | `true` | Allow 443 to the internet (CA ACME directories, DNS-provider APIs, cloud secret stores, notifiers). |
| `engine.networkPolicy.internet.cidr` | `"0.0.0.0/0"` | Destination CIDR for the internet rule. |
| `engine.networkPolicy.internet.except` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.25...` | Excluded ranges: private networks (reach them via managementNetworks; cloud private endpoints via extraEgress) and link-local, which holds the node metadata services (cloud.provider opens only what workload identity needs). |
| `engine.networkPolicy.internet.ports` | `[443]` | Ports allowed to the internet. |
| `engine.networkPolicy.extraEgress` | `[]` | Extra raw egress rules (NetworkPolicyEgressRule), e.g. in-cluster Vault, VPC/private endpoints of cloud APIs, NodeLocal DNSCache (169.254.20.10/32 port 53) or an internal ACME CA. |
| `engine.metrics.serviceMonitor.enabled` | `false` | Render a Prometheus Operator ServiceMonitor for /metrics, authenticated with the read-only token (apiReadToken) from the engine Secret. |
| `engine.metrics.serviceMonitor.interval` | `"60s"` | Scrape interval. |
| `engine.metrics.serviceMonitor.scrapeTimeout` | `"10s"` | Scrape timeout. |
| `engine.metrics.serviceMonitor.labels` | `{}` | Extra labels (e.g. the release label your Prometheus selects on). |
| `engine.metrics.serviceMonitor.metricRelabelings` | `[]` | Metric relabelings. |
| `engine.metrics.prometheusRule.enabled` | `false` | Render a Prometheus Operator PrometheusRule with ready-made alerts: certificate expiring with no open renewal, certificate expired, renewal failed (by reason code), approvals overdue, runner group offline, audit log broken. |
| `engine.metrics.prometheusRule.expiringDays` | `7` | FarrierCertificateExpiringNoRenewal fires when fewer days than this are left. |
| `engine.metrics.prometheusRule.labels` | `{}` | Extra labels (e.g. the release label your Prometheus selects rules on). |
| `engine.metrics.prometheusRule.additionalRules` | `[]` | Extra alerting or recording rules appended to the farrier group. |
| `engine.metrics.grafanaDashboard.enabled` | `false` | Ship the Farrier Grafana dashboard as a ConfigMap for the Grafana sidecar. |
| `engine.metrics.grafanaDashboard.labels` | `{"grafana_dashboard": "1"}` | Labels the Grafana sidecar selects dashboards by. |
| `engine.metrics.grafanaDashboard.annotations` | `{}` | Annotations, e.g. {grafana_folder: Certificates} for the sidecar's folder annotation. |
| `web.enabled` | `true` | Deploy the dashboard. |
| `web.replicaCount` | `2` | Replicas (ignored when autoscaling is enabled). |
| `web.image.registry` | `"ghcr.io"` | Image registry (overridden by global.imageRegistry). |
| `web.image.repository` | `"gagankarthik/farrier-web"` | Image repository. |
| `web.image.tag` | `""` | Image tag. Empty uses the chart's appVersion. |
| `web.image.digest` | `""` | Image digest (sha256:...). |
| `web.image.pullPolicy` | `"IfNotPresent"` | Image pull policy. |
| `web.siteUrl` | `""` | Public URL of the dashboard (NEXT_PUBLIC_SITE_URL). Empty derives https://<first host> from the Ingress or HTTPRoute. Use https:// to turn on HSTS and __Host- cookies. |
| `web.trustedProxyHops` | `1` | FARRIER_TRUSTED_PROXY_HOPS: X-Forwarded-For entries your own proxies append (1 = one Ingress/Gateway, 2 = a CDN or cloud LB in front of it, 0 = ignore the header). |
| `web.apiUrl` | `""` | FARRIER_API_URL override. Empty uses the engine Service: http://<engine>.<namespace>.svc.<clusterDomain>:<port>. |
| `web.auth.mode` | `"basic"` | basic (FARRIER_DASHBOARD_PASSWORD, one shared admin login) or oidc (single sign-on with viewer/operator/admin roles). A production dashboard refuses to run with neither. |
| `web.auth.basic.user` | `"admin"` | FARRIER_DASHBOARD_USER. |
| `web.auth.oidc.issuer` | `""` | FARRIER_OIDC_ISSUER, e.g. https://example.okta.com/oauth2/default. Required for oidc. |
| `web.auth.oidc.clientId` | `""` | FARRIER_OIDC_CLIENT_ID. Required for oidc. |
| `web.auth.oidc.scopes` | `"openid profile email groups"` | FARRIER_OIDC_SCOPES. Google and Entra ID reject "groups": use "openid profile email". |
| `web.auth.oidc.roleClaim` | `"groups"` | FARRIER_OIDC_ROLE_CLAIM (dotted paths work; Entra app roles: roles). |
| `web.auth.oidc.adminGroups` | `""` | FARRIER_OIDC_ADMIN_GROUPS, comma-separated. |
| `web.auth.oidc.operatorGroups` | `""` | FARRIER_OIDC_OPERATOR_GROUPS, comma-separated. |
| `web.auth.oidc.allowedGroups` | `""` | FARRIER_OIDC_ALLOWED_GROUPS: refuse anyone outside these (and admin/operator) groups. |
| `web.auth.oidc.redirectUri` | `""` | FARRIER_OIDC_REDIRECT_URI (required in production). Empty uses <siteUrl>/auth/callback; register exactly this URL with the identity provider. |
| `web.auth.oidc.postLogoutRedirectUri` | `""` | FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI. Empty derives it from the request. |
| `web.auth.oidc.sessionIdleMinutes` | `60` | FARRIER_SESSION_IDLE_MINUTES. |
| `web.auth.oidc.sessionMaxHours` | `12` | FARRIER_SESSION_MAX_HOURS. |
| `web.config` | `{}` | Extra non-secret settings rendered into the web ConfigMap as env vars. |
| `web.extraEnv` | `[]` | Extra env vars (full EnvVar objects, valueFrom allowed). |
| `web.extraEnvFrom` | `[]` | Extra envFrom sources. |
| `web.extraVolumes` | `[]` | Extra volumes for the web pod. |
| `web.extraVolumeMounts` | `[]` | Extra volume mounts for the web container. |
| `web.resources` | `{"requests": {"cpu": "50m", "memory": "128Mi"}, "limits":...` | Requests and limits. |
| `web.probes.startup` | `{"enabled": true, "periodSeconds": 5, "timeoutSeconds": 3...` | Startup probe on /api/health. |
| `web.probes.liveness` | `{"enabled": true, "periodSeconds": 20, "timeoutSeconds": ...` | Liveness probe on /api/health. |
| `web.probes.readiness` | `{"enabled": true, "periodSeconds": 10, "timeoutSeconds": ...` | Readiness probe on /api/health. |
| `web.service.type` | `"ClusterIP"` | Service type. Prefer ClusterIP behind an Ingress or Gateway. |
| `web.service.port` | `80` | Service port. |
| `web.service.annotations` | `{}` | Service annotations (e.g. cloud LB settings when type is LoadBalancer). |
| `web.ingress.enabled` | `false` | Render an Ingress. Mutually exclusive with httpRoute. |
| `web.ingress.className` | `""` | IngressClass name (nginx, alb, gce, azure-application-gateway, ...). |
| `web.ingress.annotations` | `{}` | Ingress annotations (TLS redirect, source-range allowlists, SSO, ...). |
| `web.ingress.hosts` | `[{"host": "farrier.example.com", "paths": [{"path": "/", ...` | Hosts and paths. |
| `web.ingress.tls` | `[]` | TLS, e.g. [{secretName: farrier-web-tls, hosts: [farrier.example.com]}]. |
| `web.httpRoute.enabled` | `false` | Render a Gateway API HTTPRoute. Mutually exclusive with ingress. |
| `web.httpRoute.annotations` | `{}` | HTTPRoute annotations. |
| `web.httpRoute.labels` | `{}` | HTTPRoute labels. |
| `web.httpRoute.parentRefs` | `[]` | Gateways to attach to, e.g. [{name: public, namespace: gateway, sectionName: https}]. |
| `web.httpRoute.hostnames` | `["farrier.example.com"]` | Hostnames. |
| `web.httpRoute.pathPrefix` | `"/"` | Path prefix routed to the dashboard. |
| `web.autoscaling.enabled` | `false` | Render a HorizontalPodAutoscaler (autoscaling/v2). |
| `web.autoscaling.minReplicas` | `2` | Minimum replicas. |
| `web.autoscaling.maxReplicas` | `6` | Maximum replicas. |
| `web.autoscaling.targetCPUUtilizationPercentage` | `75` | Target average CPU utilization (% of requests). null disables the metric. |
| `web.autoscaling.targetMemoryUtilizationPercentage` | `80` | Target average memory utilization (% of requests). null disables the metric. |
| `web.serviceAccount.create` | `true` | Create a ServiceAccount for the dashboard. |
| `web.serviceAccount.name` | `""` | Name of the ServiceAccount. |
| `web.serviceAccount.annotations` | `{}` | Extra ServiceAccount annotations. |
| `web.serviceAccount.automountToken` | `false` | Mount the Kubernetes API token. The dashboard never calls the Kubernetes API. |
| `web.serviceAccount.cloudIdentity.awsRoleArn` | `""` | AWS IRSA role ARN. |
| `web.serviceAccount.cloudIdentity.gcpServiceAccount` | `""` | GKE Workload Identity service account. |
| `web.serviceAccount.cloudIdentity.azureClientId` | `""` | Azure Workload Identity client ID. |
| `web.podSecurityContext` | `{"runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": ...` | Pod-level security context (the web image runs as UID/GID 10001). |
| `web.containerSecurityContext` | `{"runAsNonRoot": true, "allowPrivilegeEscalation": false,...` | Container-level security context. |
| `web.pdb.enabled` | `true` | Render a PodDisruptionBudget (only when more than one replica can run). |
| `web.pdb.minAvailable` | `1` | minAvailable (ignored when maxUnavailable is set). |
| `web.pdb.maxUnavailable` | `null` | maxUnavailable; overrides minAvailable when set. |
| `web.defaultTopologySpread` | `true` | Spread replicas across zones and nodes (ScheduleAnyway) when topologySpreadConstraints is empty. |
| `web.topologySpreadConstraints` | `[]` | Explicit topologySpreadConstraints; replaces the default spread. |
| `web.podAnnotations` | `{}` | Pod annotations. |
| `web.podLabels` | `{}` | Pod labels. |
| `web.nodeSelector` | `{}` | Node selector. |
| `web.tolerations` | `[]` | Tolerations. |
| `web.affinity` | `{}` | Affinity. |
| `web.priorityClassName` | `""` | PriorityClass name. |
| `web.revisionHistoryLimit` | `5` | Old ReplicaSets to keep. |
| `web.terminationGracePeriodSeconds` | `30` | Seconds the dashboard gets to finish requests on shutdown. |
| `web.networkPolicy.ingressFrom` | `[]` | Peers allowed to reach the dashboard on 3000 (NetworkPolicyPeer list), e.g. your ingress controller's namespace. Empty allows any source on port 3000 only. |
| `web.networkPolicy.idp.enabled` | `true` | Allow 443 egress to the identity provider (oidc mode). |
| `web.networkPolicy.idp.cidrs` | `["0.0.0.0/0"]` | IdP CIDRs. The default is the internet without private ranges; narrow it, or add your internal IdP's range. |
| `web.networkPolicy.idp.except` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.25...` | Ranges excluded from each IdP CIDR. |
| `web.networkPolicy.extraEgress` | `[]` | Extra raw egress rules (NetworkPolicyEgressRule). |
| `networkPolicy.enabled` | `true` | Render NetworkPolicies for engine and web (default-deny with the allowances above). |
| `tests.enabled` | `true` | Render the `helm test` pod (curls the dashboard / and the engine /healthz). |
| `tests.image.registry` | `"docker.io"` | Test image registry. |
| `tests.image.repository` | `"curlimages/curl"` | Test image repository (needs curl, runs as non-root UID 100). |
| `tests.image.tag` | `"8.11.1"` | Test image tag. |
| `tests.image.digest` | `""` | Test image digest. |
| `tests.image.pullPolicy` | `"IfNotPresent"` | Pull policy. |
