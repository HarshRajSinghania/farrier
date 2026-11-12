{{/*
Named templates shared by the engine and the web components.

Most templates take a "component context": (dict "ctx" $ "component" "engine"|"web"), where
$ is the root context. Component values are read with (index .ctx.Values .component), so the
engine and the web are built from the same templates with different inputs.
*/}}

{{/* ---------------------------------------------------------------- names */}}

{{/* Chart name, overridable with nameOverride. */}}
{{- define "farrier.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release-qualified name, at most 63 characters. */}}
{{- define "farrier.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Component name: <fullname>-<component>. Input: component context. */}}
{{- define "farrier.componentName" -}}
{{- printf "%s-%s" (include "farrier.fullname" .ctx | trunc 55 | trimSuffix "-") .component -}}
{{- end -}}

{{/* chart label value. */}}
{{- define "farrier.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* ---------------------------------------------------------------- labels */}}

{{/* Selector labels (immutable on workloads). Input: component context; component may be "". */}}
{{- define "farrier.selectorLabels" -}}
app.kubernetes.io/name: {{ include "farrier.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
{{- with .component }}
app.kubernetes.io/component: {{ . }}
{{- end }}
{{- end -}}

{{/* Full recommended label set. Input: component context. */}}
{{- define "farrier.labels" -}}
helm.sh/chart: {{ include "farrier.chart" .ctx }}
{{ include "farrier.selectorLabels" . }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: farrier
{{- with .ctx.Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Object metadata: name, namespace, labels, annotations (commonAnnotations + .annotations).
Input: component context, optionally with "name" (defaults to the component name), "labels"
and "annotations".
*/}}
{{- define "farrier.metadata" -}}
name: {{ get . "name" | default (include "farrier.componentName" .) }}
namespace: {{ .ctx.Release.Namespace | quote }}
labels:
  {{- include "farrier.labels" . | nindent 2 }}
  {{- with get . "labels" }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- $annotations := merge (dict) (get . "annotations" | default dict) .ctx.Values.commonAnnotations }}
{{- with $annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------- images */}}

{{/*
Image reference: [registry/]repository:tag[@digest]. The tag defaults to the chart appVersion;
global.imageRegistry overrides the per-image registry. Input: (dict "ctx" $ "image" <image values>).
*/}}
{{- define "farrier.image" -}}
{{- $registry := coalesce .ctx.Values.global.imageRegistry .image.registry -}}
{{- $repository := .image.repository -}}
{{- if $registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" $registry) .image.repository -}}
{{- end -}}
{{- $tag := default .ctx.Chart.AppVersion .image.tag | toString -}}
{{- if .image.digest -}}
{{- printf "%s:%s@%s" $repository $tag .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{/* ---------------------------------------------------------------- security contexts */}}

{{/*
Pod security context: the restricted baseline, overlaid with the component's podSecurityContext.
Input: component values.
*/}}
{{- define "farrier.podSecurityContext" -}}
{{- $baseline := dict "runAsNonRoot" true "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- toYaml (mustMergeOverwrite $baseline (deepCopy (.podSecurityContext | default dict))) -}}
{{- end -}}

{{/*
Container security context: the restricted baseline, overlaid with containerSecurityContext.
Input: component values.
*/}}
{{- define "farrier.containerSecurityContext" -}}
{{- $baseline := dict "runAsNonRoot" true "allowPrivilegeEscalation" false "readOnlyRootFilesystem" true "capabilities" (dict "drop" (list "ALL")) "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- toYaml (mustMergeOverwrite $baseline (deepCopy (.containerSecurityContext | default dict))) -}}
{{- end -}}

{{/* ---------------------------------------------------------------- service accounts */}}

{{/* ServiceAccount name. Input: component context. */}}
{{- define "farrier.serviceAccountName" -}}
{{- $sa := (index .ctx.Values .component).serviceAccount -}}
{{- if $sa.create -}}
{{- default (include "farrier.componentName" .) $sa.name -}}
{{- else -}}
{{- default "default" $sa.name -}}
{{- end -}}
{{- end -}}

{{/* ServiceAccount annotations: user annotations + cloud workload identity. Input: component values. */}}
{{- define "farrier.serviceAccountAnnotations" -}}
{{- $out := deepCopy (.serviceAccount.annotations | default dict) -}}
{{- with .serviceAccount.cloudIdentity -}}
{{- if .awsRoleArn }}{{ $_ := set $out "eks.amazonaws.com/role-arn" .awsRoleArn }}{{ end -}}
{{- if .gcpServiceAccount }}{{ $_ := set $out "iam.gke.io/gcp-service-account" .gcpServiceAccount }}{{ end -}}
{{- if .azureClientId }}{{ $_ := set $out "azure.workload.identity/client-id" .azureClientId }}{{ end -}}
{{- end -}}
{{- with $out }}{{ toYaml . }}{{ end -}}
{{- end -}}

{{/*
Whether to mount the Kubernetes API token. Off unless asked for, or the engine logs in to
HashiCorp Vault with Kubernetes auth. Input: component context.
*/}}
{{- define "farrier.automountToken" -}}
{{- $v := index .ctx.Values .component -}}
{{- $vault := and (eq .component "engine") (eq .ctx.Values.engine.secretBackend.type "hashicorp") .ctx.Values.engine.secretBackend.hashicorp.role -}}
{{- if or $v.serviceAccount.automountToken $vault }}true{{ else }}false{{ end -}}
{{- end -}}

{{/* ---------------------------------------------------------------- secrets */}}

{{/*
Secret keys a component needs, as a JSON list of {id, env, optional}. `id` names a key in
secrets.keys / remoteRefs / create; `env` is the variable it is injected as (none for the
database password, which is mounted as a file). Input: component context.
*/}}
{{- define "farrier.secretKeys" -}}
{{- $v := .ctx.Values -}}
{{- $readOptional := not (and (eq .component "engine") $v.engine.metrics.serviceMonitor.enabled) -}}
{{- $keys := list (dict "id" "apiToken" "env" "FARRIER_API_TOKEN" "optional" false) (dict "id" "apiReadToken" "env" "FARRIER_API_READ_TOKEN" "optional" $readOptional) -}}
{{- if eq .component "engine" -}}
{{- if not $v.engine.masterKey.kms -}}
{{- $keys = append $keys (dict "id" "masterKey" "env" "FARRIER_MASTER_KEY" "optional" false) -}}
{{- end -}}
{{- if ne $v.database.type "sqlite" -}}
{{- $keys = append $keys (dict "id" "databasePassword" "env" "" "optional" false) -}}
{{- end -}}
{{- else if eq $v.web.auth.mode "oidc" -}}
{{- $keys = append $keys (dict "id" "oidcClientSecret" "env" "FARRIER_OIDC_CLIENT_SECRET" "optional" false) -}}
{{- $keys = append $keys (dict "id" "sessionSecret" "env" "FARRIER_SESSION_SECRET" "optional" false) -}}
{{- else -}}
{{- $keys = append $keys (dict "id" "dashboardPassword" "env" "FARRIER_DASHBOARD_PASSWORD" "optional" false) -}}
{{- end -}}
{{- toJson $keys -}}
{{- end -}}

{{/*
Name of the Secret a component reads. existingSecret: the name you gave; externalSecrets: the
ExternalSecret target <fullname>-<component>; create: one shared Secret <fullname>.
Input: component context.
*/}}
{{- define "farrier.secretName" -}}
{{- $s := .ctx.Values.secrets -}}
{{- if eq $s.mode "existingSecret" -}}
{{- required (printf "secrets.existingSecret.%s is required when secrets.mode=existingSecret (the Secret holding the %s's keys)" .component .component) (index $s.existingSecret .component) -}}
{{- else if eq $s.mode "create" -}}
{{- include "farrier.fullname" .ctx -}}
{{- else -}}
{{- include "farrier.componentName" . -}}
{{- end -}}
{{- end -}}

{{/*
The dev-only Secret for secrets.mode=create, holding the union of both components' keys.
Values come from secrets.create, else the live Secret (so upgrades keep them), else are generated.
Input: root context.
*/}}
{{- define "farrier.secret.create" -}}
{{- $name := include "farrier.fullname" . -}}
{{- $previous := dig "data" (dict) (lookup "v1" "Secret" .Release.Namespace $name | default dict) -}}
{{- $ids := list -}}
{{- $components := list "engine" -}}
{{- if .Values.web.enabled }}{{ $components = append $components "web" }}{{ end -}}
{{- range $component := $components -}}
{{- range (include "farrier.secretKeys" (dict "ctx" $ "component" $component) | fromJsonArray) -}}
{{- $ids = append $ids .id -}}
{{- end -}}
{{- end -}}
{{- $data := dict -}}
{{- range $id := $ids | uniq -}}
{{- $key := index $.Values.secrets.keys $id -}}
{{- $value := index $.Values.secrets.create $id | default "" | toString -}}
{{- if not $value -}}
{{- with index $previous $key }}{{ $value = b64dec . }}{{ end -}}
{{- end -}}
{{- if not $value -}}
{{- if eq $id "masterKey" -}}
{{- $value = randBytes 32 | replace "+" "-" | replace "/" "_" -}}
{{- else if eq $id "sessionSecret" -}}
{{- $value = randBytes 48 -}}
{{- else if has $id (list "apiToken" "apiReadToken" "dashboardPassword") -}}
{{- $value = randAlphaNum 64 -}}
{{- else -}}
{{- $value = required (printf "secrets.create.%s is required with this configuration (it cannot be generated)" $id) "" -}}
{{- end -}}
{{- end -}}
{{- $_ := set $data $key ($value | b64enc) -}}
{{- end -}}
apiVersion: v1
kind: Secret
metadata:
  {{- include "farrier.metadata" (dict "ctx" . "component" "" "name" $name "annotations" (dict "helm.sh/resource-policy" "keep")) | nindent 2 }}
type: Opaque
data:
  {{- range $k, $v := $data }}
  {{ $k }}: {{ $v | quote }}
  {{- end }}
{{- end -}}

{{/* ExternalSecret for one component. Input: component context. */}}
{{- define "farrier.externalSecret" -}}
{{- $es := .ctx.Values.secrets.externalSecrets -}}
{{- $keys := .ctx.Values.secrets.keys -}}
apiVersion: {{ $es.apiVersion }}
kind: ExternalSecret
metadata:
  {{- include "farrier.metadata" . | nindent 2 }}
spec:
  refreshInterval: {{ $es.refreshInterval | quote }}
  secretStoreRef:
    name: {{ required "secrets.externalSecrets.secretStoreRef.name is required when secrets.mode=externalSecrets" $es.secretStoreRef.name | quote }}
    kind: {{ $es.secretStoreRef.kind }}
  target:
    name: {{ include "farrier.secretName" . }}
    creationPolicy: Owner
  data:
    {{- range (include "farrier.secretKeys" . | fromJsonArray) }}
    {{- $ref := index $es.remoteRefs .id | default dict }}
    {{- if or (get $ref "key") (not .optional) }}
    - secretKey: {{ index $keys .id | quote }}
      remoteRef:
        key: {{ required (printf "secrets.externalSecrets.remoteRefs.%s.key is required with this configuration" .id) (get $ref "key") | quote }}
        {{- with get $ref "property" }}
        property: {{ . | quote }}
        {{- end }}
        {{- with get $ref "version" }}
        version: {{ . | quote }}
        {{- end }}
    {{- end }}
    {{- end }}
{{- end -}}

{{/*
Hash that changes when a component's secret source changes, for the checksum/secret pod
annotation. In existingSecret mode only names and keys are known: rotate values with a restart
(or a reloader). Input: component context.
*/}}
{{- define "farrier.secretChecksum" -}}
{{- $s := .ctx.Values.secrets -}}
{{- if eq $s.mode "create" -}}
{{- include "farrier.secret.create" .ctx | sha256sum -}}
{{- else if eq $s.mode "externalSecrets" -}}
{{- include "farrier.externalSecret" . | sha256sum -}}
{{- else -}}
{{- list (include "farrier.secretName" .) $s.keys (include "farrier.secretKeys" .) | toJson | sha256sum -}}
{{- end -}}
{{- end -}}

{{/* ---------------------------------------------------------------- configuration */}}

{{/* Engine Service URL the dashboard calls. Input: root context. */}}
{{- define "farrier.engine.url" -}}
{{- printf "http://%s.%s.svc.%s:%v" (include "farrier.componentName" (dict "ctx" . "component" "engine")) .Release.Namespace .Values.clusterDomain .Values.engine.service.port -}}
{{- end -}}

{{/* Public dashboard URL: web.siteUrl, else https://<first Ingress/HTTPRoute host>. Input: root context. */}}
{{- define "farrier.web.siteUrl" -}}
{{- $w := .Values.web -}}
{{- if $w.siteUrl -}}
{{- $w.siteUrl -}}
{{- else if and $w.ingress.enabled $w.ingress.hosts -}}
{{- printf "https://%s" (first $w.ingress.hosts).host -}}
{{- else if and $w.httpRoute.enabled $w.httpRoute.hostnames -}}
{{- printf "https://%s" (first $w.httpRoute.hostnames) -}}
{{- end -}}
{{- end -}}

{{/* Engine non-secret settings, as a YAML map of env vars. Input: root context. */}}
{{- define "farrier.engine.configData" -}}
{{- $e := .Values.engine -}}
{{- $d := dict
  "FARRIER_DATA" "/var/lib/farrier"
  "FARRIER_SHUTDOWN_GRACE" ($e.shutdownGrace | toString)
  "FARRIER_SECRET_ENV_PREFIX" $e.secretEnvPrefix
  "FARRIER_SECRET_DIRS" "/run/secrets/farrier"
  "FARRIER_SECRET_BACKEND" $e.secretBackend.type -}}
{{- if ne .Values.database.type "sqlite" -}}
{{- $_ := set $d "FARRIER_DATABASE_URL" .Values.database.url -}}
{{- $_ := set $d "FARRIER_DATABASE_PASSWORD" "file:/run/secrets/farrier-db/password" -}}
{{- end -}}
{{- with $e.masterKey.kms }}{{ $_ := set $d "FARRIER_MASTER_KEY_KMS" . }}{{ end -}}
{{- with $e.leaderKey }}{{ $_ := set $d "FARRIER_LEADER_KEY" . }}{{ end -}}
{{- with include "farrier.web.siteUrl" . }}{{ $_ := set $d "FARRIER_DASHBOARD_URL" . }}{{ end -}}
{{- $b := $e.secretBackend -}}
{{- if eq $b.type "aws" -}}
{{- with $b.aws.region }}{{ $_ := set $d "FARRIER_SECRET_AWS_REGION" . }}{{ end -}}
{{- with $b.aws.prefix }}{{ $_ := set $d "FARRIER_SECRET_AWS_PREFIX" . }}{{ end -}}
{{- else if eq $b.type "gcp" -}}
{{- $_ := set $d "FARRIER_SECRET_GCP_PROJECT" (required "engine.secretBackend.gcp.project is required when secretBackend.type=gcp" $b.gcp.project) -}}
{{- else if eq $b.type "azure" -}}
{{- $_ := set $d "FARRIER_SECRET_AZURE_VAULT_URL" (required "engine.secretBackend.azure.vaultUrl is required when secretBackend.type=azure" $b.azure.vaultUrl) -}}
{{- else if eq $b.type "hashicorp" -}}
{{- $_ := set $d "FARRIER_SECRET_VAULT_ADDR" (required "engine.secretBackend.hashicorp.addr is required when secretBackend.type=hashicorp" $b.hashicorp.addr) -}}
{{- with $b.hashicorp.mount }}{{ $_ := set $d "FARRIER_SECRET_VAULT_MOUNT" . }}{{ end -}}
{{- with $b.hashicorp.role }}{{ $_ := set $d "FARRIER_SECRET_VAULT_ROLE" . }}{{ end -}}
{{- end -}}
{{- with $e.storage.url }}{{ $_ := set $d "FARRIER_STORAGE_URL" . }}{{ end -}}
{{- with $e.storage.s3Endpoint }}{{ $_ := set $d "FARRIER_STORAGE_S3_ENDPOINT" . }}{{ end -}}
{{- with $e.storage.kmsKey }}{{ $_ := set $d "FARRIER_STORAGE_KMS_KEY" . }}{{ end -}}
{{- toYaml (merge $d ($e.config | default dict)) -}}
{{- end -}}

{{/* Web non-secret settings, as a YAML map of env vars. Input: root context. */}}
{{- define "farrier.web.configData" -}}
{{- $w := .Values.web -}}
{{- $d := dict "FARRIER_API_URL" (default (include "farrier.engine.url" .) $w.apiUrl) -}}
{{- with include "farrier.web.siteUrl" . }}{{ $_ := set $d "NEXT_PUBLIC_SITE_URL" . }}{{ end -}}
{{- if eq $w.auth.mode "oidc" -}}
{{- $o := $w.auth.oidc -}}
{{- $_ := set $d "FARRIER_OIDC_ISSUER" (required "web.auth.oidc.issuer is required when web.auth.mode=oidc" $o.issuer) -}}
{{- $_ := set $d "FARRIER_OIDC_CLIENT_ID" (required "web.auth.oidc.clientId is required when web.auth.mode=oidc" $o.clientId) -}}
{{- $_ := set $d "FARRIER_OIDC_SCOPES" $o.scopes -}}
{{- $_ := set $d "FARRIER_OIDC_ROLE_CLAIM" $o.roleClaim -}}
{{- $_ := set $d "FARRIER_SESSION_IDLE_MINUTES" ($o.sessionIdleMinutes | toString) -}}
{{- $_ := set $d "FARRIER_SESSION_MAX_HOURS" ($o.sessionMaxHours | toString) -}}
{{- with $o.adminGroups }}{{ $_ := set $d "FARRIER_OIDC_ADMIN_GROUPS" . }}{{ end -}}
{{- with $o.operatorGroups }}{{ $_ := set $d "FARRIER_OIDC_OPERATOR_GROUPS" . }}{{ end -}}
{{- with $o.allowedGroups }}{{ $_ := set $d "FARRIER_OIDC_ALLOWED_GROUPS" . }}{{ end -}}
{{- with $o.redirectUri }}{{ $_ := set $d "FARRIER_OIDC_REDIRECT_URI" . }}{{ end -}}
{{- with $o.postLogoutRedirectUri }}{{ $_ := set $d "FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI" . }}{{ end -}}
{{- else -}}
{{- $_ := set $d "FARRIER_DASHBOARD_USER" $w.auth.basic.user -}}
{{- end -}}
{{- toYaml (merge $d ($w.config | default dict)) -}}
{{- end -}}

{{/* ConfigMap of a component's non-secret env. Input: component context. */}}
{{- define "farrier.configMap" -}}
{{- $data := include (printf "farrier.%s.configData" .component) .ctx | fromYaml -}}
apiVersion: v1
kind: ConfigMap
metadata:
  {{- include "farrier.metadata" . | nindent 2 }}
data:
  {{- range $k, $v := $data }}
  {{ $k }}: {{ $v | toString | quote }}
  {{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------- engine specifics */}}

{{/* Engine replicas: 1 for sqlite (fails on more), else replicaCount or 2. Input: root context. */}}
{{- define "farrier.engine.replicas" -}}
{{- $r := .Values.engine.replicaCount -}}
{{- if eq .Values.database.type "sqlite" -}}
{{- if and (not (kindIs "invalid" $r)) (gt (int $r) 1) -}}
{{- fail (printf "engine.replicaCount=%v but database.type=sqlite: SQLite has exactly one writer, so the engine runs one replica. Set database.type to postgresql or mysql (with database.url) to run several replicas, or leave engine.replicaCount empty." $r) -}}
{{- end -}}
1
{{- else if kindIs "invalid" $r -}}
2
{{- else -}}
{{- int $r -}}
{{- end -}}
{{- end -}}

{{/*
terminationGracePeriodSeconds: max(grace + 25, 2 * grace + 5). `serve` drains requests for
--grace seconds and then lets the running renewal tick finish within the same budget again.
Input: root context.
*/}}
{{- define "farrier.engine.terminationGrace" -}}
{{- $g := int .Values.engine.shutdownGrace -}}
{{- max (add $g 25) (add (mul $g 2) 5) -}}
{{- end -}}

{{/* ---------------------------------------------------------------- pod building blocks */}}

{{/*
Container env: fieldRef vars, secretKeyRef vars, then extraEnv. Secret values only ever arrive
by reference. Input: (dict "secretName" s "secretEnv" [{name,key,optional}] "fieldEnv" {NAME: path}
"extraEnv" [...]).
*/}}
{{- define "farrier.env" -}}
{{- range $name, $path := .fieldEnv }}
- name: {{ $name }}
  valueFrom:
    fieldRef:
      fieldPath: {{ $path }}
{{- end }}
{{- range .secretEnv }}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ $.secretName | quote }}
      key: {{ .key | quote }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end }}
{{- with .extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
startup/liveness/readiness probes over HTTP GET. Each probe is {enabled, ...probe fields}.
Input: (dict "probes" <probes values> "path" "/healthz" "port" "http").
*/}}
{{- define "farrier.probes" -}}
{{- $in := . -}}
{{- range $kind := list "startup" "liveness" "readiness" }}
{{- $p := index $in.probes $kind | default dict }}
{{- if $p.enabled }}
{{ $kind }}Probe:
  httpGet:
    path: {{ $in.path }}
    port: {{ $in.port }}
  {{- with omit $p "enabled" }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The application container. Input: component context plus
  port, healthPath, command (list), args (list), fieldEnv (map), volumeMounts (YAML string).
*/}}
{{- define "farrier.container" -}}
{{- $v := index .ctx.Values .component -}}
{{- $secretName := include "farrier.secretName" . -}}
{{- $secretEnv := list -}}
{{- range (include "farrier.secretKeys" . | fromJsonArray) -}}
{{- if .env -}}
{{- $secretEnv = append $secretEnv (dict "name" .env "key" (index $.ctx.Values.secrets.keys .id) "optional" .optional) -}}
{{- end -}}
{{- end -}}
- name: {{ .component }}
  image: {{ include "farrier.image" (dict "ctx" .ctx "image" $v.image) | quote }}
  imagePullPolicy: {{ $v.image.pullPolicy }}
  {{- with get . "command" }}
  command:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with get . "args" }}
  args:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  ports:
    - name: http
      containerPort: {{ .port }}
      protocol: TCP
  envFrom:
    - configMapRef:
        name: {{ include "farrier.componentName" . }}
    {{- with $v.extraEnvFrom }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with include "farrier.env" (dict "secretName" $secretName "secretEnv" $secretEnv "fieldEnv" (get . "fieldEnv" | default dict) "extraEnv" $v.extraEnv) | trim }}
  env:
    {{- . | nindent 4 }}
  {{- end }}
  {{- include "farrier.probes" (dict "probes" $v.probes "path" .healthPath "port" "http") | trim | nindent 2 }}
  resources:
    {{- toYaml $v.resources | nindent 4 }}
  securityContext:
    {{- include "farrier.containerSecurityContext" $v | nindent 4 }}
  volumeMounts:
    {{- .volumeMounts | trim | nindent 4 }}
    {{- with $v.extraVolumeMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
{{- end -}}

{{/*
Default topology spread: zones and nodes, ScheduleAnyway, unless topologySpreadConstraints is set.
Input: component context.
*/}}
{{- define "farrier.topologySpread" -}}
{{- $v := index .ctx.Values .component -}}
{{- if $v.topologySpreadConstraints -}}
{{- toYaml $v.topologySpreadConstraints -}}
{{- else if $v.defaultTopologySpread -}}
{{- range $key := list "topology.kubernetes.io/zone" "kubernetes.io/hostname" }}
- maxSkew: 1
  topologyKey: {{ $key }}
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      {{- include "farrier.selectorLabels" $ | nindent 6 }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Pod template (metadata + spec) shared by every workload. Input: component context plus
  containers (YAML string), volumes (YAML string), terminationGracePeriodSeconds.
*/}}
{{- define "farrier.podTemplate" -}}
{{- $v := index .ctx.Values .component -}}
metadata:
  labels:
    {{- include "farrier.selectorLabels" . | nindent 4 }}
    {{- if $v.serviceAccount.cloudIdentity.azureClientId }}
    azure.workload.identity/use: "true"
    {{- end }}
    {{- with $v.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  annotations:
    checksum/config: {{ include "farrier.configMap" . | sha256sum }}
    checksum/secret: {{ include "farrier.secretChecksum" . }}
    {{- with $v.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  serviceAccountName: {{ include "farrier.serviceAccountName" . }}
  automountServiceAccountToken: {{ include "farrier.automountToken" . }}
  enableServiceLinks: false
  {{- with .ctx.Values.global.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $v.priorityClassName }}
  priorityClassName: {{ . | quote }}
  {{- end }}
  terminationGracePeriodSeconds: {{ .terminationGracePeriodSeconds }}
  securityContext:
    {{- include "farrier.podSecurityContext" $v | nindent 4 }}
  {{- with $v.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $v.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $v.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with include "farrier.topologySpread" . | trim }}
  topologySpreadConstraints:
    {{- . | nindent 4 }}
  {{- end }}
  containers:
    {{- .containers | trim | nindent 4 }}
  volumes:
    {{- .volumes | trim | nindent 4 }}
    {{- with $v.extraVolumes }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
{{- end -}}

{{/*
PodDisruptionBudget, rendered only when more than one replica always runs (a minAvailable: 1
budget on a single replica would block every node drain). Input: component context plus
replicas (the guaranteed replica count).
*/}}
{{- define "farrier.pdb" -}}
{{- $v := index .ctx.Values .component -}}
{{- if and $v.pdb.enabled (gt (int .replicas) 1) }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  {{- include "farrier.metadata" . | nindent 2 }}
spec:
  {{- if not (kindIs "invalid" $v.pdb.maxUnavailable) }}
  maxUnavailable: {{ $v.pdb.maxUnavailable }}
  {{- else }}
  minAvailable: {{ $v.pdb.minAvailable }}
  {{- end }}
  unhealthyPodEvictionPolicy: AlwaysAllow
  selector:
    matchLabels:
      {{- include "farrier.selectorLabels" . | nindent 6 }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------- network policy peers */}}

{{/* Egress rule allowing cluster DNS. Input: root context. */}}
{{- define "farrier.netpol.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.dns.namespaceSelector | nindent 10 }}
      {{- with .Values.networkPolicy.dns.podSelector }}
      podSelector:
        matchLabels:
          {{- toYaml . | nindent 10 }}
      {{- end }}
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- end -}}

{{/* ---------------------------------------------------------------- validation */}}

{{/* Cross-field checks the schema cannot express. Input: root context. */}}
{{- define "farrier.validate" -}}
{{- $v := .Values -}}
{{- if and $v.web.ingress.enabled $v.web.httpRoute.enabled -}}
{{- fail "web.ingress.enabled and web.httpRoute.enabled are mutually exclusive: choose an Ingress or a Gateway API HTTPRoute" -}}
{{- end -}}
{{- if ne $v.database.type "sqlite" -}}
{{- $url := required (printf "database.url is required when database.type=%s" $v.database.type) $v.database.url -}}
{{- if regexMatch "^[a-zA-Z0-9+]+://[^/@]*:[^/@]*@" $url -}}
{{- fail "database.url must not contain a password: Farrier refuses it. Put the password in the Secret under secrets.keys.databasePassword; it is mounted as a file." -}}
{{- end -}}
{{- if and (eq $v.database.type "postgresql") (not (regexMatch "^postgres(ql)?(\\+[a-z0-9]+)?://" $url)) -}}
{{- fail "database.url must start with postgresql:// when database.type=postgresql" -}}
{{- end -}}
{{- if and (eq $v.database.type "mysql") (not (regexMatch "^mysql(\\+[a-z0-9]+)?://" $url)) -}}
{{- fail "database.url must start with mysql:// when database.type=mysql" -}}
{{- end -}}
{{- if and $v.networkPolicy.enabled (not $v.engine.networkPolicy.database.cidrs) (not $v.engine.networkPolicy.extraEgress) -}}
{{- fail "networkPolicy is enabled with an external database: set engine.networkPolicy.database.cidrs (or engine.networkPolicy.extraEgress for an in-cluster database) so the engine can reach it" -}}
{{- end -}}
{{- end -}}
{{- if and $v.engine.metrics.serviceMonitor.enabled (eq $v.secrets.mode "externalSecrets") -}}
{{- if not $v.secrets.externalSecrets.remoteRefs.apiReadToken.key -}}
{{- fail "engine.metrics.serviceMonitor needs the read-only token: set secrets.externalSecrets.remoteRefs.apiReadToken.key" -}}
{{- end -}}
{{- end -}}
{{- if and $v.web.enabled $v.web.autoscaling.enabled -}}
{{- if lt (int $v.web.autoscaling.maxReplicas) (int $v.web.autoscaling.minReplicas) -}}
{{- fail "web.autoscaling.maxReplicas must be >= web.autoscaling.minReplicas" -}}
{{- end -}}
{{- if and (kindIs "invalid" $v.web.autoscaling.targetCPUUtilizationPercentage) (kindIs "invalid" $v.web.autoscaling.targetMemoryUtilizationPercentage) -}}
{{- fail "web.autoscaling needs targetCPUUtilizationPercentage and/or targetMemoryUtilizationPercentage" -}}
{{- end -}}
{{- end -}}
{{- if and $v.web.httpRoute.enabled (not $v.web.httpRoute.parentRefs) -}}
{{- fail "web.httpRoute.parentRefs is required when web.httpRoute.enabled (the Gateway to attach to)" -}}
{{- end -}}
{{- $_ := include "farrier.engine.replicas" . -}}
{{- end -}}
