# The contract with the Helm chart: helm_values goes after examples/values-gke.yaml as a second
# -f; kubernetes_manifests is applied with kubectl before the chart is installed.

locals {
  # Chart key (secrets.externalSecrets.remoteRefs.<key>) => runtime secret. Only the secrets this
  # configuration creates are rendered.
  remote_ref_secrets = {
    apiToken          = "api-token"
    apiReadToken      = "api-read-token"
    masterKey         = "master-key"
    databasePassword  = "db-password"
    dashboardPassword = "dashboard-password"
    oidcClientSecret  = "oidc-client-secret"
    sessionSecret     = "session-secret"
  }

  helm_engine = {
    serviceAccount = {
      name          = var.service_account_name
      cloudIdentity = { gcpServiceAccount = google_service_account.engine.email }
    }
    masterKey     = { kms = "gcp-kms:${google_kms_crypto_key.master_wrap.id}" }
    secretBackend = { type = "gcp", gcp = { project = var.project_id } }
    storage       = { url = local.storage_url }
  }

  helm_values = merge(
    {
      cloud = { provider = "gke", identity = "workload-identity" }
      web   = { auth = { mode = var.oidc_enabled ? "oidc" : "basic" } }
      secrets = {
        mode = "externalSecrets"
        externalSecrets = {
          secretStoreRef = { name = local.secret_store_name, kind = "SecretStore" }
          remoteRefs = {
            for ref, secret in local.remote_ref_secrets : ref => {
              key = google_secret_manager_secret.runtime[secret].secret_id
            } if contains(local.all_secret_names, secret)
          }
        }
      }
      engine = merge(
        local.helm_engine,
        var.create_database ? { networkPolicy = { database = { cidrs = ["${local.database_ip}/32"] } } } : null,
      )
    },
    var.create_database ? {
      database = {
        type = "postgresql"
        url  = local.database_url
        tls  = { existingSecret = local.db_ca_secret_name }
      }
    } : null,
  )

  k8s_labels = { "app.kubernetes.io/part-of" = "farrier" }

  k8s_manifests = concat(
    [
      yamlencode({
        apiVersion = "v1"
        kind       = "ServiceAccount"
        metadata = {
          name        = var.external_secrets_service_account_name
          namespace   = var.namespace
          labels      = local.k8s_labels
          annotations = { "iam.gke.io/gcp-service-account" = google_service_account.external_secrets.email }
        }
      }),
      yamlencode({
        apiVersion = "external-secrets.io/v1"
        kind       = "SecretStore"
        metadata = {
          name      = local.secret_store_name
          namespace = var.namespace
          labels    = local.k8s_labels
        }
        spec = {
          provider = {
            gcpsm = {
              projectID = var.project_id
              auth = {
                workloadIdentity = {
                  clusterLocation   = var.cluster_location
                  clusterName       = var.cluster_name
                  clusterProjectID  = local.cluster_project_id
                  serviceAccountRef = { name = var.external_secrets_service_account_name }
                }
              }
            }
          }
        }
      }),
    ],
    # The Cloud SQL server CA (public): the engine verifies the server against it (verify-ca;
    # the per-instance CA does not name the private IP, so verify-full would fail).
    var.create_database ? [
      yamlencode({
        apiVersion = "v1"
        kind       = "Secret"
        type       = "Opaque"
        metadata = {
          name      = local.db_ca_secret_name
          namespace = var.namespace
          labels    = local.k8s_labels
        }
        stringData = { "ca.crt" = google_sql_database_instance.this[0].server_ca_cert[0].cert }
      }),
    ] : [],
  )
}

output "helm_values" {
  description = "Helm values for deploy/helm/farrier, passed after examples/values-gke.yaml: terraform output -raw helm_values > cloud-values.yaml"
  value       = yamlencode(local.helm_values)
}

# No secret values in it (the CA certificate is public); marked sensitive only in case the provider
# flags server_ca_cert as sensitive. `terraform output -raw` still prints it.
output "kubernetes_manifests" {
  description = "External Secrets ServiceAccount and SecretStore (and the database CA Secret): terraform output -raw kubernetes_manifests | kubectl apply -f -"
  value       = join("---\n", local.k8s_manifests)
  sensitive   = true
}

output "engine_service_account_email" {
  description = "Engine Google service account (engine.serviceAccount.cloudIdentity.gcpServiceAccount)."
  value       = google_service_account.engine.email
}

output "external_secrets_service_account_email" {
  description = "Google service account the External Secrets SecretStore impersonates."
  value       = google_service_account.external_secrets.email
}

output "kms_key_id" {
  description = "Cloud KMS key that wraps the master key."
  value       = google_kms_crypto_key.master_wrap.id
}

output "bucket_name" {
  description = "GCS bucket for change packs, backups and audit exports."
  value       = google_storage_bucket.objects.name
}

output "master_key_secret_id" {
  description = "Add the wrapped master key as a version of this secret before installing the chart."
  value       = google_secret_manager_secret.runtime["master-key"].secret_id
}

output "database_private_ip" {
  description = "Cloud SQL private IP (null when create_database = false)."
  value       = local.database_ip
}

output "dashboard_password" {
  description = "Generated Basic-auth password (only when oidc_enabled = false)."
  value       = var.oidc_enabled ? null : random_password.dashboard_password[0].result
  sensitive   = true
}
