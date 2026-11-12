# Farrier on an existing AKS cluster: the Azure side only. Workload identities (engine and
# External Secrets Operator), Key Vault (RBAC), Storage, optional PostgreSQL Flexible Server.
# The Helm chart (deploy/helm/farrier) runs the workloads; outputs helm_values and
# kubernetes_manifests connect the two.
#
#   ESO (SecretStore, workload identity) ─> runtime Key Vault ─> Kubernetes Secrets ─> engine, web
#   engine (workload identity) ─> store Key Vault (device credentials) · master-wrap key (unwrap)
#                              ─> Blob container · PostgreSQL (delegated subnet, private DNS, TLS)
#
# Never creates the cluster, a VNet or any ingress.

data "azurerm_client_config" "current" {}

data "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  resource_group_name = var.cluster_resource_group_name

  lifecycle {
    postcondition {
      condition     = try(length(self.oidc_issuer_url) > 0, false)
      error_message = "The cluster has no OIDC issuer. Run: az aks update -g <rg> -n <cluster> --enable-oidc-issuer --enable-workload-identity"
    }
  }
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  short     = replace(var.name, "-", "")
  suffix    = random_string.suffix.result
  tags      = merge({ app = "farrier", deployment = var.name }, var.tags)
  tenant_id = data.azurerm_client_config.current.tenant_id

  oidc_issuer_url = data.azurerm_kubernetes_cluster.this.oidc_issuer_url
  oidc_enabled    = var.oidc_enabled
}
