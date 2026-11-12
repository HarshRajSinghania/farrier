# Minimal Farrier on an existing AKS cluster, with PostgreSQL and Entra ID sign-in.
#
#   terraform init && terraform apply                       # identities, Key Vaults, storage, database
#   (store the wrapped master key and OIDC client secret; see ../../README.md)
#   terraform output -raw kubernetes_manifests | kubectl apply -f -
#   terraform output -raw helm_values > cloud-values.yaml   # then helm install (see README)

terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }

  # State holds the generated tokens and database password: keep it in an encrypted,
  # access-controlled backend.
  # backend "azurerm" {
  #   resource_group_name  = "tfstate"
  #   storage_account_name = "mytfstate"
  #   container_name       = "tfstate"
  #   key                  = "farrier-aks.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  subscription_id                 = "00000000-0000-0000-0000-000000000000"
  storage_use_azuread             = true
  resource_provider_registrations = "core"
  resource_providers_to_register = [
    "Microsoft.ContainerService",
    "Microsoft.DBforPostgreSQL",
    "Microsoft.KeyVault",
    "Microsoft.ManagedIdentity",
    "Microsoft.Network",
    "Microsoft.Storage",
  ]

  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

module "farrier" {
  source = "../.."

  name                = "farrier"
  location            = "westeurope"
  resource_group_name = "farrier-rg"

  cluster_name                = "aks-prod"
  cluster_resource_group_name = "aks-prod-rg"
  namespace                   = "farrier"

  # The AKS node subnet has the Microsoft.KeyVault and Microsoft.Storage service endpoints.
  # admin_allowed_ips: your Terraform runner's egress IP, for the Key Vault firewalls.
  cluster_subnet_ids = ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/aks-prod-rg/providers/Microsoft.Network/virtualNetworks/aks-vnet/subnets/nodes"]
  admin_allowed_ips  = ["203.0.113.10/32"]

  # Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers in the cluster's VNet.
  database_subnet_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/aks-prod-rg/providers/Microsoft.Network/virtualNetworks/aks-vnet/subnets/postgres"
  database_cidrs     = ["10.224.2.0/24"]
  vnet_id            = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/aks-prod-rg/providers/Microsoft.Network/virtualNetworks/aks-vnet"

  oidc_enabled = true
}

output "helm_values" {
  value = module.farrier.helm_values
}

output "kubernetes_manifests" {
  value = module.farrier.kubernetes_manifests
}

output "runtime_key_vault_name" {
  value = module.farrier.runtime_key_vault_name
}
