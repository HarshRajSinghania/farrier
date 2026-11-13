# Minimal Farrier on Azure, with a new VNet and Entra ID sign-in.
#
#   terraform init && terraform apply                       # 1. infrastructure, empty secrets
#   (store the wrapped master key and OIDC client secret; see ../../README.md)
#   terraform apply -var secrets_seeded=true                # 2. start the apps and Front Door routes

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
  #   key                  = "farrier.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  subscription_id                 = "00000000-0000-0000-0000-000000000000"
  storage_use_azuread             = true
  resource_provider_registrations = "core"
  resource_providers_to_register = [
    "Microsoft.App",
    "Microsoft.Cdn",
    "Microsoft.DBforPostgreSQL",
    "Microsoft.KeyVault",
    "Microsoft.ManagedIdentity",
    "Microsoft.Network",
    "Microsoft.OperationalInsights",
    "Microsoft.Storage",
  ]

  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

variable "secrets_seeded" {
  type    = bool
  default = false
}

module "farrier" {
  source = "../.."

  name            = "farrier"
  location        = "westeurope"
  farrier_version = "0.2.0"

  # admin_allowed_ips: your Terraform runner's egress IP, for the Key Vault firewalls.
  create_vnet       = true
  admin_allowed_ips = ["203.0.113.10/32"]

  oidc_issuer    = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
  oidc_client_id = "00000000-0000-0000-0000-000000000000"
  web_extra_env = {
    FARRIER_OIDC_ROLE_CLAIM   = "roles"
    FARRIER_OIDC_ADMIN_GROUPS = "Farrier.Admin"
  }

  secrets_seeded = var.secrets_seeded
}

output "dashboard_url" {
  value = module.farrier.dashboard_url
}

output "runtime_key_vault_name" {
  value = module.farrier.runtime_key_vault_name
}
