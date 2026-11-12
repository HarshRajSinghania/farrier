# Container Apps. One VNet-integrated environment: the engine's ingress is limited to the
# environment (no external endpoint); the web app has external ingress, fronted by Front Door.
# That ingress accepts only Front Door's backend addresses (the AzureFrontDoor.Backend service
# tag; Container Apps IP rules take CIDRs, not tags), and the web app rejects requests whose
# X-Azure-FDID header is not this Front Door profile, so other Front Door tenants can't reach it.

data "azurerm_network_service_tags" "front_door" {
  location = var.location
  service  = "AzureFrontDoor.Backend"
}

resource "azurerm_container_app_environment" "this" {
  name                       = "${var.name}-env"
  location                   = var.location
  resource_group_name        = local.resource_group_name
  infrastructure_subnet_id   = local.container_apps_subnet_id
  zone_redundancy_enabled    = var.zone_redundant
  logs_destination           = "log-analytics"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  tags                       = local.tags

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
}

locals {
  site_url = var.custom_domain != "" ? "https://${var.custom_domain}" : "https://${azurerm_cdn_frontdoor_endpoint.web.host_name}"

  database_url = format(
    "postgresql://farrier@%s:5432/farrier?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
    azurerm_postgresql_flexible_server.this.fqdn,
  )
  storage_url = "azblob://${azurerm_storage_account.this.name}/${azurerm_storage_container.objects.name}/${trimsuffix(var.storage_prefix, "/")}"

  engine_env = merge({
    AZURE_CLIENT_ID                = azurerm_user_assigned_identity.engine.client_id
    FARRIER_DATA                   = "/data"
    FARRIER_DATABASE_URL           = local.database_url
    FARRIER_MASTER_KEY_KMS         = "azure-kv:${azurerm_key_vault_key.master_wrap.versionless_id}"
    FARRIER_SECRET_BACKEND         = "azure"
    FARRIER_SECRET_AZURE_VAULT_URL = azurerm_key_vault.this["store"].vault_uri
    FARRIER_STORAGE_URL            = local.storage_url
  }, var.engine_extra_env)

  engine_secret_env = {
    FARRIER_API_TOKEN         = "api-token"
    FARRIER_API_READ_TOKEN    = "api-read-token"
    FARRIER_DATABASE_PASSWORD = "db-password"
    FARRIER_MASTER_KEY        = "master-key"
  }

  web_oidc_env = {
    FARRIER_OIDC_ISSUER                   = var.oidc_issuer
    FARRIER_OIDC_CLIENT_ID                = var.oidc_client_id
    FARRIER_OIDC_SCOPES                   = var.oidc_scopes
    FARRIER_OIDC_REDIRECT_URI             = "${local.site_url}/auth/callback"
    FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI = "${local.site_url}/auth/signin?signed_out=1"
  }

  web_env = merge(
    {
      NEXT_PUBLIC_SITE_URL = local.site_url

      # Requests that did not come through this Front Door profile are refused.
      FARRIER_REQUIRE_HEADER = "X-Azure-FDID:${azurerm_cdn_frontdoor_profile.this.resource_guid}"

      # Front Door appends the client address, then the Container Apps ingress appends Front
      # Door's: the client is the second X-Forwarded-For entry from the right.
      FARRIER_TRUSTED_PROXY_HOPS = "2"
    },
    local.oidc_enabled ? local.web_oidc_env : {},
    var.web_extra_env,
  )

  web_secret_env = merge(
    {
      FARRIER_API_TOKEN      = "api-token"
      FARRIER_API_READ_TOKEN = "api-read-token"
    },
    local.oidc_enabled ? {
      FARRIER_SESSION_SECRET     = "session-secret"
      FARRIER_OIDC_CLIENT_SECRET = "oidc-client-secret"
    } : {},
    local.oidc_enabled ? {} : {
      FARRIER_DASHBOARD_PASSWORD = "dashboard-password"
    },
  )
}

resource "azurerm_container_app" "engine" {
  count = var.secrets_seeded ? 1 : 0

  name                         = "${var.name}-engine"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = local.resource_group_name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.engine.id]
  }

  dynamic "secret" {
    for_each = toset(local.engine_secret_names)

    content {
      name                = secret.value
      identity            = azurerm_user_assigned_identity.engine.id
      key_vault_secret_id = local.secret_urls[secret.value]
    }
  }

  ingress {
    external_enabled           = false
    allow_insecure_connections = false
    target_port                = 8740
    transport                  = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.engine_min_replicas
    max_replicas = var.engine_max_replicas

    container {
      name    = "engine"
      image   = local.engine_image
      cpu     = 0.5
      memory  = "1Gi"
      command = ["farrier"]
      args    = ["serve", "--host", "0.0.0.0", "--port", "8740", "--grace", "20"]

      dynamic "env" {
        for_each = local.engine_env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.engine_secret_env

        content {
          name        = env.key
          secret_name = env.value
        }
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8740
        path      = "/healthz"
      }

      readiness_probe {
        transport = "HTTP"
        port      = 8740
        path      = "/healthz"
      }
    }
  }

  depends_on = [time_sleep.app_rbac, azurerm_private_endpoint.vault]
}

resource "azurerm_container_app" "web" {
  count = var.secrets_seeded ? 1 : 0

  name                         = "${var.name}-web"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = local.resource_group_name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.web.id]
  }

  dynamic "secret" {
    for_each = toset(local.web_secret_names)

    content {
      name                = secret.value
      identity            = azurerm_user_assigned_identity.web.id
      key_vault_secret_id = local.secret_urls[secret.value]
    }
  }

  ingress {
    external_enabled           = true
    allow_insecure_connections = false
    target_port                = 3000
    transport                  = "http"

    # Only Front Door may connect (all rules must share one action; anything unlisted is denied).
    dynamic "ip_security_restriction" {
      for_each = data.azurerm_network_service_tags.front_door.ipv4_cidrs

      content {
        name             = "front-door-${ip_security_restriction.key}"
        description      = "AzureFrontDoor.Backend"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
      }
    }

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.web_min_replicas
    max_replicas = var.web_max_replicas

    container {
      name   = "web"
      image  = local.web_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "FARRIER_API_URL"
        value = "https://${azurerm_container_app.engine[0].ingress[0].fqdn}"
      }

      dynamic "env" {
        for_each = local.web_env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.web_secret_env

        content {
          name        = env.key
          secret_name = env.value
        }
      }

      liveness_probe {
        transport = "HTTP"
        port      = 3000
        path      = "/api/health"
      }

      readiness_probe {
        transport = "HTTP"
        port      = 3000
        path      = "/api/health"
      }
    }
  }

  depends_on = [time_sleep.app_rbac, azurerm_private_endpoint.vault]
}
