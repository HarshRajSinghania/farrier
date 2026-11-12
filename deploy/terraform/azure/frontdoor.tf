# Azure Front Door Standard in front of the web app. Two routes on one endpoint: the static one
# caches, the catch-all does not (no cache block = caching disabled), so the dashboard, API proxy
# and sign-in are never cached.

resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = "${var.name}-fd"
  resource_group_name      = local.resource_group_name
  sku_name                 = "Standard_AzureFrontDoor"
  response_timeout_seconds = 60
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "web" {
  name                     = "${var.name}-${local.suffix}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "web" {
  name                     = "web"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/api/health"
    protocol            = "Https"
    request_type        = "GET"
    interval_in_seconds = 60
  }
}

resource "azurerm_cdn_frontdoor_origin" "web" {
  count = var.secrets_seeded ? 1 : 0

  name                           = "web"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.web.id
  enabled                        = true
  host_name                      = azurerm_container_app.web[0].ingress[0].fqdn
  origin_host_header             = azurerm_container_app.web[0].ingress[0].fqdn
  certificate_name_check_enabled = true
  http_port                      = 80
  https_port                     = 443
  priority                       = 1
  weight                         = 1000
}

resource "azurerm_cdn_frontdoor_custom_domain" "web" {
  count = var.custom_domain != "" ? 1 : 0

  name                     = replace(var.custom_domain, ".", "-")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  host_name                = var.custom_domain

  tls {
    certificate_type = "ManagedCertificate"
    minimum_version  = "TLS12"
  }
}

locals {
  custom_domain_ids = var.custom_domain != "" ? [azurerm_cdn_frontdoor_custom_domain.web[0].id] : []
}

resource "azurerm_cdn_frontdoor_route" "static" {
  count = var.secrets_seeded ? 1 : 0

  name                            = "static"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.web.id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.web.id
  cdn_frontdoor_origin_ids        = [azurerm_cdn_frontdoor_origin.web[0].id]
  cdn_frontdoor_custom_domain_ids = local.custom_domain_ids
  patterns_to_match               = ["/_next/static/*", "/assets/*"]
  supported_protocols             = ["Http", "Https"]
  https_redirect_enabled          = true
  forwarding_protocol             = "HttpsOnly"
  link_to_default_domain          = true

  cache {
    query_string_caching_behavior = "UseQueryString"
    compression_enabled           = true
    content_types_to_compress     = ["application/javascript", "text/css", "image/svg+xml", "application/json", "text/plain"]
  }
}

resource "azurerm_cdn_frontdoor_route" "web" {
  count = var.secrets_seeded ? 1 : 0

  name                            = "web"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.web.id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.web.id
  cdn_frontdoor_origin_ids        = [azurerm_cdn_frontdoor_origin.web[0].id]
  cdn_frontdoor_custom_domain_ids = local.custom_domain_ids
  patterns_to_match               = ["/*"]
  supported_protocols             = ["Http", "Https"]
  https_redirect_enabled          = true
  forwarding_protocol             = "HttpsOnly"
  link_to_default_domain          = true
}
