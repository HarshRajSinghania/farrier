# Global external Application Load Balancer for the web service. Two backend services share one
# serverless NEG: only the CDN one (static build assets) caches.

resource "google_compute_region_network_endpoint_group" "web" {
  project               = var.project_id
  name                  = "${var.name}-web"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = "${var.name}-web"
  }

  depends_on = [google_project_service.apis]
}

resource "google_compute_security_policy" "web" {
  count = var.enable_cloud_armor ? 1 : 0

  project     = var.project_id
  name        = "${var.name}-web"
  description = "Farrier dashboard edge policy"

  dynamic "rule" {
    for_each = length(var.allowed_source_ranges) > 0 ? [1] : []

    content {
      action      = "allow"
      priority    = 1000
      description = "Allowed client ranges"

      match {
        versioned_expr = "SRC_IPS_V1"

        config {
          src_ip_ranges = var.allowed_source_ranges
        }
      }
    }
  }

  dynamic "rule" {
    for_each = length(var.allowed_source_ranges) > 0 ? [] : [1]

    content {
      action      = "throttle"
      priority    = 1000
      description = "Per-IP rate limit"

      match {
        versioned_expr = "SRC_IPS_V1"

        config {
          src_ip_ranges = ["*"]
        }
      }

      rate_limit_options {
        conform_action = "allow"
        exceed_action  = "deny(429)"
        enforce_on_key = "IP"

        rate_limit_threshold {
          count        = var.rate_limit_per_minute
          interval_sec = 60
        }
      }
    }
  }

  rule {
    action      = length(var.allowed_source_ranges) > 0 ? "deny(403)" : "allow"
    priority    = 2147483647
    description = "Default rule"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  depends_on = [google_project_service.apis]
}

locals {
  security_policy = var.enable_cloud_armor ? google_compute_security_policy.web[0].id : null
}

resource "google_compute_backend_service" "web" {
  project               = var.project_id
  name                  = "${var.name}-web"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  enable_cdn            = false
  security_policy       = local.security_policy

  backend {
    group = google_compute_region_network_endpoint_group.web.id
  }

  log_config {
    enable      = true
    sample_rate = 1
  }
}

resource "google_compute_backend_service" "web_static" {
  project               = var.project_id
  name                  = "${var.name}-web-static"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  enable_cdn            = true
  compression_mode      = "AUTOMATIC"
  security_policy       = local.security_policy

  backend {
    group = google_compute_region_network_endpoint_group.web.id
  }

  cdn_policy {
    cache_mode       = "CACHE_ALL_STATIC"
    default_ttl      = 3600
    max_ttl          = 86400
    client_ttl       = 3600
    negative_caching = false

    cache_key_policy {
      include_host         = true
      include_protocol     = true
      include_query_string = true
    }
  }

  log_config {
    enable      = true
    sample_rate = 0.1
  }
}

resource "google_compute_url_map" "web" {
  project         = var.project_id
  name            = "${var.name}-web"
  default_service = google_compute_backend_service.web.id

  host_rule {
    hosts        = ["*"]
    path_matcher = "farrier"
  }

  path_matcher {
    name            = "farrier"
    default_service = google_compute_backend_service.web.id

    path_rule {
      paths   = ["/_next/static/*", "/assets/*"]
      service = google_compute_backend_service.web_static.id
    }
  }
}

resource "google_compute_managed_ssl_certificate" "web" {
  project = var.project_id
  name    = "${var.name}-web-${substr(sha1(join(",", var.domains)), 0, 8)}"

  managed {
    domains = var.domains
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_ssl_policy" "web" {
  project         = var.project_id
  name            = "${var.name}-web"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "web" {
  project          = var.project_id
  name             = "${var.name}-web"
  url_map          = google_compute_url_map.web.id
  ssl_certificates = [google_compute_managed_ssl_certificate.web.id]
  ssl_policy       = google_compute_ssl_policy.web.id
}

resource "google_compute_global_address" "web" {
  project = var.project_id
  name    = "${var.name}-web"

  depends_on = [google_project_service.apis]
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${var.name}-web-https"
  target                = google_compute_target_https_proxy.web.id
  ip_address            = google_compute_global_address.web.id
  port_range            = "443"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  labels                = local.labels
}

# Port 80 only redirects to HTTPS.
resource "google_compute_url_map" "redirect" {
  project = var.project_id
  name    = "${var.name}-web-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  project = var.project_id
  name    = "${var.name}-web-redirect"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  project               = var.project_id
  name                  = "${var.name}-web-http"
  target                = google_compute_target_http_proxy.redirect.id
  ip_address            = google_compute_global_address.web.id
  port_range            = "80"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  labels                = local.labels
}
