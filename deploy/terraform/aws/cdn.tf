# CloudFront in front of the (internal) web ALB through a VPC origin. Only Next.js build assets and
# /assets/* are cached; the dashboard, API proxy, auth and pages are never cached and get every
# viewer header, cookie and query string so sign-in works.

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_response_headers_policy" "security" {
  name = "Managed-SecurityHeadersPolicy"
}

locals {
  cached_paths   = ["/_next/static/*", "/assets/*"]
  uncached_paths = ["/dashboard*", "/api/*", "/auth/*"]
  custom_cert    = var.cloudfront_certificate_arn != ""
}

resource "aws_cloudfront_vpc_origin" "web" {
  vpc_origin_endpoint_config {
    name                   = "${var.name}-web"
    arn                    = aws_lb.web.arn
    http_port              = 80
    https_port             = 443
    origin_protocol_policy = "http-only"

    origin_ssl_protocols {
      items    = ["TLSv1.2"]
      quantity = 1
    }
  }

  tags = local.tags
}

resource "aws_cloudfront_distribution" "web" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.name} dashboard"
  aliases         = var.domain_names
  price_class     = var.cloudfront_price_class
  http_version    = "http2and3"
  web_acl_id      = var.web_acl_arn != "" ? var.web_acl_arn : null
  tags            = local.tags

  origin {
    origin_id   = "web"
    domain_name = aws_lb.web.dns_name

    vpc_origin_config {
      vpc_origin_id       = aws_cloudfront_vpc_origin.web.id
      origin_read_timeout = 60
    }
  }

  default_cache_behavior {
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.cached_paths

    content {
      path_pattern               = ordered_cache_behavior.value
      target_origin_id           = "web"
      viewer_protocol_policy     = "redirect-to-https"
      allowed_methods            = ["GET", "HEAD", "OPTIONS"]
      cached_methods             = ["GET", "HEAD"]
      compress                   = true
      cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
      response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.uncached_paths

    content {
      path_pattern               = ordered_cache_behavior.value
      target_origin_id           = "web"
      viewer_protocol_policy     = "https-only"
      allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods             = ["GET", "HEAD"]
      compress                   = true
      cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
      origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer.id
      response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = !local.custom_cert
    acm_certificate_arn            = local.custom_cert ? var.cloudfront_certificate_arn : null
    ssl_support_method             = local.custom_cert ? "sni-only" : null
    minimum_protocol_version       = local.custom_cert ? "TLSv1.2_2021" : "TLSv1"
  }

  lifecycle {
    precondition {
      condition     = length(var.domain_names) == 0 || local.custom_cert
      error_message = "domain_names needs cloudfront_certificate_arn (an ACM certificate in us-east-1)."
    }
  }
}
