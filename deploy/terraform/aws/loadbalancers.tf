# Two internal ALBs. The web ALB is reached only by CloudFront (VPC origin); the engine ALB only by
# the web tasks (and engine_api_allowed_cidrs). Neither has a public address.

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

# ---------------------------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------------------------

resource "aws_security_group" "web_alb" {
  name        = "${var.name}-web-alb"
  description = "Farrier web ALB: CloudFront only"
  vpc_id      = local.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-web-alb" })
}

resource "aws_security_group" "web_task" {
  name        = "${var.name}-web"
  description = "Farrier web tasks"
  vpc_id      = local.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-web" })
}

resource "aws_security_group" "engine_alb" {
  name        = "${var.name}-engine-alb"
  description = "Farrier engine ALB: web tasks only"
  vpc_id      = local.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-engine-alb" })
}

resource "aws_security_group" "engine_task" {
  name        = "${var.name}-engine"
  description = "Farrier engine tasks"
  vpc_id      = local.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-engine" })
}

resource "aws_vpc_security_group_ingress_rule" "web_alb_from_cloudfront" {
  security_group_id = aws_security_group.web_alb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront.id
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  description       = "CloudFront VPC origin"
}

resource "aws_vpc_security_group_egress_rule" "web_alb_to_web" {
  security_group_id            = aws_security_group.web_alb.id
  referenced_security_group_id = aws_security_group.web_task.id
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
}

resource "aws_vpc_security_group_ingress_rule" "web_from_alb" {
  security_group_id            = aws_security_group.web_task.id
  referenced_security_group_id = aws_security_group.web_alb.id
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
}

resource "aws_vpc_security_group_egress_rule" "web_https" {
  security_group_id = aws_security_group.web_task.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "OIDC issuer, AWS APIs"
}

resource "aws_vpc_security_group_egress_rule" "web_to_engine_alb" {
  security_group_id            = aws_security_group.web_task.id
  referenced_security_group_id = aws_security_group.engine_alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.engine_listen_port
  to_port                      = local.engine_listen_port
}

resource "aws_vpc_security_group_ingress_rule" "engine_alb_from_web" {
  security_group_id            = aws_security_group.engine_alb.id
  referenced_security_group_id = aws_security_group.web_task.id
  ip_protocol                  = "tcp"
  from_port                    = local.engine_listen_port
  to_port                      = local.engine_listen_port
}

resource "aws_vpc_security_group_ingress_rule" "engine_alb_from_cidrs" {
  for_each = toset(var.engine_api_allowed_cidrs)

  security_group_id = aws_security_group.engine_alb.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.engine_listen_port
  to_port           = local.engine_listen_port
}

resource "aws_vpc_security_group_egress_rule" "engine_alb_to_engine" {
  security_group_id            = aws_security_group.engine_alb.id
  referenced_security_group_id = aws_security_group.engine_task.id
  ip_protocol                  = "tcp"
  from_port                    = 8740
  to_port                      = 8740
}

resource "aws_vpc_security_group_ingress_rule" "engine_from_alb" {
  security_group_id            = aws_security_group.engine_task.id
  referenced_security_group_id = aws_security_group.engine_alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8740
  to_port                      = 8740
}

resource "aws_vpc_security_group_egress_rule" "engine_to_db" {
  security_group_id            = aws_security_group.engine_task.id
  referenced_security_group_id = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "engine_out" {
  for_each = toset(var.engine_egress_cidrs)

  security_group_id = aws_security_group.engine_task.id
  cidr_ipv4         = each.value
  ip_protocol       = "-1"
  description       = "ACME CAs, DNS APIs, devices"
}

# ---------------------------------------------------------------------------------------------
# Web ALB (CloudFront VPC origin)
# ---------------------------------------------------------------------------------------------

resource "aws_lb" "web" {
  name                       = "${var.name}-web"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.web_alb.id]
  subnets                    = local.private_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  tags                       = local.tags

  lifecycle {
    precondition {
      condition     = local.vpc_id != "" && length(local.private_subnet_ids) >= 2
      error_message = "Set create_vpc = true, or give vpc_id and at least two private_subnet_ids."
    }
  }
}

resource "aws_lb_target_group" "web" {
  name                 = "${var.name}-web"
  port                 = 3000
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = local.vpc_id
  deregistration_delay = 30
  tags                 = local.tags

  health_check {
    path                = "/api/health"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "web" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"
  tags              = local.tags

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

# ---------------------------------------------------------------------------------------------
# Engine ALB (internal; reachable from the web tasks only)
# ---------------------------------------------------------------------------------------------

resource "aws_lb" "engine" {
  name                       = "${var.name}-engine"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.engine_alb.id]
  subnets                    = local.private_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  tags                       = local.tags

  lifecycle {
    precondition {
      condition     = var.engine_certificate_arn == "" || var.engine_domain_name != ""
      error_message = "engine_certificate_arn needs engine_domain_name (the private DNS name the certificate covers)."
    }
  }
}

resource "aws_lb_target_group" "engine" {
  name                 = "${var.name}-engine"
  port                 = 8740
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = local.vpc_id
  deregistration_delay = 30
  tags                 = local.tags

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "engine" {
  load_balancer_arn = aws_lb.engine.arn
  port              = local.engine_listen_port
  protocol          = local.engine_https ? "HTTPS" : "HTTP"
  ssl_policy        = local.engine_https ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : null
  certificate_arn   = local.engine_https ? var.engine_certificate_arn : null
  tags              = local.tags

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.engine.arn
  }
}
