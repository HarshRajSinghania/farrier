# Farrier on AWS: ECS Fargate (engine + web), RDS PostgreSQL, S3, Secrets Manager, KMS, CloudFront.
#
#   Internet ──HTTPS──> CloudFront ──VPC origin (private)──> internal ALB (web) ──> web tasks
#                                                                                    │
#                                     internal ALB (engine, web SG only) <───────────┘
#                                                 │
#                                            engine tasks ──> RDS, S3, Secrets Manager, KMS, devices
#
# Nothing except CloudFront has a public address. The engine is never reachable from the internet.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge({ "app.kubernetes.io/part-of" = "farrier", "farrier:deployment" = var.name }, var.tags)

  engine_image = var.engine_image != "" ? var.engine_image : "ghcr.io/gagankarthik/farrier:${var.farrier_version}"
  web_image    = var.web_image != "" ? var.web_image : "ghcr.io/gagankarthik/farrier-web:${var.farrier_version}"

  vpc_id              = var.create_vpc ? aws_vpc.this[0].id : var.vpc_id
  private_subnet_ids  = var.create_vpc ? aws_subnet.private[*].id : var.private_subnet_ids
  database_subnet_ids = length(var.database_subnet_ids) > 0 ? var.database_subnet_ids : local.private_subnet_ids

  oidc_enabled = var.oidc_issuer != ""

  # Values for the web app and engine (never device credentials) live under <name>-runtime/,
  # outside the engine's own store prefix, so the engine's IAM grant on its prefix never covers them.
  runtime_prefix = "${var.name}-runtime/"

  engine_https       = var.engine_certificate_arn != ""
  engine_listen_port = local.engine_https ? 443 : 80
  engine_url         = local.engine_https ? "https://${var.engine_domain_name}" : "http://${aws_lb.engine.dns_name}"

  site_url = length(var.domain_names) > 0 ? "https://${var.domain_names[0]}" : "https://${aws_cloudfront_distribution.web.domain_name}"

  rds_ca_dir = "/etc/farrier/rds"
  rds_ca_url = "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"
  database_url = format(
    "postgresql://%s@%s:%d/farrier?sslmode=verify-full&sslrootcert=%s/rds-ca.pem",
    var.db_username, aws_db_instance.this.address, aws_db_instance.this.port, local.rds_ca_dir,
  )
  storage_url = "s3://${aws_s3_bucket.objects.bucket}/${trimsuffix(var.storage_prefix, "/")}"
}

# ---------------------------------------------------------------------------------------------
# Optional VPC (create_vpc = true). Two-tier: public subnets hold only the NAT gateway.
# ---------------------------------------------------------------------------------------------

resource "aws_vpc" "this" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = var.name })
}

resource "aws_internet_gateway" "this" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = var.name })
}

resource "aws_subnet" "public" {
  count = var.create_vpc ? var.az_count : 0

  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-public-${count.index}" })
}

resource "aws_subnet" "private" {
  count = var.create_vpc ? var.az_count : 0

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 1)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge(local.tags, { Name = "${var.name}-private-${count.index}" })
}

resource "aws_eip" "nat" {
  count = var.create_vpc ? 1 : 0

  domain = "vpc"
  tags   = merge(local.tags, { Name = "${var.name}-nat" })
}

resource "aws_nat_gateway" "this" {
  count = var.create_vpc ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = merge(local.tags, { Name = var.name })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = "${var.name}-public" })
}

resource "aws_route" "public_internet" {
  count = var.create_vpc ? 1 : 0

  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  count = var.create_vpc ? var.az_count : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = "${var.name}-private" })
}

resource "aws_route" "private_nat" {
  count = var.create_vpc ? 1 : 0

  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private" {
  count = var.create_vpc ? var.az_count : 0

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}
