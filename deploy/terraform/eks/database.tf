# Optional RDS PostgreSQL (create_database): private, encrypted with the CMK, TLS enforced,
# password managed by RDS in Secrets Manager (never in Terraform state). Reachable from the
# cluster security group (managed node groups and Fargate pods carry it) and db_allowed_cidrs.

resource "aws_db_subnet_group" "this" {
  count = var.create_database ? 1 : 0

  name       = var.name
  subnet_ids = local.database_subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "db" {
  count = var.create_database ? 1 : 0

  name        = "${var.name}-db"
  description = "Farrier PostgreSQL: EKS cluster only"
  vpc_id      = local.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-db" })
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cluster" {
  count = var.create_database ? 1 : 0

  security_group_id            = aws_security_group.db[0].id
  referenced_security_group_id = local.cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "PostgreSQL from the EKS cluster security group"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cidrs" {
  for_each = var.create_database ? toset(var.db_allowed_cidrs) : toset([])

  security_group_id = aws_security_group.db[0].id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  description       = "PostgreSQL from ${each.value}"
}

resource "aws_db_parameter_group" "this" {
  count = var.create_database ? 1 : 0

  name_prefix = "${var.name}-pg-"
  family      = "postgres${split(".", var.db_engine_version)[0]}"
  description = "Farrier: TLS required, connections logged"
  tags        = local.tags

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  count = var.create_database ? 1 : 0

  identifier     = var.name
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  db_name  = "farrier"
  username = var.db_username

  # RDS rotates this password every 7 days by default; ESO re-reads it on its refreshInterval.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.app.arn

  iam_database_authentication_enabled = var.db_iam_auth

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.app.arn

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.db[0].id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.this[0].name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  backup_retention_period         = var.db_backup_retention_days
  backup_window                   = "03:00-04:00"
  maintenance_window              = "sun:04:30-sun:05:30"
  copy_tags_to_snapshot           = true
  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql"]

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"

  tags = local.tags
}
