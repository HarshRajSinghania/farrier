# ECS Fargate: the engine (private, behind the internal engine ALB) and the web app.

resource "aws_cloudwatch_log_group" "engine" {
  name              = "/ecs/${var.name}/engine"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.app.arn
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "web" {
  name              = "/ecs/${var.name}/web"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.app.arn
  tags              = local.tags
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  tags = local.tags

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

locals {
  engine_env = merge({
    FARRIER_DATA              = "/data"
    FARRIER_DATABASE_URL      = local.database_url
    FARRIER_MASTER_KEY_KMS    = "aws-kms:${aws_kms_key.app.arn}"
    FARRIER_SECRET_BACKEND    = "aws"
    FARRIER_SECRET_AWS_REGION = local.region
    FARRIER_SECRET_AWS_PREFIX = var.secret_store_prefix
    FARRIER_STORAGE_URL       = local.storage_url
    FARRIER_STORAGE_KMS_KEY   = aws_kms_key.app.arn
  }, var.engine_extra_env)

  engine_secrets = {
    FARRIER_API_TOKEN         = local.secret_arns["api-token"]
    FARRIER_API_READ_TOKEN    = local.secret_arns["api-read-token"]
    FARRIER_MASTER_KEY        = local.secret_arns["master-key"]
    FARRIER_DATABASE_PASSWORD = "${local.db_secret_arn}:password::"
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
      FARRIER_API_URL      = local.engine_url
      NEXT_PUBLIC_SITE_URL = local.site_url
    },
    local.oidc_enabled ? local.web_oidc_env : {},
    var.web_extra_env,
  )

  # lookup(): only the keys for the chosen sign-in mode exist in secret_arns.
  web_secrets = merge(
    {
      FARRIER_API_TOKEN      = local.secret_arns["api-token"]
      FARRIER_API_READ_TOKEN = local.secret_arns["api-read-token"]
    },
    local.oidc_enabled ? {
      FARRIER_SESSION_SECRET     = lookup(local.secret_arns, "session-secret", "")
      FARRIER_OIDC_CLIENT_SECRET = lookup(local.secret_arns, "oidc-client-secret", "")
    } : {},
    local.oidc_enabled ? {} : {
      FARRIER_DASHBOARD_PASSWORD = lookup(local.secret_arns, "dashboard-password", "")
    },
  )

  container_hardening = {
    readonlyRootFilesystem = true
    user                   = "10001"
    linuxParameters = {
      capabilities       = { drop = ["ALL"] }
      initProcessEnabled = true
    }
  }
}

resource "aws_ecs_task_definition" "engine" {
  family                   = "${var.name}-engine"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.engine_cpu
  memory                   = var.engine_memory
  execution_role_arn       = aws_iam_role.engine_execution.arn
  task_role_arn            = aws_iam_role.engine_task.arn
  tags                     = local.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "data"
  }

  volume {
    name = "tmp"
  }

  volume {
    name = "rds-ca"
  }

  container_definitions = jsonencode([
    # Fetches the RDS CA bundle over verified TLS so the engine can use sslmode=verify-full.
    # Reuses the engine image (Python's urllib verifies certificates); exits when done.
    {
      name                   = "rds-ca"
      image                  = local.engine_image
      essential              = false
      user                   = "0"
      readonlyRootFilesystem = true
      command                = ["python", "-c", "import urllib.request; urllib.request.urlretrieve('${local.rds_ca_url}', '${local.rds_ca_dir}/rds-ca.pem')"]
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      mountPoints            = [{ sourceVolume = "rds-ca", containerPath = local.rds_ca_dir }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.engine.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "rds-ca"
        }
      }
    },
    merge(local.container_hardening, {
      name         = "engine"
      image        = local.engine_image
      essential    = true
      command      = ["farrier", "serve", "--host", "0.0.0.0", "--port", "8740", "--grace", "20"]
      stopTimeout  = 45
      portMappings = [{ name = "http", containerPort = 8740, protocol = "tcp" }]
      environment  = [for k, v in local.engine_env : { name = k, value = v }]
      secrets      = [for k, v in local.engine_secrets : { name = k, valueFrom = v }]
      dependsOn    = [{ containerName = "rds-ca", condition = "SUCCESS" }]
      mountPoints = [
        { sourceVolume = "data", containerPath = "/data" },
        { sourceVolume = "tmp", containerPath = "/tmp" },
        { sourceVolume = "rds-ca", containerPath = local.rds_ca_dir, readOnly = true },
      ]
      healthCheck = {
        command     = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8740/healthz', timeout=3)"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.engine.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "engine"
        }
      }
    }),
  ])
}

resource "aws_ecs_task_definition" "web" {
  family                   = "${var.name}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.web_cpu
  memory                   = var.web_memory
  execution_role_arn       = aws_iam_role.web_execution.arn
  task_role_arn            = aws_iam_role.web_task.arn
  tags                     = local.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "next-cache"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([
    merge(local.container_hardening, {
      name         = "web"
      image        = local.web_image
      essential    = true
      portMappings = [{ name = "http", containerPort = 3000, protocol = "tcp" }]
      environment  = [for k, v in local.web_env : { name = k, value = v }]
      secrets      = [for k, v in local.web_secrets : { name = k, valueFrom = v }]
      mountPoints = [
        { sourceVolume = "next-cache", containerPath = "/app/.next/cache" },
        { sourceVolume = "tmp", containerPath = "/tmp" },
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 20
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.web.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "web"
        }
      }
    }),
  ])
}

resource "aws_ecs_service" "engine" {
  count = var.secrets_seeded ? 1 : 0

  name                              = "${var.name}-engine"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.engine.arn
  desired_count                     = var.engine_desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false
  health_check_grace_period_seconds = 60
  tags                              = local.tags

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.engine_task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.engine.arn
    container_name   = "engine"
    container_port   = 8740
  }

  depends_on = [aws_lb_listener.engine, aws_iam_role_policy.engine_execution]
}

resource "aws_ecs_service" "web" {
  count = var.secrets_seeded ? 1 : 0

  name                              = "${var.name}-web"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.web.arn
  desired_count                     = var.web_desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false
  health_check_grace_period_seconds = 30
  tags                              = local.tags

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.web_task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "web"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.web, aws_iam_role_policy.web_execution]
}
