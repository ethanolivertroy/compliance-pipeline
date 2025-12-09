# Compliant AWS Infrastructure - FedRAMP 20x KSIs
#
# This configuration demonstrates compliant resources for:
# - KSI-CNA-01: Restricted network traffic
# - KSI-SVC-02: Network encryption (TLS)
# - KSI-IAM-01: MFA requirements
# - KSI-SVC-06: Secrets management

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

# -----------------------------------------------------------------------------
# KSI-CNA-01: Network Controls - COMPLIANT
# -----------------------------------------------------------------------------

# VPC with flow logs enabled
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "compliant-vpc"
    Environment = var.environment
  }
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn

  tags = {
    Name = "vpc-flow-log"
  }
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 365

  tags = {
    Name = "vpc-flow-log-group"
  }
}

resource "aws_iam_role" "flow_log" {
  name = "vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

# Security group with restricted ingress (private CIDR only)
resource "aws_security_group" "app" {
  name        = "compliant-app-sg"
  description = "Security group with restricted ingress"
  vpc_id      = aws_vpc.main.id

  # Only allow traffic from private subnets
  ingress {
    description = "HTTPS from private network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "compliant-app-sg"
  }
}

# Public-facing security group - only HTTPS (443) allowed
resource "aws_security_group" "alb" {
  name        = "compliant-alb-sg"
  description = "ALB security group - HTTPS only"
  vpc_id      = aws_vpc.main.id

  # Only HTTPS from public (allowed exception)
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "compliant-alb-sg"
  }
}

# -----------------------------------------------------------------------------
# KSI-SVC-02: Network Encryption - COMPLIANT
# -----------------------------------------------------------------------------

resource "aws_lb" "main" {
  name               = "compliant-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  tags = {
    Name = "compliant-alb"
  }
}

# HTTPS listener with strong TLS policy
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# HTTP listener with redirect to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group" "app" {
  name     = "compliant-app-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }
}

resource "aws_acm_certificate" "main" {
  domain_name       = "example.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# CloudFront with HTTPS enforced
resource "aws_cloudfront_distribution" "main" {
  enabled = true
  comment = "Compliant CloudFront distribution"

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

# -----------------------------------------------------------------------------
# KSI-IAM-01: MFA Requirements - COMPLIANT
# -----------------------------------------------------------------------------

# IAM policy requiring MFA for sensitive actions
resource "aws_iam_policy" "sensitive_with_mfa" {
  name        = "sensitive-actions-require-mfa"
  description = "Policy requiring MFA for sensitive actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSensitiveActionsWithMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "kms:Decrypt",
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

# IAM role with MFA condition in trust policy
resource "aws_iam_role" "admin_with_mfa" {
  name = "admin-role-requires-mfa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# KSI-SVC-06: Secrets Management - COMPLIANT
# -----------------------------------------------------------------------------

# Customer-managed KMS key with rotation
resource "aws_kms_key" "secrets" {
  description             = "KMS key for secrets encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "secrets-kms-key"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/secrets-key"
  target_key_id = aws_kms_key.secrets.key_id
}

# Secrets Manager secret with CMK encryption
resource "aws_secretsmanager_secret" "db_password" {
  name       = "database/password"
  kms_key_id = aws_kms_key.secrets.arn

  tags = {
    Name = "db-password-secret"
  }
}

# Secret rotation configuration
resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.secret_rotation.arn

  rotation_rules {
    automatically_after_days = 30
  }
}

# SSM Parameter with SecureString and CMK
resource "aws_ssm_parameter" "api_key" {
  name   = "/app/api-key"
  type   = "SecureString"
  value  = "placeholder-will-be-set-manually"
  key_id = aws_kms_key.secrets.arn

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "api-key-parameter"
  }
}

# Lambda for secret rotation (stub)
resource "aws_lambda_function" "secret_rotation" {
  function_name = "secret-rotation-function"
  role          = aws_iam_role.lambda_rotation.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = data.archive_file.lambda_placeholder.output_path

  # No secrets in environment variables - uses Secrets Manager
  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

resource "aws_iam_role" "lambda_rotation" {
  name = "lambda-secret-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Supporting Resources
# -----------------------------------------------------------------------------

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "public-subnet-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "public-subnet-b"
  }
}

data "aws_caller_identity" "current" {}

data "archive_file" "lambda_placeholder" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"

  source {
    content  = "def handler(event, context): pass"
    filename = "index.py"
  }
}
