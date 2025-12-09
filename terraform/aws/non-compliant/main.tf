# Non-Compliant AWS Infrastructure - FedRAMP 20x KSIs
#
# This configuration demonstrates NON-COMPLIANT resources that will
# trigger policy violations for:
# - KSI-CNA-01: Unrestricted network traffic
# - KSI-SVC-02: Missing or weak encryption
# - KSI-IAM-01: Missing MFA requirements
# - KSI-SVC-06: Poor secrets management

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

# -----------------------------------------------------------------------------
# KSI-CNA-01 VIOLATIONS: Unrestricted Network Traffic
# -----------------------------------------------------------------------------

# VPC WITHOUT flow logs - VIOLATION
resource "aws_vpc" "insecure" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "insecure-vpc-no-flow-logs"
  }
}

# Security group with SSH from anywhere - VIOLATION
resource "aws_security_group" "insecure_ssh" {
  name        = "insecure-ssh-sg"
  description = "INSECURE: Allows SSH from anywhere"
  vpc_id      = aws_vpc.insecure.id

  ingress {
    description = "SSH from anywhere - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Unrestricted SSH
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "insecure-ssh-sg"
  }
}

# Security group with RDP from anywhere - VIOLATION
resource "aws_security_group" "insecure_rdp" {
  name        = "insecure-rdp-sg"
  description = "INSECURE: Allows RDP from anywhere"
  vpc_id      = aws_vpc.insecure.id

  ingress {
    description = "RDP from anywhere - INSECURE"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Unrestricted RDP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security group with wide port range from anywhere - VIOLATION
resource "aws_security_group" "insecure_wide_open" {
  name        = "insecure-wide-open-sg"
  description = "INSECURE: Wide port range from anywhere"
  vpc_id      = aws_vpc.insecure.id

  ingress {
    description = "Wide port range from anywhere - INSECURE"
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Wide open ports
  }
}

# -----------------------------------------------------------------------------
# KSI-SVC-02 VIOLATIONS: Missing/Weak Encryption
# -----------------------------------------------------------------------------

resource "aws_lb" "insecure" {
  name               = "insecure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.insecure_wide_open.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

# HTTP listener without redirect - VIOLATION
resource "aws_lb_listener" "http_no_redirect" {
  load_balancer_arn = aws_lb.insecure.arn
  port              = 8080
  protocol          = "HTTP"  # VIOLATION: HTTP on non-80 port without redirect

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.insecure.arn
  }
}

# HTTPS listener with weak TLS policy - VIOLATION
resource "aws_lb_listener" "weak_tls" {
  load_balancer_arn = aws_lb.insecure.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"  # VIOLATION: Weak TLS
  certificate_arn   = aws_acm_certificate.insecure.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.insecure.arn
  }
}

resource "aws_lb_target_group" "insecure" {
  name     = "insecure-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.insecure.id
}

resource "aws_acm_certificate" "insecure" {
  domain_name       = "insecure.example.com"
  validation_method = "DNS"
}

# CloudFront allowing HTTP - VIOLATION
resource "aws_cloudfront_distribution" "insecure" {
  enabled = true
  comment = "INSECURE CloudFront - allows HTTP"

  origin {
    domain_name = aws_lb.insecure.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"  # VIOLATION: HTTP only
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1", "TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "alb"
    viewer_protocol_policy = "allow-all"  # VIOLATION: Allows HTTP

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"  # VIOLATION: Weak TLS
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

# Elasticsearch without encryption - VIOLATION
resource "aws_opensearch_domain" "insecure" {
  domain_name    = "insecure-domain"
  engine_version = "OpenSearch_2.5"

  cluster_config {
    instance_type = "t3.small.search"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # VIOLATION: No node-to-node encryption
  node_to_node_encryption {
    enabled = false
  }

  # VIOLATION: HTTPS not enforced
  domain_endpoint_options {
    enforce_https = false
  }
}

# -----------------------------------------------------------------------------
# KSI-IAM-01 VIOLATIONS: Missing MFA Requirements
# -----------------------------------------------------------------------------

# IAM policy without MFA condition for sensitive actions - VIOLATION
resource "aws_iam_policy" "sensitive_no_mfa" {
  name        = "sensitive-actions-no-mfa"
  description = "INSECURE: Allows sensitive actions without MFA"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSensitiveActionsNoMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "kms:Decrypt",
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
        # VIOLATION: No MFA condition
      }
    ]
  })
}

# IAM role assumable without MFA - VIOLATION
resource "aws_iam_role" "admin_no_mfa" {
  name = "admin-role-no-mfa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:user/admin"
        }
        Action = "sts:AssumeRole"
        # VIOLATION: No MFA condition in trust policy
      }
    ]
  })
}

# IAM user created without MFA in plan - WARNING
resource "aws_iam_user" "no_mfa_user" {
  name = "user-without-mfa"
  # No MFA device created in this plan
}

resource "aws_iam_user_login_profile" "no_mfa_user" {
  user = aws_iam_user.no_mfa_user.name
  # WARNING: Login profile without MFA enforcement
}

# -----------------------------------------------------------------------------
# KSI-SVC-06 VIOLATIONS: Poor Secrets Management
# -----------------------------------------------------------------------------

# Secrets Manager secret without CMK - VIOLATION
resource "aws_secretsmanager_secret" "no_cmk" {
  name = "secret-without-cmk"
  # VIOLATION: No kms_key_id - uses AWS managed key
  # VIOLATION: No rotation configured
}

# KMS key without rotation - VIOLATION
resource "aws_kms_key" "no_rotation" {
  description             = "KMS key without rotation"
  deletion_window_in_days = 7  # WARNING: Short deletion window
  enable_key_rotation     = false  # VIOLATION: No rotation
}

# SSM Parameter as String instead of SecureString - VIOLATION
resource "aws_ssm_parameter" "insecure_password" {
  name  = "/app/database-password"  # Name suggests secret
  type  = "String"  # VIOLATION: Should be SecureString
  value = "insecure-password-in-plain-text"
}

# SSM SecureString without CMK - VIOLATION
resource "aws_ssm_parameter" "no_cmk" {
  name  = "/app/api-secret"
  type  = "SecureString"
  value = "secret-value"
  # VIOLATION: No key_id - uses AWS managed key
}

# Lambda with secrets in environment variables - WARNING
resource "aws_lambda_function" "secrets_in_env" {
  function_name = "function-with-secrets-in-env"
  role          = aws_iam_role.lambda_insecure.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = data.archive_file.lambda_placeholder.output_path

  environment {
    variables = {
      DATABASE_PASSWORD = "super-secret-password"  # WARNING: Secret in env var
      API_KEY           = "sk-1234567890"  # WARNING: Secret in env var
    }
  }
}

resource "aws_iam_role" "lambda_insecure" {
  name = "lambda-insecure-role"

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

# ECS task with secrets in environment - WARNING
resource "aws_ecs_task_definition" "secrets_in_env" {
  family = "task-with-secrets-in-env"
  container_definitions = jsonencode([
    {
      name  = "app"
      image = "nginx:latest"
      environment = [
        {
          name  = "DB_PASSWORD"  # WARNING: Secret in env var
          value = "password123"
        },
        {
          name  = "API_TOKEN"  # WARNING: Secret in env var
          value = "token-12345"
        }
      ]
    }
  ])
}

# -----------------------------------------------------------------------------
# Supporting Resources
# -----------------------------------------------------------------------------

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.insecure.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.insecure.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"
}

data "archive_file" "lambda_placeholder" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"

  source {
    content  = "def handler(event, context): pass"
    filename = "index.py"
  }
}
