terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.26"
      configuration_aliases = [aws.primary, aws.failover]
    }
  }
}

# KMS Key for Primary Region
resource "aws_kms_key" "primary" {
  count = var.create_keys ? 1 : 0

  provider = aws.primary

  description             = "KMS key for S3 bucket encryption in ${var.primary_region}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3ServiceAccess"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.primary_region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "DenyDirectAccess"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "kms:ViaService" = [
              "s3.${var.primary_region}.amazonaws.com"
            ]
          }
          Null = {
            "aws:PrincipalServiceName" = "false"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name   = "${var.alias_name}-primary"
      Region = var.primary_region
    }
  )
}

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {
  provider = aws.primary
}

resource "aws_kms_alias" "primary" {
  count = var.create_keys ? 1 : 0

  provider = aws.primary

  name          = "alias/${var.alias_name}-primary"
  target_key_id = aws_kms_key.primary[0].key_id
}

# KMS Key for Failover Region
resource "aws_kms_key" "failover" {
  count = var.create_keys ? 1 : 0

  provider = aws.failover

  description             = "KMS key for S3 bucket encryption in ${var.failover_region}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.failover.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3ServiceAccess"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.failover_region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "DenyDirectAccess"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "kms:ViaService" = [
              "s3.${var.failover_region}.amazonaws.com"
            ]
          }
          Null = {
            "aws:PrincipalServiceName" = "false"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name   = "${var.alias_name}-failover"
      Region = var.failover_region
    }
  )
}

# Data source to get current AWS account ID for failover region
data "aws_caller_identity" "failover" {
  provider = aws.failover
}

resource "aws_kms_alias" "failover" {
  count = var.create_keys ? 1 : 0

  provider = aws.failover

  name          = "alias/${var.alias_name}-failover"
  target_key_id = aws_kms_key.failover[0].key_id
}
