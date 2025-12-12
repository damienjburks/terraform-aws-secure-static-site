terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.26"
      configuration_aliases = [aws.us_east_1]
    }
  }
}


# ACM Certificate (must be in us-east-1 for CloudFront)
resource "aws_acm_certificate" "main" {
  count = var.enabled ? 1 : 0

  provider = aws.us_east_1

  domain_name               = var.domain_name
  subject_alternative_names = var.alternate_domain_names
  validation_method         = "DNS"

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# KMS Key for DNS query logs
resource "aws_kms_key" "dns_logs" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  description             = "KMS key for Route 53 DNS query log encryption"
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
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.us-east-1.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

# Data source for current account
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for Route 53 DNS queries
resource "aws_cloudwatch_log_group" "dns_queries" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.dns_logs[0].arn

  tags = var.tags

  depends_on = [aws_kms_key.dns_logs]
}

# Route 53 Hosted Zone
resource "aws_route53_zone" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  name = var.domain_name

  tags = var.tags
}

# Route 53 DNS Query Logging
resource "aws_route53_query_log" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_queries[0].arn
  zone_id                  = aws_route53_zone.main[0].zone_id

  depends_on = [aws_cloudwatch_log_group.dns_queries]
}

# Route 53 Records for ACM Validation
resource "aws_route53_record" "cert_validation" {
  for_each = var.enabled ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
}

# ACM Certificate Validation
resource "aws_acm_certificate_validation" "main" {
  count = var.enabled ? 1 : 0

  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  timeouts {
    create = "45m"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# DNSSEC Key Signing Key for Route 53
resource "aws_route53_key_signing_key" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  hosted_zone_id             = aws_route53_zone.main[0].id
  key_management_service_arn = aws_kms_key.dns_logs[0].arn
  name                       = "${replace(var.domain_name, ".", "-")}-ksk"

  depends_on = [aws_route53_zone.main, aws_kms_key.dns_logs]
}

# Enable DNSSEC for Route 53 Hosted Zone
resource "aws_route53_hosted_zone_dnssec" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  hosted_zone_id = aws_route53_zone.main[0].id

  depends_on = [aws_route53_key_signing_key.main]
}

# Route 53 A Record (IPv4)
resource "aws_route53_record" "a" {
  count = var.enabled ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.cloudfront_distribution_domain
    zone_id                = var.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

# Route 53 AAAA Record (IPv6)
resource "aws_route53_record" "aaaa" {
  count = var.enabled ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = var.domain_name
  type    = "AAAA"

  alias {
    name                   = var.cloudfront_distribution_domain
    zone_id                = var.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}


