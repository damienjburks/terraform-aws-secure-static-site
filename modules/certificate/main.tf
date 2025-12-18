terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0.0"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

# Local values for certificate configuration
locals {
  # Check if domain is a root domain (no subdomain) by counting dots
  # Root domains like "example.com" have 1 dot, subdomains like "app.example.com" have 2+ dots
  is_root_domain = length(split(".", var.domain_name)) == 2

  # Only add www subdomain for root domains, not for existing subdomains
  www_domain = local.is_root_domain ? ["www.${var.domain_name}"] : []
}

# ACM Certificate (must be in us-east-1 for CloudFront)
resource "aws_acm_certificate" "main" {
  count = var.enabled ? 1 : 0

  provider = aws.us_east_1

  domain_name               = var.domain_name
  subject_alternative_names = concat(local.www_domain, var.alternate_domain_names)
  validation_method         = "DNS"

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# Route 53 Records for ACM Validation (optional - only if auto_validate is true)
resource "aws_route53_record" "cert_validation" {
  for_each = var.enabled && var.auto_validate ? {
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
  zone_id         = var.zone_id
}

# ACM Certificate Validation (optional - only if auto_validate is true)
resource "aws_acm_certificate_validation" "main" {
  count = var.enabled && var.auto_validate ? 1 : 0

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