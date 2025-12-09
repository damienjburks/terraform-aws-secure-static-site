terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0.0"
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

# Route 53 Hosted Zone
resource "aws_route53_zone" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  name = var.domain_name

  tags = var.tags
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

# Route 53 CNAME Record for www subdomain
resource "aws_route53_record" "www" {
  count = var.enabled ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = "www"
  type    = "CNAME"
  ttl     = 300
  records = [var.domain_name]
}
