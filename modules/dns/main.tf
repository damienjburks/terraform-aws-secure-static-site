terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

# Route 53 Hosted Zone
resource "aws_route53_zone" "main" {
  count = var.enabled && var.create_hosted_zone ? 1 : 0

  name = var.domain_name

  tags = var.tags
}

# Route 53 A Record (IPv4)
resource "aws_route53_record" "a" {
  count = var.enabled && var.create_dns_records ? 1 : 0

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
  count = var.enabled && var.create_dns_records ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = var.domain_name
  type    = "AAAA"

  alias {
    name                   = var.cloudfront_distribution_domain
    zone_id                = var.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

# Route 53 A Record for WWW subdomain (IPv4) - only for root domains
resource "aws_route53_record" "www_a" {
  count = var.enabled && var.create_dns_records && var.create_www_records ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.cloudfront_distribution_domain
    zone_id                = var.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

# Route 53 AAAA Record for WWW subdomain (IPv6) - only for root domains
resource "aws_route53_record" "www_aaaa" {
  count = var.enabled && var.create_dns_records && var.create_www_records ? 1 : 0

  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
  name    = "www.${var.domain_name}"
  type    = "AAAA"

  alias {
    name                   = var.cloudfront_distribution_domain
    zone_id                = var.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}


