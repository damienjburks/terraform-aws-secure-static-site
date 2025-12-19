# AWS Provider Configuration
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "failover"
  region = var.failover_region

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = var.tags
  }
}


# Local values for KMS key management
locals {
  create_kms_keys      = var.kms_key_arn == null
  kms_key_arn_primary  = local.create_kms_keys ? module.kms[0].key_arn_primary : var.kms_key_arn
  kms_key_arn_failover = local.create_kms_keys ? module.kms[0].key_arn_failover : var.kms_key_arn
}

# KMS Module
module "kms" {
  count  = local.create_kms_keys ? 1 : 0
  source = "./modules/kms"

  providers = {
    aws.primary  = aws.primary
    aws.failover = aws.failover
  }

  create_keys               = true
  primary_region            = var.primary_region
  failover_region           = var.failover_region
  existing_key_arn_primary  = null
  existing_key_arn_failover = null
  alias_name                = var.bucket_name
  tags                      = var.tags
}


# S3 Module - Buckets created first, policies reference CloudFront
module "s3" {
  source = "./modules/s3"

  providers = {
    aws.primary  = aws.primary
    aws.failover = aws.failover
  }

  bucket_name                 = var.bucket_name
  primary_region              = var.primary_region
  failover_region             = var.failover_region
  kms_key_arn_primary         = local.kms_key_arn_primary
  kms_key_arn_failover        = local.kms_key_arn_failover
  cloudfront_oac_arn          = module.cloudfront.oac_arn
  cloudfront_distribution_arn = module.cloudfront.distribution_arn
  enable_replication          = var.enable_replication
  enable_intelligent_tiering  = var.enable_intelligent_tiering
  enable_s3_notifications     = var.enable_s3_notifications
  tags                        = var.tags
}

# CloudFront Module - Distribution with certificate and domain aliases
module "cloudfront" {
  source = "./modules/cloudfront"

  primary_origin_bucket_domain  = module.s3.website_bucket_regional_domain_name_primary
  primary_origin_bucket_id      = module.s3.website_bucket_id_primary
  failover_origin_bucket_domain = module.s3.website_bucket_regional_domain_name_failover
  failover_origin_bucket_id     = module.s3.website_bucket_id_failover
  enable_failover               = var.enable_failover
  logging_enabled               = var.logging_enabled
  logging_bucket_domain         = var.logging_enabled ? module.s3.logs_bucket_domain_name : null
  price_class                   = var.price_class
  comment                       = var.comment
  acm_certificate_arn           = var.enable_domain ? module.certificate[0].certificate_arn : null
  domain_aliases                = local.domain_aliases
  enable_security_headers       = var.enable_security_headers
  content_security_policy       = var.content_security_policy
  enable_spa_routing            = var.enable_spa_routing
  wait_for_deployment           = var.wait_for_deployment
  cache_control_header          = var.cache_control_header
  enable_waf                    = var.enable_waf
  tags                          = var.tags

  depends_on = [module.certificate]
}


# Validation for DNS configuration
locals {
  validate_dns_config = (
    var.enable_domain && !var.create_route53_zone && var.existing_route53_zone_id == null
    ? file("ERROR: existing_route53_zone_id must be provided when enable_domain is true and create_route53_zone is false")
    : "validation_passed"
  )

  # Determine zone ID for certificate validation and DNS records
  zone_id = var.enable_domain ? (
    var.create_route53_zone ? module.dns_zone[0].zone_id : var.existing_route53_zone_id
  ) : null

  # Domain aliases for CloudFront - only add www for root domains
  is_root_domain = var.enable_domain ? length(split(".", var.domain_name)) == 2 : false
  domain_aliases = var.enable_domain ? (
    local.is_root_domain ? [var.domain_name, "www.${var.domain_name}"] : [var.domain_name]
  ) : []
}

# DNS Zone Module - Route53 Zone only (created first if needed)
module "dns_zone" {
  count  = var.enable_domain && var.create_route53_zone ? 1 : 0
  source = "./modules/dns"

  enabled                         = true
  domain_name                     = var.domain_name
  create_hosted_zone              = true
  create_dns_records              = false # Only create zone, not records
  create_www_records              = false # Not creating records in this module
  existing_zone_id                = null
  cloudfront_distribution_domain  = ""
  cloudfront_distribution_zone_id = ""
  tags                            = var.tags
}

# Certificate Module - ACM Certificate (with optional auto-validation)
module "certificate" {
  count  = var.enable_domain ? 1 : 0
  source = "./modules/certificate"

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  enabled                = true
  domain_name            = var.domain_name
  alternate_domain_names = var.alternate_domain_names
  auto_validate          = var.auto_validate_certificate
  zone_id                = var.auto_validate_certificate ? local.zone_id : null
  tags                   = var.tags
}

# DNS Records Module - A/AAAA records pointing to CloudFront (after CloudFront exists)
module "dns_records" {
  count  = var.enable_domain ? 1 : 0
  source = "./modules/dns"

  enabled                         = true
  domain_name                     = var.domain_name
  create_hosted_zone              = false                # Zone already exists
  create_dns_records              = true                 # Create DNS records
  create_www_records              = local.is_root_domain # Only for root domains
  existing_zone_id                = local.zone_id
  cloudfront_distribution_domain  = module.cloudfront.distribution_domain_name
  cloudfront_distribution_zone_id = module.cloudfront.distribution_hosted_zone_id
  tags                            = var.tags

  depends_on = [module.cloudfront]
}

# Security Module - CloudTrail and Monitoring (disabled for now due to configuration complexity)
# module "security" {
#   source = "./modules/security"
#
#   providers = {
#     aws.primary   = aws.primary
#     aws.us_east_1 = aws.us_east_1
#     aws.failover  = aws.failover
#   }
#
#   bucket_prefix                 = var.bucket_name
#   cloudtrail_log_retention_days = var.cloudtrail_log_retention_days
#   cloudwatch_log_retention_days = var.cloudwatch_log_retention_days
#   alarm_sns_topic_arn           = var.alarm_sns_topic_arn
#   primary_region                = var.primary_region
#   failover_region               = var.failover_region
#   enable_replication            = var.enable_replication
#   kms_key_arn_primary           = local.kms_key_arn_primary
#   kms_key_arn_failover          = local.kms_key_arn_failover
#   tags                          = var.tags
# }
