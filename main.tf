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
  tags                        = var.tags
}

# CloudFront Module - Distribution references S3 buckets
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
  acm_certificate_arn           = var.enable_domain ? module.dns[0].certificate_arn : null
  domain_aliases                = var.enable_domain ? concat([var.domain_name], ["www.${var.domain_name}"], var.alternate_domain_names) : []
  enable_security_headers       = var.enable_security_headers
  content_security_policy       = var.content_security_policy
  enable_spa_routing            = var.enable_spa_routing
  wait_for_deployment           = var.wait_for_deployment
  ignore_alias_conflicts        = var.ignore_alias_conflicts
  tags                          = var.tags
}


# Validation for DNS configuration
locals {
  validate_dns_config = (
    var.enable_domain && !var.create_route53_zone && var.existing_route53_zone_id == null
    ? file("ERROR: existing_route53_zone_id must be provided when enable_domain is true and create_route53_zone is false")
    : "validation_passed"
  )
}

# DNS Module (conditional - only if custom domain is enabled)
module "dns" {
  count  = var.enable_domain ? 1 : 0
  source = "./modules/dns"

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  enabled                         = true
  domain_name                     = var.domain_name
  alternate_domain_names          = var.alternate_domain_names
  create_hosted_zone              = var.create_route53_zone
  existing_zone_id                = var.existing_route53_zone_id
  cloudfront_distribution_domain  = module.cloudfront.distribution_domain_name
  cloudfront_distribution_zone_id = module.cloudfront.distribution_hosted_zone_id
  tags                            = var.tags
}
