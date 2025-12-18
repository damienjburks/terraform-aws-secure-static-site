terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "static_website" {
  source = "../.."

  bucket_name             = var.bucket_name
  enable_domain           = true
  logging_enabled         = true
  enable_failover         = true
  enable_replication      = true
  enable_security_headers = true
  enable_spa_routing      = true
  create_route53_zone     = true
  primary_region          = var.primary_region
  failover_region         = var.failover_region

  domain_name = "dev.devsecblueprint.com"

  tags = {
    Environment = "Development"
    ManagedBy   = "Terraform Cloud"
  }
}
