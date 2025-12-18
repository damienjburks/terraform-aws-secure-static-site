terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.26"
      configuration_aliases = [
        aws.primary,
        aws.failover,
        aws.us_east_1
      ]
    }
  }
}
