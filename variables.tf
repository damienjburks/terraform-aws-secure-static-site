variable "bucket_name" {
  type        = string
  description = "Name of the S3 bucket for website content (must be globally unique)"
}

variable "enable_domain" {
  type        = bool
  description = "Enable custom domain support with ACM and Route 53"
  default     = false
}

variable "domain_name" {
  type        = string
  description = "Primary domain name for the website (required if enable_domain is true)"
  default     = null
}

variable "alternate_domain_names" {
  type        = list(string)
  description = "List of alternate domain names (CNAMEs) for CloudFront"
  default     = []
}

variable "create_route53_zone" {
  type        = bool
  description = "Create a new Route 53 hosted zone for the domain"
  default     = false
}

variable "existing_route53_zone_id" {
  type        = string
  description = "Existing Route 53 hosted zone ID (required if enable_domain is true and create_route53_zone is false)"
  default     = null
}

variable "logging_enabled" {
  type        = bool
  description = "Enable CloudFront access logging"
  default     = true
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of existing KMS key for S3 encryption (creates new keys if not provided)"
  default     = null
}

variable "price_class" {
  type        = string
  description = "CloudFront price class (PriceClass_All, PriceClass_200, PriceClass_100)"
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_All", "PriceClass_200", "PriceClass_100"], var.price_class)
    error_message = "price_class must be one of: PriceClass_All, PriceClass_200, PriceClass_100"
  }
}

variable "comment" {
  type        = string
  description = "Comment for the CloudFront distribution"
  default     = "Static website distribution"
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to all resources"
  default     = {}
}

variable "primary_region" {
  type        = string
  description = "Primary AWS region for S3 bucket (e.g., us-east-1). Recommended pairs: us-east-1/us-west-2, eu-west-1/eu-central-1, ap-southeast-1/ap-northeast-1"
  default     = "us-east-1"
}

variable "failover_region" {
  type        = string
  description = "Failover AWS region for S3 bucket (e.g., us-west-2). Should be in different geographic area than primary. Recommended pairs: us-east-1/us-west-2, eu-west-1/eu-central-1, ap-southeast-1/ap-northeast-1"
  default     = "us-west-2"
}

variable "enable_failover" {
  type        = bool
  description = "Enable multi-region failover with S3 buckets in primary and failover regions"
  default     = true
}

variable "enable_replication" {
  type        = bool
  description = "Enable S3 cross-region replication from primary to failover region"
  default     = true
}

variable "enable_security_headers" {
  type        = bool
  description = "Enable CloudFront response headers policy with security headers"
  default     = true
}

variable "content_security_policy" {
  type        = string
  description = "Content Security Policy header value. Default allows common external resources. Use 'default-src 'self'' for strict policy."
  default     = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';"
}

variable "enable_spa_routing" {
  type        = bool
  description = "Enable Single Page Application (SPA) routing by redirecting 404/403 errors to index.html. Required for React, Vue, Angular, Docusaurus, and other client-side routing frameworks."
  default     = false
}

variable "wait_for_deployment" {
  type        = bool
  description = "Wait for CloudFront distribution deployment to complete (can be disabled for faster applies)"
  default     = true
}

variable "ignore_alias_conflicts" {
  type        = bool
  description = "Temporarily disable domain aliases to avoid CNAME conflicts during updates (set to true if you get CNAMEAlreadyExists errors)"
  default     = false
}

variable "cache_control_header" {
  type        = string
  description = "Cache-Control header value to add to all responses from CloudFront"
  default     = "no-cache, no-store, must-revalidate"
}

variable "cloudtrail_log_retention_days" {
  type        = number
  description = "Number of days to retain CloudTrail logs in S3"
  default     = 365
}

variable "cloudwatch_log_retention_days" {
  type        = number
  description = "Number of days to retain CloudWatch logs"
  default     = 365
}

variable "alarm_sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for security alarms (optional)"
  default     = null
}


