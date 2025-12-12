variable "primary_origin_bucket_domain" {
  type        = string
  description = "Primary S3 bucket regional domain name"
}

variable "primary_origin_bucket_id" {
  type        = string
  description = "Primary S3 bucket name for origin ID"
}

variable "failover_origin_bucket_domain" {
  type        = string
  description = "Failover S3 bucket regional domain name"
}

variable "failover_origin_bucket_id" {
  type        = string
  description = "Failover S3 bucket name for origin ID"
}

variable "enable_failover" {
  type        = bool
  description = "Enable origin group failover"
  default     = true
}

variable "logging_enabled" {
  type        = bool
  description = "Enable access logging"
  default     = true
}

variable "logging_bucket_domain" {
  type        = string
  description = "Logs bucket domain"
  default     = null
}

variable "price_class" {
  type        = string
  description = "CloudFront price class"
  default     = "PriceClass_100"
}

variable "comment" {
  type        = string
  description = "Distribution comment"
  default     = "Static website distribution"
}

variable "acm_certificate_arn" {
  type        = string
  description = "Optional ACM certificate ARN"
  default     = null
}

variable "domain_aliases" {
  type        = list(string)
  description = "Optional list of domain aliases"
  default     = []
}

variable "enable_security_headers" {
  type        = bool
  description = "Enable security headers policy"
  default     = true
}

variable "content_security_policy" {
  type        = string
  description = "Content Security Policy header value. Use 'default-src 'self'' for strict policy, or customize for your needs (e.g., allow external resources)"
  default     = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';"
}

variable "enable_spa_routing" {
  type        = bool
  description = "Enable SPA routing by redirecting 404 errors to index.html (required for React, Vue, Angular, Docusaurus, etc.)"
  default     = false
}

variable "wait_for_deployment" {
  type        = bool
  description = "Wait for CloudFront distribution deployment to complete"
  default     = true
}

variable "ignore_alias_conflicts" {
  type        = bool
  description = "Temporarily disable domain aliases to avoid CNAME conflicts during updates"
  default     = false
}

variable "cache_control_header" {
  type        = string
  description = "Cache-Control header value to add to all responses"
  default     = "no-cache, no-store, must-revalidate"
}

variable "allowed_countries" {
  type        = list(string)
  description = "List of allowed country codes for geo-restriction. If null, defaults to common countries (US, CA, GB, AU, DE, FR, etc.)"
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}
