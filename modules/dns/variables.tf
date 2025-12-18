variable "enabled" {
  type        = bool
  description = "Enable DNS module"
}

variable "domain_name" {
  type        = string
  description = "Primary domain name"
}

variable "create_hosted_zone" {
  type        = bool
  description = "Create new Route 53 hosted zone"
  default     = false
}

variable "create_dns_records" {
  type        = bool
  description = "Create DNS A/AAAA records pointing to CloudFront"
  default     = false
}

variable "create_www_records" {
  type        = bool
  description = "Create www subdomain DNS records (only for root domains)"
  default     = false
}

variable "existing_zone_id" {
  type        = string
  description = "Existing Route 53 zone ID (if not creating new zone)"
  default     = null
}

variable "cloudfront_distribution_domain" {
  type        = string
  description = "CloudFront distribution domain name"
  default     = ""
}

variable "cloudfront_distribution_zone_id" {
  type        = string
  description = "CloudFront distribution hosted zone ID"
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}
