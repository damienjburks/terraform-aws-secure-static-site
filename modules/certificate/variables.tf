variable "enabled" {
  type        = bool
  description = "Enable certificate creation"
}

variable "domain_name" {
  type        = string
  description = "Primary domain name"
}

variable "alternate_domain_names" {
  type        = list(string)
  description = "Additional domain names"
  default     = []
}

variable "auto_validate" {
  type        = bool
  description = "Automatically validate certificate using DNS (requires Route53 zone)"
  default     = true
}

variable "zone_id" {
  type        = string
  description = "Route 53 zone ID for certificate validation (required if auto_validate is true)"
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}