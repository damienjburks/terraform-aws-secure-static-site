variable "bucket_name" {
  type        = string
  description = "Base name for S3 buckets"
}

variable "primary_region" {
  type        = string
  description = "Primary AWS region"
}

variable "failover_region" {
  type        = string
  description = "Failover AWS region"
}

variable "kms_key_arn_primary" {
  type        = string
  description = "KMS key ARN for primary region encryption"
}

variable "kms_key_arn_failover" {
  type        = string
  description = "KMS key ARN for failover region encryption"
}

variable "cloudfront_oac_arn" {
  type        = string
  description = "CloudFront Origin Access Control ARN"
}

variable "cloudfront_distribution_arn" {
  type        = string
  description = "CloudFront distribution ARN for bucket policies"
}

variable "enable_replication" {
  type        = bool
  description = "Enable S3 cross-region replication"
  default     = true
}

variable "enable_intelligent_tiering" {
  type        = bool
  description = "Enable S3 Intelligent Tiering for cost optimization"
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to S3 buckets"
  default     = {}
}
