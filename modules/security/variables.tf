variable "bucket_prefix" {
  type        = string
  description = "Prefix for S3 bucket names used in security resources"
}

variable "cloudtrail_log_retention_days" {
  type        = number
  description = "Number of days to retain CloudTrail logs in S3"
  default     = 90
}

variable "cloudwatch_log_retention_days" {
  type        = number
  description = "Number of days to retain CloudWatch logs"
  default     = 30
}

variable "alarm_sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for security alarms (optional)"
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}

variable "primary_region" {
  type        = string
  description = "Primary AWS region for S3 buckets"
  default     = "us-east-1"
}

variable "failover_region" {
  type        = string
  description = "Failover AWS region for S3 buckets"
  default     = "us-west-2"
}

variable "enable_replication" {
  type        = bool
  description = "Enable S3 cross-region replication"
  default     = true
}

variable "kms_key_arn_primary" {
  type        = string
  description = "ARN of KMS key for encryption in primary region"
}

variable "kms_key_arn_failover" {
  type        = string
  description = "ARN of KMS key for encryption in failover region"
}