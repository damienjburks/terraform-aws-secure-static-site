terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.26"
      configuration_aliases = [aws.primary, aws.us_east_1, aws.failover]
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {
  provider = aws.primary
}

data "aws_region" "current" {
  provider = aws.primary
}

# CloudTrail S3 Bucket for logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  provider = aws.primary

  bucket = "${var.bucket_prefix}-cloudtrail-logs"

  tags = merge(
    var.tags,
    {
      Name = "${var.bucket_prefix}-cloudtrail-logs"
      Type = "cloudtrail-logs"
    }
  )
}

# CloudTrail S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail S3 Access Logging Bucket
resource "aws_s3_bucket" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = "${var.bucket_prefix}-cloudtrail-access-logs"

  tags = merge(
    var.tags,
    {
      Name = "${var.bucket_prefix}-cloudtrail-access-logs"
      Type = "cloudtrail-access-logs"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# CloudTrail Access Logs Bucket Versioning
resource "aws_s3_bucket_versioning" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CloudTrail S3 Bucket Encryption (updated to use KMS)
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# CloudTrail S3 Bucket Access Logging
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  target_bucket = aws_s3_bucket.cloudtrail_access_logs.id
  target_prefix = "access-logs/"
}

# S3 Access Logging for CloudTrail Access Logs Bucket (self-logging)
resource "aws_s3_bucket_logging" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  target_bucket = aws_s3_bucket.cloudtrail_access_logs.id
  target_prefix = "self-access-logs/"
}

# CloudTrail S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CloudTrail S3 Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "cloudtrail_logs_lifecycle"
    status = "Enabled"

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs]
}

# CloudTrail S3 Bucket Policy
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.bucket_prefix}-cloudtrail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.bucket_prefix}-cloudtrail"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
          aws_s3_bucket.cloudtrail_logs.arn
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# S3 Lifecycle Configuration - CloudTrail Access Logs Bucket
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  rule {
    id     = "cloudtrail_access_logs_lifecycle"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_access_logs]
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  provider = aws.primary

  name              = "/aws/cloudtrail/${var.bucket_prefix}-cloudtrail"
  retention_in_days = var.cloudtrail_log_retention_days
  kms_key_id        = aws_kms_key.cloudtrail.arn

  tags = var.tags

  depends_on = [aws_kms_key.cloudtrail]
}

# CloudWatch Log Stream for CloudTrail
resource "aws_cloudwatch_log_stream" "cloudtrail" {
  provider = aws.primary

  name           = "${var.bucket_prefix}-cloudtrail-stream"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
}

# IAM Role for CloudTrail to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  provider = aws.primary

  name = "${var.bucket_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for CloudTrail to CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  provider = aws.primary

  name = "${var.bucket_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:${aws_cloudwatch_log_stream.cloudtrail.name}"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream"
        ]
        Resource = aws_cloudwatch_log_group.cloudtrail.arn
      }
    ]
  })
}

# Failover CloudTrail S3 Bucket for logs
resource "aws_s3_bucket" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = "${var.bucket_prefix}-cloudtrail-logs-${var.failover_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_prefix}-cloudtrail-logs-${var.failover_region}"
      Type   = "cloudtrail-logs-failover"
      Region = var.failover_region
    }
  )
}

# Failover CloudTrail S3 Access Logging Bucket
resource "aws_s3_bucket" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = "${var.bucket_prefix}-cloudtrail-access-logs-${var.failover_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_prefix}-cloudtrail-access-logs-${var.failover_region}"
      Type   = "cloudtrail-access-logs-failover"
      Region = var.failover_region
    }
  )
}

# Failover CloudTrail S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Failover bucket encryption configurations
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_failover
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_failover
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Failover bucket versioning
resource "aws_s3_bucket_versioning" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Failover bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Failover bucket logging configurations
resource "aws_s3_bucket_logging" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  target_bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id
  target_prefix = "failover-cloudtrail-access-logs/"
}

resource "aws_s3_bucket_logging" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  target_bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id
  target_prefix = "failover-self-access-logs/"
}

# Lifecycle configurations for failover security buckets
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  rule {
    id     = "cloudtrail_logs_failover_lifecycle"
    status = "Enabled"

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs_failover]
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  rule {
    id     = "cloudtrail_access_logs_failover_lifecycle"
    status = "Enabled"

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_access_logs_failover]
}

# KMS Key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  provider = aws.primary

  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.bucket_prefix}-cloudtrail"
          }
        }
      },
      {
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.id}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/cloudtrail/${var.bucket_prefix}-cloudtrail"
          }
        }
      },
      {
        Sid    = "AllowSNSEncryption"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.bucket_prefix}-cloudtrail-key"
    }
  )
}

resource "aws_kms_alias" "cloudtrail" {
  provider = aws.primary

  name          = "alias/${var.bucket_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# SNS Topic for CloudTrail notifications
resource "aws_sns_topic" "cloudtrail" {
  provider = aws.primary

  name              = "${var.bucket_prefix}-cloudtrail-notifications"
  kms_master_key_id = aws_kms_key.cloudtrail.id

  tags = var.tags
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  provider = aws.primary

  name           = "${var.bucket_prefix}-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket

  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  sns_topic_name                = aws_sns_topic.cloudtrail.name

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type                  = "All"
    include_management_events        = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }

  }

  tags = var.tags

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]
}

# SNS Topic for Security S3 Event Notifications
resource "aws_sns_topic" "security_s3_notifications" {
  provider = aws.primary

  name              = "${var.bucket_prefix}-security-s3-notifications"
  kms_master_key_id = aws_kms_key.cloudtrail.id

  tags = var.tags
}

# S3 Event Notifications - CloudTrail Logs Bucket
resource "aws_s3_bucket_notification" "cloudtrail_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id

  topic {
    topic_arn = aws_sns_topic.security_s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.security_s3_notifications]
}

# S3 Event Notifications - CloudTrail Access Logs Bucket
resource "aws_s3_bucket_notification" "cloudtrail_access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  topic {
    topic_arn = aws_sns_topic.security_s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.security_s3_notifications]
}

# S3 bucket notifications for failover security buckets
resource "aws_s3_bucket_notification" "cloudtrail_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_logs_failover.id

  topic {
    topic_arn = aws_sns_topic.security_s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.security_s3_notifications]
}

resource "aws_s3_bucket_notification" "cloudtrail_access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.cloudtrail_access_logs_failover.id

  topic {
    topic_arn = aws_sns_topic.security_s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.security_s3_notifications]
}

# CloudWatch Alarms for Security Events
resource "aws_cloudwatch_metric_alarm" "root_access" {
  provider = aws.primary

  alarm_name          = "${var.bucket_prefix}-root-access-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccessCount"
  namespace           = "LogMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "This metric monitors root access events"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  tags = var.tags
}

resource "aws_cloudwatch_log_metric_filter" "root_access" {
  provider = aws.primary

  name           = "RootAccessFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccessCount"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  provider = aws.primary

  alarm_name          = "${var.bucket_prefix}-console-signin-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleSigninFailureCount"
  namespace           = "LogMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "3"
  alarm_description   = "This metric monitors console signin failures"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  tags = var.tags
}

resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  provider = aws.primary

  name           = "ConsoleSigninFailuresFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"

  metric_transformation {
    name      = "ConsoleSigninFailureCount"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  provider = aws.primary

  alarm_name          = "${var.bucket_prefix}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedApiCallCount"
  namespace           = "LogMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "This metric monitors unauthorized API calls"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  tags = var.tags
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  provider = aws.primary

  name           = "UnauthorizedApiCallsFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedApiCallCount"
    namespace = "LogMetrics"
    value     = "1"
  }
}

# IAM Role for S3 Cross-Region Replication
resource "aws_iam_role" "cloudtrail_replication" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  name = "${var.bucket_prefix}-cloudtrail-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for CloudTrail S3 Cross-Region Replication
resource "aws_iam_role_policy" "cloudtrail_replication" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  name = "${var.bucket_prefix}-cloudtrail-replication-policy"
  role = aws_iam_role.cloudtrail_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          aws_s3_bucket.cloudtrail_access_logs.arn
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.primary_region
          }
        }
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
          "${aws_s3_bucket.cloudtrail_access_logs.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.primary_region
          }
        }
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs_failover.arn}/*",
          "${aws_s3_bucket.cloudtrail_access_logs_failover.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.failover_region
          }
        }
      }
    ]
  })
}

# S3 Cross-Region Replication for CloudTrail Logs Bucket
resource "aws_s3_bucket_replication_configuration" "cloudtrail_logs_to_failover" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_logs.id
  role   = aws_iam_role.cloudtrail_replication[0].arn

  rule {
    id     = "replicate-cloudtrail-logs"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.cloudtrail_logs_failover.arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.cloudtrail_logs_failover
  ]
}

# S3 Cross-Region Replication for CloudTrail Access Logs Bucket
resource "aws_s3_bucket_replication_configuration" "cloudtrail_access_logs_to_failover" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  bucket = aws_s3_bucket.cloudtrail_access_logs.id
  role   = aws_iam_role.cloudtrail_replication[0].arn

  rule {
    id     = "replicate-cloudtrail-access-logs"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.cloudtrail_access_logs_failover.arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.cloudtrail_access_logs_failover
  ]
}