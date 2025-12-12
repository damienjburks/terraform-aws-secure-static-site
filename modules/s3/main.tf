terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.26"
      configuration_aliases = [aws.primary, aws.failover]
    }
  }
}


# Primary Website Bucket
resource "aws_s3_bucket" "website_primary" {
  provider = aws.primary

  bucket = "${var.bucket_name}-${var.primary_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-${var.primary_region}"
      Region = var.primary_region
      Type   = "website-primary"
    }
  )
}

# Failover Website Bucket
resource "aws_s3_bucket" "website_failover" {
  provider = aws.failover

  bucket = "${var.bucket_name}-${var.failover_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-${var.failover_region}"
      Region = var.failover_region
      Type   = "website-failover"
    }
  )
}


# Logging Bucket
resource "aws_s3_bucket" "logs" {
  provider = aws.primary

  bucket = "${var.bucket_name}-logs"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-logs"
      Region = var.primary_region
      Type   = "cloudfront-logs"
    }
  )
}

# Access Logging Bucket for S3 buckets
resource "aws_s3_bucket" "access_logs" {
  provider = aws.primary

  bucket = "${var.bucket_name}-s3-access-logs"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-s3-access-logs"
      Region = var.primary_region
      Type   = "s3-access-logs"
    }
  )
}

# Failover Logging Bucket
resource "aws_s3_bucket" "logs_failover" {
  provider = aws.failover

  bucket = "${var.bucket_name}-logs-${var.failover_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-logs-${var.failover_region}"
      Region = var.failover_region
      Type   = "cloudfront-logs-failover"
    }
  )
}

# Failover Access Logging Bucket for S3 buckets
resource "aws_s3_bucket" "access_logs_failover" {
  provider = aws.failover

  bucket = "${var.bucket_name}-s3-access-logs-${var.failover_region}"

  tags = merge(
    var.tags,
    {
      Name   = "${var.bucket_name}-s3-access-logs-${var.failover_region}"
      Region = var.failover_region
      Type   = "s3-access-logs-failover"
    }
  )
}

# Access Logs Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Failover Logging Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Failover Access Logs Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Access Logs Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_primary
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Access Logs Bucket Versioning
resource "aws_s3_bucket_versioning" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Failover Logging Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_failover
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Failover Access Logs Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_failover
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Failover Logging Bucket Versioning
resource "aws_s3_bucket_versioning" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Failover Access Logs Bucket Versioning
resource "aws_s3_bucket_versioning" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ACL Configuration for Logging Bucket (required for CloudFront logging)
resource "aws_s3_bucket_ownership_controls" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# ACL Configuration for Access Logs Bucket
resource "aws_s3_bucket_ownership_controls" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# ACL Configuration for Failover Logging Bucket
resource "aws_s3_bucket_ownership_controls" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# ACL Configuration for Failover Access Logs Bucket
resource "aws_s3_bucket_ownership_controls" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Failover buckets logging configurations
resource "aws_s3_bucket_logging" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  target_bucket = aws_s3_bucket.access_logs_failover.id
  target_prefix = "failover-cloudfront-logs/"
}

resource "aws_s3_bucket_logging" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  target_bucket = aws_s3_bucket.access_logs_failover.id
  target_prefix = "failover-access-logs/"
}

# Lifecycle configurations for failover buckets
resource "aws_s3_bucket_lifecycle_configuration" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  rule {
    id     = "logs_failover_lifecycle"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs_failover]
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  rule {
    id     = "access_logs_failover_lifecycle"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs_failover]
}

# ACL removed - BucketOwnerEnforced disables ACLs
# CloudFront now supports bucket policies for log delivery


# Block Public Access - Primary Website Bucket (secure configuration for CloudFront OAC)
resource "aws_s3_bucket_public_access_block" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Block Public Access - Failover Website Bucket (secure configuration for CloudFront OAC)
resource "aws_s3_bucket_public_access_block" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Block Public Access - Logs Bucket (secure configuration)
resource "aws_s3_bucket_public_access_block" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


# Customer-managed KMS Encryption - Primary Website Bucket
# Note: CloudFront OAC supports KMS encryption as of late 2023
resource "aws_s3_bucket_server_side_encryption_configuration" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_primary
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Customer-managed KMS Encryption - Failover Website Bucket
# Note: CloudFront OAC supports KMS encryption as of late 2023
resource "aws_s3_bucket_server_side_encryption_configuration" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_failover
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Customer-managed KMS Encryption - Logs Bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn_primary
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}


# Versioning - Primary Website Bucket
resource "aws_s3_bucket_versioning" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Versioning - Failover Website Bucket
resource "aws_s3_bucket_versioning" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Versioning - Logs Bucket
resource "aws_s3_bucket_versioning" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}


# IAM Role for S3 Replication
resource "aws_iam_role" "replication" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  name = "${var.bucket_name}-replication-role"

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

# IAM Policy for S3 Replication
resource "aws_iam_role_policy" "replication" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  name = "${var.bucket_name}-replication-policy"
  role = aws_iam_role.replication[0].id

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
          aws_s3_bucket.website_primary.arn,
          aws_s3_bucket.logs.arn,
          aws_s3_bucket.access_logs.arn
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.primary_region
          }
          DateGreaterThan = {
            "aws:CurrentTime" = "2024-01-01T00:00:00Z"
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
          "${aws_s3_bucket.website_primary.arn}/*",
          "${aws_s3_bucket.logs.arn}/*",
          "${aws_s3_bucket.access_logs.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.primary_region
          }
          StringLike = {
            "s3:x-amz-server-side-encryption" = "AES256"
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
          "${aws_s3_bucket.website_failover.arn}/*",
          "${aws_s3_bucket.logs_failover.arn}/*",
          "${aws_s3_bucket.access_logs_failover.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.failover_region
          }
          StringLike = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      }
    ]
  })
}

# S3 Replication Configuration
resource "aws_s3_bucket_replication_configuration" "primary_to_failover" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.website_failover.arn
      storage_class = "STANDARD"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.website_primary,
    aws_s3_bucket_versioning.website_failover
  ]
}

# S3 Replication Configuration for Logs Bucket
resource "aws_s3_bucket_replication_configuration" "logs_to_failover" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  bucket = aws_s3_bucket.logs.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-logs"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.logs_failover.arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.logs_failover
  ]
}

# S3 Replication Configuration for Access Logs Bucket
resource "aws_s3_bucket_replication_configuration" "access_logs_to_failover" {
  count = var.enable_replication ? 1 : 0

  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-access-logs"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.access_logs_failover.arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.access_logs_failover
  ]
}


# Bucket Policy - Primary Website Bucket
resource "aws_s3_bucket_policy" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.website_primary.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = var.cloudfront_distribution_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "${aws_s3_bucket.website_primary.arn}/*",
          aws_s3_bucket.website_primary.arn
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

# Bucket Policy - Failover Website Bucket
resource "aws_s3_bucket_policy" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.website_failover.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = var.cloudfront_distribution_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "${aws_s3_bucket.website_failover.arn}/*",
          aws_s3_bucket.website_failover.arn
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


# S3 Lifecycle Configuration - Primary Website Bucket
resource "aws_s3_bucket_lifecycle_configuration" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  rule {
    id     = "website_content_lifecycle"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.website_primary]
}

# S3 Lifecycle Configuration - Failover Website Bucket
resource "aws_s3_bucket_lifecycle_configuration" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  rule {
    id     = "website_content_lifecycle"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.website_failover]
}

# S3 Lifecycle Configuration - Logs Bucket
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "cloudfront_logs_lifecycle"
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
}

# S3 Lifecycle Configuration - Access Logs Bucket
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "access_logs_lifecycle"
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

  depends_on = [aws_s3_bucket_versioning.access_logs]
}


# MFA Delete Protection - Primary Website Bucket
resource "aws_s3_bucket_versioning" "website_primary_mfa" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }

  depends_on = [aws_s3_bucket_versioning.website_primary]
}

# MFA Delete Protection - Failover Website Bucket
resource "aws_s3_bucket_versioning" "website_failover_mfa" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }

  depends_on = [aws_s3_bucket_versioning.website_failover]
}


# Bucket Policy - Logs Bucket
resource "aws_s3_bucket_policy" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontLogging"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = var.cloudfront_distribution_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "${aws_s3_bucket.logs.arn}/*",
          aws_s3_bucket.logs.arn
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

# S3 Access Logging - Primary Website Bucket
resource "aws_s3_bucket_logging" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "primary-website-logs/"
}

# S3 Access Logging - Failover Website Bucket
resource "aws_s3_bucket_logging" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "failover-website-logs/"
}

# S3 Access Logging - CloudFront Logs Bucket
resource "aws_s3_bucket_logging" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudfront-logs-access/"
}

# S3 Access Logging - Access Logs Bucket (self-logging)
resource "aws_s3_bucket_logging" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "self-access-logs/"
}

# SNS Topic for S3 Event Notifications
resource "aws_sns_topic" "s3_notifications" {
  provider = aws.primary

  name              = "${var.bucket_name}-s3-notifications"
  kms_master_key_id = var.kms_key_arn_primary

  tags = var.tags
}

# S3 Event Notifications - Primary Website Bucket
resource "aws_s3_bucket_notification" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}

# S3 Event Notifications - Failover Website Bucket
resource "aws_s3_bucket_notification" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}

# S3 Event Notifications - Logs Bucket
resource "aws_s3_bucket_notification" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}

# S3 Event Notifications - Access Logs Bucket
resource "aws_s3_bucket_notification" "access_logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.access_logs.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}

# S3 bucket notifications for failover buckets
resource "aws_s3_bucket_notification" "logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.logs_failover.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}

resource "aws_s3_bucket_notification" "access_logs_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.access_logs_failover.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic.s3_notifications]
}
