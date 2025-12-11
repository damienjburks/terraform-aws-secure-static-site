terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0.0"
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

# ACL Configuration for Logging Bucket (required for CloudFront logging)
resource "aws_s3_bucket_ownership_controls" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id
  acl    = "log-delivery-write"

  depends_on = [aws_s3_bucket_ownership_controls.logs]
}


# Block Public Access - Primary Website Bucket
resource "aws_s3_bucket_public_access_block" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

# Block Public Access - Failover Website Bucket
resource "aws_s3_bucket_public_access_block" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

# Block Public Access - Logs Bucket (allow ACLs for CloudFront logging)
resource "aws_s3_bucket_public_access_block" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}


# SSE-AES256 Encryption - Primary Website Bucket (KMS not compatible with CloudFront OAC)
resource "aws_s3_bucket_server_side_encryption_configuration" "website_primary" {
  provider = aws.primary

  bucket = aws_s3_bucket.website_primary.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# SSE-AES256 Encryption - Failover Website Bucket (KMS not compatible with CloudFront OAC)
resource "aws_s3_bucket_server_side_encryption_configuration" "website_failover" {
  provider = aws.failover

  bucket = aws_s3_bucket.website_failover.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# SSE-AES256 Encryption - Logs Bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  provider = aws.primary

  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
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
          aws_s3_bucket.website_primary.arn
        ]
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.website_primary.arn}/*"
        ]
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.website_failover.arn}/*"
        ]
      },

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
      }
    ]
  })

}
