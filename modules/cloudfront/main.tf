terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.26"
    }
  }
}

# WAF Web ACL for CloudFront (optional)
resource "aws_wafv2_web_acl" "cloudfront_waf" {
  count = var.enable_waf ? 1 : 0

  name        = "cloudfront-waf-${var.primary_origin_bucket_id}"
  description = "WAF Web ACL for CloudFront distribution - Static Website Optimized"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Allow static assets explicitly
  rule {
    name     = "AllowStaticAssets"
    priority = 1

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = ".html"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "ENDS_WITH"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowStaticAssetsMetric"
      sampled_requests_enabled   = true
    }
  }

  # Allow JavaScript files
  rule {
    name     = "AllowJavaScript"
    priority = 2

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = ".js"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "ENDS_WITH"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowJavaScriptMetric"
      sampled_requests_enabled   = true
    }
  }

  # Allow CSS files
  rule {
    name     = "AllowCSS"
    priority = 3

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = ".css"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "ENDS_WITH"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowCSSMetric"
      sampled_requests_enabled   = true
    }
  }

  # Allow image files
  rule {
    name     = "AllowImages"
    priority = 4

    action {
      allow {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = ".svg"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".png"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".ico"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".jpg"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".jpeg"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".gif"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = ".webp"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "ENDS_WITH"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowImagesMetric"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rule - IP Reputation List (only block known malicious IPs)
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IpReputationListMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rate Limiting Rule (more permissive for static sites)
  rule {
    name     = "RateLimitRule"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 10000  # Increased from 2000 to 10000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRuleMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CloudFrontWAFMetric"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# KMS Key for WAF logs (only if WAF is enabled)
resource "aws_kms_key" "waf_logs" {
  count = var.enable_waf ? 1 : 0

  description             = "KMS key for WAF log encryption"
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
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
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

  tags = var.tags
}

# Data source for current account
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for WAF (only if WAF is enabled)
resource "aws_cloudwatch_log_group" "waf_logs" {
  count = var.enable_waf ? 1 : 0

  name              = "aws-waf-logs-${var.primary_origin_bucket_id}"
  retention_in_days = 365
  kms_key_id        = var.enable_waf ? aws_kms_key.waf_logs[0].arn : null

  tags = var.tags

  depends_on = [aws_kms_key.waf_logs]
}

# WAF Logging Configuration (only if WAF is enabled)
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.enable_waf ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.cloudfront_waf[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs[0].arn]

  depends_on = [aws_cloudwatch_log_group.waf_logs]
}

# Origin Access Control for S3
resource "aws_cloudfront_origin_access_control" "main" {
  name                              = "oac-${var.primary_origin_bucket_id}"
  description                       = "Origin Access Control for ${var.primary_origin_bucket_id}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}


# Response Headers Policy for Security
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  count = var.enable_security_headers ? 1 : 0

  name    = "security-headers-${var.primary_origin_bucket_id}"
  comment = "Security headers policy for static website"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    content_security_policy {
      content_security_policy = var.content_security_policy
      override                = true
    }
  }

  custom_headers_config {
    items {
      header   = "Cache-Control"
      value    = var.cache_control_header
      override = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}


# CloudFront Distribution with Origin Group
resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = var.comment
  default_root_object = "index.html"
  price_class         = var.price_class
  aliases             = var.domain_aliases
  wait_for_deployment = var.wait_for_deployment

  # Primary Origin
  origin {
    domain_name              = var.primary_origin_bucket_domain
    origin_id                = "S3-${var.primary_origin_bucket_id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id
  }

  # Failover Origin
  origin {
    domain_name              = var.failover_origin_bucket_domain
    origin_id                = "S3-${var.failover_origin_bucket_id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id
  }

  # Origin Group for Failover
  dynamic "origin_group" {
    for_each = var.enable_failover ? [1] : []

    content {
      origin_id = "origin-group-${var.primary_origin_bucket_id}"

      failover_criteria {
        status_codes = [500, 502, 503, 504]
      }

      member {
        origin_id = "S3-${var.primary_origin_bucket_id}"
      }

      member {
        origin_id = "S3-${var.failover_origin_bucket_id}"
      }
    }
  }

  # Default Cache Behavior
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = var.enable_failover ? "origin-group-${var.primary_origin_bucket_id}" : "S3-${var.primary_origin_bucket_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    min_ttl                    = 0
    default_ttl                = 3600
    max_ttl                    = 86400
    compress                   = true
    response_headers_policy_id = var.enable_security_headers ? aws_cloudfront_response_headers_policy.security_headers[0].id : null
  }

  # Viewer Certificate
  viewer_certificate {
    cloudfront_default_certificate = var.acm_certificate_arn == null
    acm_certificate_arn            = var.acm_certificate_arn
    ssl_support_method             = var.acm_certificate_arn != null ? "sni-only" : null
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  # Logging Configuration
  dynamic "logging_config" {
    for_each = var.logging_enabled ? [1] : []

    content {
      include_cookies = false
      bucket          = var.logging_bucket_domain
      prefix          = "cloudfront/"
    }
  }

  # Custom Error Pages for SPA Routing
  dynamic "custom_error_response" {
    for_each = var.enable_spa_routing ? [1] : []

    content {
      error_code         = 404
      response_code      = 200
      response_page_path = "/index.html"
    }
  }

  dynamic "custom_error_response" {
    for_each = var.enable_spa_routing ? [1] : []

    content {
      error_code         = 403
      response_code      = 200
      response_page_path = "/index.html"
    }
  }

  # WAF Association (optional)
  web_acl_id = var.enable_waf ? aws_wafv2_web_acl.cloudfront_waf[0].arn : null

  # Restrictions
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = var.allowed_countries != null ? var.allowed_countries : ["US", "CA", "GB", "AU", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "DK", "FI", "JP", "KR", "SG", "BR", "MX"]
    }
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_cloudfront_response_headers_policy.security_headers
  ]
}
