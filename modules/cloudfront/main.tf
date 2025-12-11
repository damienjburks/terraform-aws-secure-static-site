terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
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
  aliases                = var.ignore_alias_conflicts ? [] : var.domain_aliases
  wait_for_deployment    = var.wait_for_deployment

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

  # Restrictions
  restrictions {
    geo_restriction {
      restriction_type = "none"
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
