output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = module.cloudfront.distribution_domain_name
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = module.cloudfront.distribution_id
}

output "website_bucket_name" {
  description = "Name of the primary S3 bucket containing website content"
  value       = module.s3.website_bucket_id_primary
}

output "logging_bucket_name" {
  description = "Name of the S3 bucket containing CloudFront logs"
  value       = module.s3.logs_bucket_id
}

output "route53_nameservers" {
  description = "Nameservers for the Route 53 hosted zone (if created)"
  value       = var.enable_domain && var.create_route53_zone ? module.dns_zone[0].zone_nameservers : null
}

output "certificate_arn" {
  description = "ARN of the ACM certificate (if domain is enabled)"
  value       = var.enable_domain ? module.certificate[0].certificate_arn : null
}

output "route53_zone_id" {
  description = "Route 53 hosted zone ID (if created or provided)"
  value       = var.enable_domain ? local.zone_id : null
}
