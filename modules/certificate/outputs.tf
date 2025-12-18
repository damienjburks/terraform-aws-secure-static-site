output "certificate_arn" {
  description = "ACM certificate ARN (validated if auto_validate=true, otherwise unvalidated)"
  value = var.enabled ? (
    var.auto_validate ? aws_acm_certificate_validation.main[0].certificate_arn : aws_acm_certificate.main[0].arn
  ) : null
}

output "certificate_domain_validation_options" {
  description = "Certificate domain validation options (for external validation when auto_validate=false)"
  value       = var.enabled ? aws_acm_certificate.main[0].domain_validation_options : []
}