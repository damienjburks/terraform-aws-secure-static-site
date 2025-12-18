output "zone_id" {
  description = "Route 53 zone ID"
  value       = var.enabled && var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : var.existing_zone_id
}

output "zone_nameservers" {
  description = "Route 53 zone nameservers"
  value       = var.enabled && var.create_hosted_zone ? aws_route53_zone.main[0].name_servers : null
}
