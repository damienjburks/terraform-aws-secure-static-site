# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2025-12-08

### Added

- **WWW Subdomain CNAME Record**: Automatically creates a CNAME record for `www` subdomain pointing to the root domain when custom domain is enabled. This allows both `example.com` and `www.example.com` to work seamlessly.

### Changed

- **DNS Module**: Added `aws_route53_record` resource for www subdomain with 300 second TTL

## [1.0.2] - 2025-12-08

### Fixed

- **Invalid Variable Validation**: Removed cross-variable validation that was causing "Invalid reference in variable validation" error. Terraform variable validations can only reference the variable itself.
- **Invalid Lifecycle Block**: Removed lifecycle block from module declaration that was causing "Reserved block type name in module block" error. Lifecycle blocks are only supported in resource blocks, not module blocks.

### Changed

- **DNS Configuration Validation**: Replaced variable validation and lifecycle precondition with a local value validation check that triggers during `terraform plan` if `existing_route53_zone_id` is not provided when required.

## [1.0.1] - 2025-12-08

### Fixed

- **Missing Variable for Existing Route 53 Zone**: Added `existing_route53_zone_id` variable to support using an existing Route 53 hosted zone when `enable_domain = true` and `create_route53_zone = false`. Previously, the module would fail with "Missing required argument" error when trying to use an existing zone.

### Added

- **Variable Validation**: Added validation to ensure `existing_route53_zone_id` is provided when using an existing Route 53 zone (when `enable_domain = true` and `create_route53_zone = false`)

### Changed

- **DNS Module Integration**: Updated root module to pass `existing_route53_zone_id` to the DNS module instead of hardcoded `null` value

## [1.0.0] - 2025-12-08

### Added

- **Multi-Region Failover**: Automatic failover between configurable AWS regions using CloudFront origin groups
- **Cross-Region Replication**: S3 replication from primary to failover region for data durability
- **Security Headers**: Comprehensive security headers policy (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy)
- **CloudFront Origin Access Control (OAC)**: Modern OAC implementation for secure S3 access (replaces legacy OAI)
- **Private S3 Buckets**: All buckets configured with Block Public Access enabled
- **Server-Side Encryption**: AES-256 encryption at rest for all S3 buckets
- **HTTPS Enforcement**: CloudFront configured for HTTPS-only with TLS 1.2 minimum
- **Custom Domain Support**: Optional ACM certificate provisioning and Route 53 DNS management
- **Access Logging**: CloudFront access logs stored in encrypted S3 bucket
- **Modular Architecture**: Clean separation into KMS, S3, CloudFront, and DNS modules
- **Configurable Regions**: Support for any AWS region pair with recommended pairings documented
- **Comprehensive Documentation**: Detailed README with architecture diagrams, security model, and troubleshooting guide
- **Working Example**: Basic example with sample HTML files demonstrating module usage

### Security

- **Encryption at Rest**: All S3 buckets use S3-managed encryption (SSE-S3/AES-256)
- **Encryption in Transit**: TLS 1.2 minimum enforced on all CloudFront connections
- **Least Privilege Access**: S3 bucket policies restrict access exclusively to CloudFront distribution
- **Security Headers**: Response headers policy adds multiple security headers to all responses
- **Private Buckets**: No public access allowed to S3 buckets at any level

### Important Notes

- **CloudFront OAC and KMS Incompatibility**: This module uses S3-managed encryption (SSE-S3/AES-256) instead of KMS encryption for website buckets due to an AWS platform limitation. CloudFront Origin Access Control (OAC) cannot decrypt KMS-encrypted objects because CloudFront makes anonymous requests to S3, and KMS requires authenticated requests for decryption. This is documented in the README and design specifications.

- **Encryption Settings Are Not Retroactive**: When changing S3 bucket encryption settings, only new objects use the new encryption method. Existing objects retain their original encryption and must be re-uploaded to apply new settings.

- **KMS Module Included**: The module includes a KMS module for future use or alternative architectures, but it is not used for website bucket encryption due to the CloudFront OAC limitation mentioned above.

### Technical Details

- **Terraform Version**: Requires Terraform >= 1.5.0
- **AWS Provider Version**: Requires AWS provider >= 5.0.0
- **Supported Regions**: All AWS regions (configurable primary and failover regions)
- **CloudFront Price Class**: Configurable (default: PriceClass_100)
- **S3 Versioning**: Enabled on website buckets for replication support
- **Origin Group Failover**: Triggers on 5xx status codes (500, 502, 503, 504)

### Documentation

- Comprehensive README with architecture diagrams
- Security model documentation explaining encryption choices
- Troubleshooting guide for common issues
- IAM permissions documentation for deployment
- Lessons learned section covering S3 encryption behavior and KMS limitations
- Example configuration demonstrating basic usage

[1.0.3]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.3
[1.0.2]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.2
[1.0.1]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.1
[1.0.0]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.0
