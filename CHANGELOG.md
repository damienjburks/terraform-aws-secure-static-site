# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.0
