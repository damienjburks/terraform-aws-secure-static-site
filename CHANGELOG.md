# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.14] - 2025-12-12

### Fixed

- **CloudFront Certificate Mismatch**: Fixed error where CloudFront distribution failed to create due to certificate not covering www subdomain. Removed automatic addition of `www.${domain_name}` from CloudFront domain aliases to match the ACM certificate configuration from v1.0.12.

### Changed

- **CloudFront Domain Aliases**: CloudFront distribution now only includes the primary domain and explicitly specified alternate domains, ensuring consistency with ACM certificate Subject Alternative Names.

## [1.0.13] - 2025-12-12

### Changed

- **ACM Certificate Validation Timeout**: Increased timeout for ACM certificate validation from 10 minutes to 45 minutes to accommodate slower DNS propagation and validation processes, preventing timeout errors during certificate issuance.

## [1.0.12] - 2025-12-12

### Removed

- **WWW Subdomain Records**: Removed automatic creation of `www` A and AAAA records and removed `www.${domain_name}` from ACM certificate Subject Alternative Names. Users should specify their preferred domain (with or without www) as the primary domain and use `alternate_domain_names` if they need both variants.

### Changed

- **ACM Certificate SANs**: ACM certificate now only includes domains specified in `alternate_domain_names` variable, no longer automatically includes www variant.
- **Simplified DNS**: DNS configuration is now cleaner with only the specified domains, giving users full control over their domain strategy.

## [1.0.11] - 2025-12-10

### Added

- **Cache-Control Headers**: Added configurable Cache-Control headers to all CloudFront responses via the response headers policy. Default value is `"no-cache, no-store, must-revalidate"` to prevent unwanted caching.
- **Cache Control Configuration**: Added `cache_control_header` variable to allow customization of cache behavior for different use cases (static assets, dynamic content, etc.).
- **Custom Headers Support**: Enhanced CloudFront response headers policy with `custom_headers_config` block to support additional HTTP headers.

### Changed

- **Response Headers Policy**: Extended the existing security headers policy to include custom Cache-Control headers alongside security headers.
- **Documentation**: Added comprehensive Cache-Control configuration section with examples for different caching strategies.

### Technical Details

- **Default Behavior**: Prevents browser and proxy caching with `no-cache, no-store, must-revalidate` header by default.
- **Flexibility**: Easily configurable for different scenarios (long-term caching for static assets, short-term caching, or no caching).
- **Override Capability**: Cache-Control header is set with `override = true` to ensure consistent application regardless of origin headers.
- **Integration**: Seamlessly integrated with existing security headers policy without breaking changes.

### Examples

- **No Caching (Default)**: `cache_control_header = "no-cache, no-store, must-revalidate"`
- **Static Assets**: `cache_control_header = "public, max-age=31536000, immutable"`
- **Short Cache**: `cache_control_header = "public, max-age=300"`

## [1.0.10] - 2025-12-10

### Fixed

- **DNS Resolution Issues**: Fixed intermittent `ERR_NAME_NOT_RESOLVED` errors for www subdomains by eliminating problematic CNAME → ALIAS chains. The www subdomain now uses direct ALIAS records to CloudFront instead of CNAME records pointing to the apex domain.
- **DNS Compatibility**: Resolved DNS resolver compatibility issues that occurred with some DNS clients when following CNAME → ALIAS chains.

### Added

- **Automatic WWW Subdomain Support**: The module now automatically includes `www.domain.com` in CloudFront distribution aliases and ACM certificate Subject Alternative Names without requiring manual configuration.
- **Dual ALIAS Records**: Both A (IPv4) and AAAA (IPv6) ALIAS records are automatically created for the www subdomain, ensuring full compatibility and performance.
- **Enhanced DNS Documentation**: Added comprehensive DNS configuration section explaining automatic domain setup and best practices.

### Changed

- **WWW DNS Records**: Changed from CNAME record (`www` → `domain.com`) to direct ALIAS records (`www` → CloudFront distribution) for both A and AAAA record types.
- **CloudFront Aliases**: Updated domain aliases configuration to automatically include `www.${domain_name}` alongside the apex domain.
- **ACM Certificate**: Modified certificate configuration to automatically include www subdomain in Subject Alternative Names.

### Technical Details

- **DNS Best Practices**: Implements AWS recommended DNS configuration using direct ALIAS records for both apex and www subdomains.
- **Resolver Compatibility**: Eliminates DNS resolution issues across all DNS resolver implementations by avoiding CNAME → ALIAS chains.
- **Automatic Configuration**: No user configuration changes required - www subdomain support is automatically enabled when `enable_domain = true`.

## [1.0.9] - 2025-12-10

### Added

- **S3 Bucket Keys**: Enabled S3 Bucket Keys by default on all S3 buckets (primary, failover, and logging) to reduce encryption costs by up to 99%. This optimization applies to all SSE-S3 encryption operations without any configuration changes required.

### Changed

- **Encryption Configuration**: Updated all S3 bucket server-side encryption configurations to include `bucket_key_enabled = true` for cost optimization.
- **Documentation**: Updated README to reflect S3 Bucket Keys being enabled by default and their cost benefits.

### Technical Details

- **Cost Optimization**: S3 Bucket Keys reduce the number of encryption operations by using a bucket-level key hierarchy, significantly lowering costs for high-volume encryption workloads.
- **Automatic**: No user configuration required - bucket keys are enabled by default on all buckets.
- **Compatible**: Works seamlessly with existing SSE-S3 AES-256 encryption and S3 cross-region replication.

## [1.0.8] - 2025-12-10

### Fixed

- **CloudFront CNAME Conflict Resolution**: Fixed "CNAMEAlreadyExists" error (StatusCode: 409) that occurs when domain aliases are already associated with another CloudFront distribution. Added `ignore_alias_conflicts` variable to temporarily disable domain aliases during updates.
- **ACM Certificate Validation**: Fixed "InvalidViewerCertificate" error by ensuring CloudFront only uses validated certificate ARNs. Changed DNS module output from raw certificate ARN to validated certificate ARN.
- **Certificate Validation Timeout**: Added 10-minute timeout to ACM certificate validation to handle DNS propagation delays properly.

### Added

- **Conflict Resolution Variable**: Added `ignore_alias_conflicts` variable to temporarily disable domain aliases when CNAME conflicts occur during deployment.
- **Deployment Control**: Added `wait_for_deployment` variable to control whether Terraform waits for CloudFront distribution deployment completion.
- **Enhanced Troubleshooting**: Added comprehensive CNAME conflict troubleshooting section in README with multiple resolution strategies.

### Changed

- **CloudFront Lifecycle Management**: Added `create_before_destroy = true` to CloudFront distribution for smoother updates and replacements.
- **DNS Module Output**: Changed certificate ARN output from `aws_acm_certificate.main[0].arn` to `aws_acm_certificate_validation.main[0].certificate_arn` to ensure certificate is validated before use.
- **Certificate Validation**: Added lifecycle management and timeout configuration to ACM certificate validation resource.

### Technical Details

- **Domain Alias Handling**: Domain aliases are now conditional based on `ignore_alias_conflicts` flag to prevent deployment failures.
- **Certificate Chain Validation**: Ensures SSL certificates are fully validated and include valid certificate chains before CloudFront attempts to use them.
- **Error Recovery**: Provides multiple recovery paths for common CloudFront deployment issues including CNAME conflicts and certificate validation failures.

## [1.0.7] - 2025-12-10

### Added

- **Single Page Application (SPA) Routing Support**: Added `enable_spa_routing` variable to support client-side routing for modern web frameworks. When enabled, CloudFront redirects 404 and 403 errors to `/index.html` with 200 status code.
- **Framework Compatibility**: Full support for React Router, Vue Router, Angular Router, Docusaurus, and other client-side routing frameworks that require fallback to index.html.
- **Custom Error Pages**: Configurable CloudFront custom error responses for 404 and 403 status codes when SPA routing is enabled.

### Changed

- **CloudFront Distribution**: Added dynamic `custom_error_response` blocks that activate when `enable_spa_routing = true`.
- **Documentation**: Updated README with SPA routing section explaining the feature and framework compatibility.
- **Example Configuration**: Added SPA routing example in README showing how to enable for Docusaurus and other frameworks.

### Technical Details

- **Backward Compatible**: SPA routing is disabled by default (`enable_spa_routing = false`) to maintain existing behavior.
- **Error Handling**: Both 404 (Not Found) and 403 (Forbidden) errors redirect to `/index.html` to handle various S3 access scenarios.
- **Status Code Preservation**: Returns 200 status code with index.html content to prevent browser error pages while allowing JavaScript routers to handle URLs.

## [1.0.6] - 2025-12-10

### Fixed

- **CloudFront Response Headers Policy Deletion Error**: Fixed Terraform destroy operation failing with "ResponseHeadersPolicyInUse" error (StatusCode: 409). Added proper resource dependencies and lifecycle management to ensure CloudFront distribution is destroyed before the response headers policy.

### Changed

- **Resource Destruction Order**: Added `depends_on` attribute to CloudFront distribution to explicitly depend on response headers policy, ensuring proper cleanup sequence during `terraform destroy`.
- **Response Headers Policy Lifecycle**: Added `create_before_destroy = true` lifecycle rule to response headers policy for smoother updates and replacements.

## [1.0.5] - 2025-12-08

### Added

- **Configurable Content Security Policy**: Added `content_security_policy` variable to allow customization of CSP header. This fixes issues with modern websites that load external resources (fonts, scripts, images from CDNs, etc.).

### Changed

- **Default CSP Policy**: Changed default Content Security Policy from restrictive `default-src 'self'` to a more permissive policy that allows HTTPS external resources, inline scripts/styles, and data URIs. This prevents `(blocked:csp)` errors common with modern web frameworks and static site generators.
- **CSP Configuration**: The CSP header is now configurable via the `content_security_policy` variable in both root and CloudFront modules.

### Fixed

- **CSP Blocking External Resources**: Resolved issue where the default CSP was too restrictive and blocked legitimate external resources like fonts, CDN scripts, and third-party integrations that worked fine on other hosting platforms (e.g., GitHub Pages).

## [1.0.4] - 2025-12-08

### Added

- **Deny Insecure Transport Policy**: Added S3 bucket policy statement to deny all HTTP (non-SSL) traffic to website buckets. This enforces HTTPS-only access at the bucket level, providing defense-in-depth security alongside CloudFront's HTTPS enforcement.

### Security

- **Enhanced Transport Security**: S3 bucket policies now explicitly deny any requests made over HTTP, ensuring all S3 API calls must use HTTPS/TLS. This meets compliance requirements for secure transport and prevents accidental insecure access.

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

[1.0.14]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.14
[1.0.13]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.13
[1.0.12]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.12
[1.0.11]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.11
[1.0.10]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.10
[1.0.9]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.9
[1.0.8]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.8
[1.0.7]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.7
[1.0.6]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.6
[1.0.5]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.5
[1.0.4]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.4
[1.0.3]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.3
[1.0.2]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.2
[1.0.1]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.1
[1.0.0]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.0
