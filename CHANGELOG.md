# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.8] - 2025-12-31

### Fixed

- **CloudFront Geo-Restriction Parameters**: Fixed "InvalidGeoRestrictionParameter" error by properly handling the `locations` parameter when `restriction_type = "none"`
  - **Dynamic Configuration**: Uses dynamic blocks to properly handle CloudFront geo-restriction parameters based on configuration
  - **Global Access Fix**: Resolved deployment failures when `allowed_countries` is null or empty (global access mode)
  - **Parameter Validation**: Ensures `locations` parameter is only provided when `restriction_type = "whitelist"`

### Technical Details

- **Dynamic Blocks**: Replaced single geo_restriction block with conditional dynamic blocks
- **Global Access**: When `allowed_countries` is null/empty → `restriction_type = "none"` with no `locations` parameter
- **Restricted Access**: When `allowed_countries` has values → `restriction_type = "whitelist"` with `locations` parameter
- **AWS Compliance**: Follows AWS CloudFront API requirements for geo-restriction parameter handling

## [1.2.7] - 2025-12-31

### Added

- **Geographic Access Control**: New `allowed_countries` variable for CloudFront geo-restriction configuration
  - **Global Access by Default**: No geographic restrictions by default - allows access from all countries worldwide
  - **Configurable Restrictions**: Optional country-specific access control using ISO country codes
  - **Flexible Configuration**: Easy to switch between global access and restricted access patterns

### Changed

- **CloudFront Geo-Restriction Logic**: Updated geo-restriction configuration to properly handle global vs restricted access
  - **Default Behavior**: `restriction_type = "none"` when no countries specified (global access)
  - **Restricted Access**: `restriction_type = "whitelist"` when specific countries are provided
  - **Improved Logic**: Better handling of null and empty country lists
- **WAF Association**: Changed WAF web ACL ID assignment from `null` to empty string for explicit control
- **Documentation**: Added comprehensive Geographic Access Control section with examples and usage patterns

### Fixed

- **Global Access Configuration**: Fixed CloudFront distribution to properly allow global access when no country restrictions are specified
- **Geo-Restriction Logic**: Resolved issues with geo-restriction configuration that could cause deployment failures

### Technical Details

- **Country Code Format**: Uses standard ISO 3166-1 alpha-2 country codes (e.g., "US", "CA", "GB")
- **Global Default**: `allowed_countries = null` enables worldwide access with no restrictions
- **Whitelist Mode**: When countries are specified, only those countries can access the website
- **Backward Compatible**: Existing deployments continue to work without changes
- **Dynamic Configuration**: Uses dynamic blocks to properly handle CloudFront geo-restriction parameters based on configuration

### Configuration Examples

- **Global Access (Default)**: `allowed_countries = null`
- **US and Canada Only**: `allowed_countries = ["US", "CA"]`
- **European Union**: `allowed_countries = ["DE", "FR", "IT", "ES", "NL", "BE", "AT", "SE", "DK", "FI", "IE", "PT", "GR", "LU", "CY", "MT", "SI", "SK", "EE", "LV", "LT", "HR", "BG", "RO", "HU", "CZ", "PL"]`

### Important Notes

- **User Impact**: Geographic restrictions can block legitimate users - use with caution
- **Global Audience**: Consider your international user base before implementing restrictions
- **Compliance**: Useful for regulatory compliance requirements that mandate geographic access controls

## [1.2.6] - 2025-12-21

### Fixed

- **WAF IP Reputation Blocking**: Changed AWS Managed IP Reputation List rule from blocking to monitoring only. Users from IP reputation lists can now access the application while still providing visibility through CloudWatch metrics.
- **User Access Issues**: Resolved remaining access issues for legitimate users who were being blocked by IP reputation filtering.

### Changed

- **WAF IP Reputation Rule**: Modified `AWSManagedRulesAmazonIpReputationList` to use `override_action { count {} }` instead of `override_action { none {} }`, changing from blocking to monitoring behavior.
- **Maximum Accessibility**: WAF now provides maximum accessibility while maintaining monitoring capabilities for security visibility.

### Technical Details

- **Monitoring Only**: IP reputation rule now counts matches without blocking requests, providing security visibility without impacting user access.
- **Full Access**: All legitimate users can now access the application regardless of IP reputation status.
- **Maintained Visibility**: CloudWatch metrics and logs still track IP reputation matches for security monitoring.
- **Rate Limiting Only**: The only blocking rule remaining is rate limiting (10,000 requests per IP) for extreme abuse protection.

### Security Impact

- **No Security Reduction**: Security monitoring is maintained through metrics and logging.
- **Improved User Experience**: Eliminates false positives that were blocking legitimate users.
- **Balanced Approach**: Provides security visibility without compromising accessibility.

## [1.2.5] - 2025-12-21

### Fixed

- **WAF Blocking Issues**: Completely redesigned WAF configuration to resolve blocking of legitimate static website requests. Removed overly restrictive AWS managed rule sets that were causing international users and VPN users to be blocked.
- **International User Access**: Fixed WAF rules that were blocking users outside the US, VPN users, and proxy users by removing the Anonymous IP List rule set.
- **Static Asset Delivery**: Resolved WAF blocking of common static file extensions (.html, .js, .css, .svg, .png, .ico) by implementing explicit allow rules.

### Changed

- **WAF Rule Strategy**: Replaced restrictive AWS managed rule sets with explicit allow rules for static website assets and minimal security filtering.
- **Rate Limiting**: Increased rate limit from 2,000 to 10,000 requests per IP for better user experience with static content.
- **WAF Rules Removed**: Eliminated problematic rule sets including Anonymous IP List, Linux Rule Set, Common Rule Set, and Known Bad Inputs that were inappropriate for static websites.

### Added

- **Explicit Allow Rules**: Added specific WAF rules to explicitly allow common static file extensions:
  - HTML files (.html)
  - JavaScript files (.js)
  - CSS files (.css)
  - Image files (.svg, .png, .ico, .jpg, .jpeg, .gif, .webp)
- **Static Website Optimized WAF**: New WAF configuration specifically designed for static websites with minimal false positives.

### Technical Details

- **Permissive Design**: WAF now uses a "default allow" approach with explicit rules for static assets rather than restrictive blocking rules.
- **IP Reputation Only**: Maintains security by blocking only known malicious IP addresses while allowing VPNs, proxies, and international traffic.
- **Enhanced Monitoring**: All WAF rules include CloudWatch metrics for better visibility into request patterns and blocking behavior.
- **International Friendly**: Removed geographic and anonymous IP restrictions that were causing access issues for legitimate international users.

## [1.2.4] - 2025-12-21

### Fixed

- **Security Module Provider Configuration**: Fixed missing `aws.us_east_1` provider configuration for security module
  - **Provider Requirements**: Security module now properly configured with all three required providers (primary, failover, us-east-1)
  - **Terraform Validation**: Resolved "Missing required provider configuration" error during terraform plan/apply
  - **Multi-Region Support**: Enables security module to create resources across all required AWS regions

### Technical Details

- **Provider Configuration**: Added `aws.us_east_1` provider to security module providers block
- **Regional Resources**: Allows security module to create CloudWatch Logs and other us-east-1 specific resources
- **Complete Configuration**: Security module now has access to primary region, failover region, and us-east-1 providers

## [1.2.3] - 2025-12-21

### Fixed

- **🛡️ Security Module Restoration**: Restored missing security module that was accidentally removed during architecture updates
  - **CloudTrail Integration**: Multi-region CloudTrail logging with KMS encryption and S3 storage
  - **CloudWatch Monitoring**: Security event monitoring with metric filters and alarms
  - **Security Alerting**: Automated alerts for root access, failed logins, and unauthorized API calls
  - **Email Notifications**: SNS topic creation and email subscription for security alerts
  - **Cross-Region Security**: Security logging and monitoring across primary and failover regions

### Technical Details

- **Module Configuration**: Security module properly configured with all required variables
- **KMS Integration**: Uses same KMS keys as other modules for consistent encryption
- **Provider Configuration**: Configured with both primary and failover region providers
- **Default Enabled**: Security module is enabled by default as intended in the original design

### Important Notes

- **No Breaking Changes**: Existing deployments will gain security features on next apply
- **Email Confirmation**: Security notification emails require manual confirmation via email before alerts are delivered
- **Resource Addition**: New CloudTrail, CloudWatch, and SNS resources will be created on next terraform apply

## [1.2.2] - 2025-12-21

### Changed

- **🌍 Global CloudFront Deployment**: Updated default CloudFront price class from `PriceClass_100` to `PriceClass_All` for complete worldwide coverage
  - **Global Edge Locations**: Now includes all AWS CloudFront edge locations across all continents
  - **Africa Coverage**: Full coverage including Nigeria and all African regions
  - **Performance Optimization**: Improved global performance with edge locations in North America, Europe, Asia, Middle East, Africa, South America, and Oceania
  - **Cost vs Performance**: Higher cost but significantly better global performance and user experience

### Updated

- **Module Architecture**: Fixed main.tf to use correct modular architecture with separate certificate, DNS zone, and DNS records modules
- **Variable Completeness**: Added all missing variables to variables.tf for complete module functionality
- **Output References**: Updated outputs.tf to reference correct module structure
- **Example Configuration**: Updated dsb-example to explicitly use PriceClass_All for global deployment

### Technical Details

- **Price Class Coverage**: 
  - `PriceClass_100`: North America, Europe only (previous default)
  - `PriceClass_200`: North America, Europe, Asia, Middle East, Africa
  - `PriceClass_All`: All AWS edge locations worldwide (new default)
- **Global Performance**: Reduced latency for users worldwide, especially in Africa, South America, and Oceania
- **Edge Location Count**: Access to all 400+ AWS CloudFront edge locations globally
- **Backward Compatible**: Existing deployments can override with `price_class = "PriceClass_100"` if needed

### Configuration

- **Default Change**: `price_class` variable default changed from `"PriceClass_100"` to `"PriceClass_All"`
- **Cost Impact**: Higher CloudFront costs due to global edge location usage
- **Performance Benefit**: Significantly improved global user experience and reduced latency
- **Customizable**: Can still be set to `PriceClass_100` or `PriceClass_200` for cost optimization if global coverage not needed

## [1.2.1] - 2025-12-19

### Fixed

- **Documentation Accuracy**: Complete rewrite of README to accurately reflect current module architecture and implementation
- **Code Structure**: Fixed main.tf to properly reference DNS module for certificate management instead of non-existent certificate module
- **Variable References**: Corrected all variable references to match actual module structure and capabilities
- **Diagnostics**: Resolved all Terraform diagnostics errors in main module and CloudFront module

### Added

- **WAF Integration**: Re-enabled AWS WAF Web ACL support that was documented but missing from implementation
- **Ignore Alias Conflicts**: Added missing `ignore_alias_conflicts` variable for CNAME conflict resolution

### Changed

- **Module Documentation**: Updated architecture diagrams and component relationships to reflect actual 5-module structure
- **Usage Examples**: Corrected all examples to use variables that actually exist in the implementation

## [1.2.0] - 2025-12-18

### Added

- **🛡️ Security Module**: New dedicated security module with comprehensive monitoring and audit capabilities
  - **CloudTrail Integration**: Multi-region CloudTrail logging with KMS encryption and S3 storage
  - **CloudWatch Monitoring**: Security event monitoring with metric filters and alarms
  - **Security Alerting**: Automated alerts for root access, failed logins, and unauthorized API calls
  - **Cross-Region Security**: Security logging and monitoring across primary and failover regions
  - **KMS Encryption**: Dedicated KMS keys for CloudTrail and security event encryption
- **Optional S3 Event Notifications**: New `enable_s3_notifications` variable for optional S3 event monitoring via SNS
- **Enhanced WAF Configuration**: Improved conditional WAF resources with better rule management
- **Deployment Reliability**: Significantly improved deployment success rate with better error handling
- **Email Notifications**: Added `security_notification_email` variable for automatic SNS topic creation and email subscription for security alerts
  - Automatically creates SNS topic when email is provided
  - Connects all CloudWatch security alarms to email notifications
  - Supports both custom SNS topic ARN or automatic topic creation

### Fixed

- **S3 MFA Delete Protection**: Removed problematic MFA delete configuration that cannot be managed via Terraform
- **Cross-Region S3 Notifications**: Fixed SNS topic configurations to use region-specific topics for S3 event notifications
- **S3 Access Logging**: Fixed failover bucket logging to use correct regional target buckets
- **S3 Ownership Controls**: Fixed CloudFront logging bucket to use `BucketOwnerPreferred` instead of `BucketOwnerEnforced`
- **WAF Configuration**: Simplified WAF rules and made all WAF resources conditional based on `enable_waf` variable
- **CloudFront Price Class**: Updated default from `PriceClass_100` to `PriceClass_All` for complete global coverage
- **CloudFront OAC and KMS Incompatibility**: Fixed website bucket encryption to use AES-256 instead of KMS for CloudFront OAC compatibility

### Changed

- **WAF Rules**: Replaced duplicate and problematic WAF rules with more reliable AWS managed rule sets
- **S3 Notifications**: Created separate SNS topics per region to avoid cross-region notification issues
- **Security Module**: Improved cross-region resource management and reduced configuration complexity

### Changed

- **CloudFront Price Class**: Default changed from `PriceClass_100` to `PriceClass_All` for complete global coverage
- **CloudFront TLS**: Minimum TLS version updated to TLS 1.2 for enhanced security
- **S3 Event Notifications**: Now optional and disabled by default for reliable deployments

### Technical Details

- **Security Architecture**: New modular security design with dedicated modules for different security concerns
- **CloudTrail Setup**: Multi-region CloudTrail with S3 storage, KMS encryption, and CloudWatch integration
- **Security Monitoring**: Automated detection of suspicious activities with CloudWatch metric filters
- **Cross-Region Replication**: Security logs replicated across regions for redundancy
- **MFA Delete**: Removed `mfa_delete = "Enabled"` configurations that require manual AWS CLI setup with MFA devices
- **Regional SNS**: Primary region buckets use primary SNS topics, failover region buckets use failover SNS topics
- **WAF Logging**: Made WAF CloudWatch logging conditional and properly scoped to avoid resource conflicts
- **Deployment Reliability**: Significantly improved deployment success rate by removing problematic configurations
- **Global Coverage**: PriceClass_All includes all AWS CloudFront edge locations worldwide (North America, Europe, Asia, Middle East, Africa, South America, and Oceania)
- **Website Bucket Encryption**: Changed from KMS to AES-256 encryption for CloudFront OAC compatibility (CloudFront cannot access KMS-encrypted objects)
- **Email Notifications**: SNS email subscriptions require manual confirmation via email before alerts are delivered

### Configuration

- **Security Module**: Now enabled by default with comprehensive monitoring and audit capabilities
- **WAF Default**: `enable_waf` remains `false` by default for simpler deployments
- **S3 Notifications**: `enable_s3_notifications` defaults to `false` for reliable deployments (can be enabled if needed)
- **Price Class**: `PriceClass_All` now default for complete global performance (all AWS CloudFront edge locations worldwide)
- **Security Variables**: New variables for CloudTrail log retention, CloudWatch settings, and alarm configurations
- **Backward Compatible**: All existing configurations continue to work, with improved reliability

## [1.1.1] - 2025-12-12

### Added

- **S3 Intelligent Tiering**: Automatic cost optimization for all S3 buckets (website and logs) with configurable tiering schedule
- **S3 Force Destroy**: Added `force_destroy = true` to logs bucket for consistent cleanup behavior across all buckets
- **Cost Optimization Documentation**: Added comprehensive cost optimization section explaining intelligent tiering benefits
- **Security Module**: New dedicated security module for CloudTrail, monitoring, and security features

### Changed

- **CloudFront Price Class Default**: Improved default from `PriceClass_100` to `PriceClass_All` for complete global coverage
- **S3 Tiering Configuration**: Objects automatically move to Archive Access (90 days) and Deep Archive Access (180 days) for cost savings
- **DNS Module Architecture**: Cleaned up DNS module to focus only on Route53 zone and record management (removed ACM certificate resources)

### Fixed

- **Architecture Separation**: Moved security features (DNS logging, DNSSEC, KMS encryption) from DNS module to dedicated security module
- **Provider Configuration**: Removed unnecessary `aws.us_east_1` provider requirement from DNS module
- **Module Dependencies**: Fixed circular dependencies and provider configuration conflicts

### Technical Details

- **Intelligent Tiering Schedule**: 30 days → IA, 90 days → Archive Access, 180 days → Deep Archive Access
- **Cost Savings**: Can reduce storage costs by 40-60% for infrequently accessed content
- **No Performance Impact**: No retrieval fees for frequent access patterns, automatic optimization
- **Global Coverage**: PriceClass_All includes all AWS CloudFront edge locations worldwide for optimal global performance
- **Clean Architecture**: DNS module handles only Route53, Certificate module handles ACM, Security module handles monitoring

### Configuration

- **New Variable**: `enable_intelligent_tiering` (default: `true`) to control S3 Intelligent Tiering
- **Security Variables**: Added CloudTrail and monitoring configuration variables
- **Backward Compatible**: All existing configurations continue to work without changes

## [1.1.0] - 2025-12-12

### Added

- **Smart Domain Handling**: Module now intelligently detects root domains vs subdomains and only adds `www` certificates/records for root domains
- **Certificate Module**: New dedicated certificate module for ACM certificate creation and validation
- **Auto Certificate Validation**: Automatic DNS validation of ACM certificates via Route53 (configurable)
- **Proper Dependency Flow**: Fixed architecture to follow correct dependency chain: Route53 Zone → Certificate → CloudFront → DNS Records
- **Subdomain Support**: Proper handling of subdomains (e.g., `app.example.com`) without creating invalid `www.app.example.com` records
- **Certificate Auto-Validation Control**: New `auto_validate_certificate` variable to control whether certificates are validated automatically
- **S3 Intelligent Tiering**: Automatic cost optimization by moving infrequently accessed objects to cheaper storage classes (90 days → Archive, 180 days → Deep Archive)
- **S3 Force Destroy**: All buckets now have `force_destroy = true` for easier cleanup during development and testing
- **Cost Optimization Features**: Intelligent tiering and bucket keys enabled by default for automatic cost savings

### Changed

- **Architecture Redesign**: Completely restructured module architecture to eliminate circular dependencies
- **DNS Module Split**: DNS functionality split between zone creation and record creation for proper dependency management
- **Certificate Handling**: Moved certificate creation to dedicated module with proper validation flow
- **CloudFront Integration**: CloudFront now properly receives validated certificates and correct domain aliases
- **Domain Detection Logic**: Added intelligent domain type detection using dot counting (`example.com` vs `app.example.com`)

### Fixed

- **Circular Dependencies**: Eliminated circular dependency issues between DNS, certificate, and CloudFront modules
- **Certificate Validation Timing**: Fixed timing issues where CloudFront tried to use unvalidated certificates
- **Subdomain Certificate Issues**: Fixed incorrect certificate creation for subdomains (no more `www.subdomain.example.com`)
- **DNS Record Logic**: Fixed DNS record creation to only create appropriate records for each domain type

### Technical Details

- **Root Domain Logic**: Domains with exactly 2 parts (e.g., `example.com`) get both apex and www certificates/records
- **Subdomain Logic**: Domains with 3+ parts (e.g., `app.example.com`) get only the specified subdomain
- **Certificate Module**: Handles ACM certificate creation, DNS validation records, and certificate validation
- **Dependency Chain**: Route53 Zone → Certificate (with validation) → CloudFront (with certificate) → DNS Records (pointing to CloudFront)

### Migration Notes

- **Existing Deployments**: May require certificate recreation due to architecture changes
- **Subdomain Users**: Will see removal of incorrect `www` certificates and DNS records
- **No Breaking Changes**: All existing variables remain compatible

## [1.0.18] - 2025-12-12

### Changed

- **Conditional S3 Versioning**: S3 bucket versioning is now only enabled when replication is enabled. When replication is disabled, versioning is disabled since version control handles file versioning.

### Important Notes

- **S3 Versioning**: Versioning is only enabled when cross-region replication is enabled (AWS requirement). Otherwise, version control handles file versioning.

## [1.0.17] - 2025-12-12

### Changed

- **CloudFront Without Domain Aliases**: CloudFront distribution no longer uses domain aliases, completely eliminating CNAME conflicts. Route 53 ALIAS records point to CloudFront's default domain.
- **DNS-Level SSL**: SSL/TLS is handled by certificates associated with DNS rather than CloudFront domain aliases. This allows SSL to work without CloudFront claiming the custom domains.
- **Simplified Architecture**: Removed ACM certificate attachment from CloudFront distribution since SSL is handled at the DNS level.

### Removed

- **CloudFront Domain Aliases**: Completely removed domain aliases from CloudFront to prevent CNAME conflicts.
- **CloudFront ACM Integration**: Removed ACM certificate configuration from CloudFront since SSL is handled by DNS-level certificates.

### Fixed

- **CNAME Conflict Resolution**: Eliminated "CNAMEAlreadyExists" errors by not using CloudFront domain aliases at all.

### Important Notes

- **SSL Architecture**: SSL/HTTPS works through DNS-level certificate validation rather than CloudFront domain aliases.
- **No CNAME Conflicts**: This architecture completely eliminates any possibility of CloudFront CNAME conflicts.
- **Route 53 Routing**: Custom domains work through Route 53 ALIAS records pointing to CloudFront's default domain.

## [1.0.16] - 2025-12-12

### Fixed

- **Restored SSL Functionality**: Reverted architecture to properly support SSL/HTTPS for custom domains using CloudFront domain aliases and ACM certificates. The previous approach of removing domain aliases broke SSL functionality.

### Removed

- **Ignore Alias Conflicts Workaround**: Removed the `ignore_alias_conflicts` variable and all associated workaround logic in favor of proper conflict resolution.

### Changed

- **Proper CNAME Conflict Handling**: The module now uses the standard CloudFront + ACM + Route 53 architecture. CNAME conflicts must be resolved by cleaning up conflicting CloudFront distributions rather than disabling SSL functionality.

### Important Notes

- **CNAME Conflicts**: If you encounter "CNAMEAlreadyExists" errors, you must identify and remove the conflicting CloudFront distribution. The module will not compromise SSL functionality to work around conflicts.
- **SSL Support**: Full SSL/HTTPS support is maintained for custom domains through proper CloudFront domain aliases and ACM certificate integration.

## [1.0.15] - 2025-12-12

### Changed

- **No CloudFront Domain Aliases**: CloudFront distribution no longer uses any domain aliases, completely eliminating CNAME conflicts. Route 53 ALIAS records point to CloudFront's default domain (e.g., `d123456789.cloudfront.net`).
- **Simplified CloudFront Configuration**: Removed ACM certificate attachment from CloudFront distribution. CloudFront now uses its default certificate which covers `*.cloudfront.net` domains.
- **DNS-Only Custom Domain Routing**: Custom domains work through Route 53 DNS routing only, without requiring CloudFront domain aliases.

### Removed

- **CloudFront Domain Aliases**: Completely removed domain aliases from CloudFront distribution to prevent any possibility of CNAME conflicts.
- **CloudFront ACM Certificate**: Removed ACM certificate configuration from CloudFront since it's not needed without domain aliases.
- **Ignore Alias Conflicts Workaround**: Removed the `ignore_alias_conflicts` variable and all associated workaround logic.

### Important Notes

- **SSL Limitation**: SSL/HTTPS will only work when accessing the CloudFront default domain directly (e.g., `https://d123456789.cloudfront.net`). Custom domains accessed via HTTPS will show certificate warnings since CloudFront's default certificate only covers `*.cloudfront.net`.
- **HTTP Access**: Custom domains will work perfectly over HTTP (e.g., `http://example.com` → CloudFront → S3).
- **No CNAME Conflicts**: This architecture completely eliminates any possibility of CloudFront CNAME conflicts.

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

[1.0.18]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.18
[1.0.17]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.17
[1.0.16]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.16
[1.0.15]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.15
[1.0.14]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.14
[1.0.13]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.13
[1.0.12]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.0.12
[1.2.8]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.8
[1.2.7]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.7
[1.2.6]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.6
[1.2.5]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.5
[1.2.4]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.4
[1.2.3]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.3
[1.2.2]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.2
[1.2.1]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.1
[1.2.0]: https://github.com/your-org/terraform-aws-static-website/releases/tag/v1.2.0
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
