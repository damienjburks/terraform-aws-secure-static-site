# AWS Static Website Terraform Module

A secure, production-ready Terraform module for hosting static websites on AWS with multi-region failover, comprehensive security hardening, and automated deployment.

## Features

- **🔒 Security First**: Private S3 buckets with AES-256 encryption, CloudFront OAC, Block Public Access, and comprehensive security headers (HSTS, CSP, X-Frame-Options, etc.)
- **🌍 Multi-Region Failover**: Automatic failover between configurable AWS regions with CloudFront origin groups
- **🔄 Cross-Region Replication**: Automated S3 replication from primary to failover region for data durability
- **⚡ CloudFront CDN**: Global content delivery with HTTPS-only access and TLS 1.2 minimum
- **🎯 Custom Domain Support**: Optional ACM certificate provisioning and Route 53 DNS management
- **📊 Access Logging**: CloudFront access logs stored in encrypted S3 bucket
- **🏗️ Modular Design**: Clean separation of concerns with dedicated modules for KMS, S3, CloudFront, and DNS
- **♻️ Reusable**: Configurable for different environments, regions, and use cases

## Architecture

```
┌─────────────┐
│   User      │
└──────┬──────┘
       │ HTTPS (TLS 1.2+)
       ▼
┌─────────────────────────────────────────────┐
│   Route53 (Optional)                        │
│   - Custom Domain (example.com)             │
│   - A/AAAA Records → CloudFront             │
│   - Smart www handling (root domains only)  │
└──────┬──────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│   CloudFront Distribution                   │
│   - HTTPS Only + Custom Domain              │
│   - ACM Certificate (Auto-validated)        │
│   - Security Headers (HSTS, CSP, etc.)      │
│   - Origin Group (Multi-Region Failover)    │
└──────┬──────────────────────────────────────┘
       │
       ├─ Primary Origin (OAC) ──────────────┐
       │                                      ▼
       │              ┌─────────────────────────────────────┐
       │              │ S3 Bucket - Primary Region          │
       │              │ - Private + AES-256 Encrypted       │
       │              │ - Replicates to Failover            │
       │              └─────────────────────────────────────┘
       │
       └─ Failover Origin (OAC) ─────────────┐
                                              ▼
                      ┌─────────────────────────────────────┐
                      │ S3 Bucket - Failover Region         │
                      │ - Private + AES-256 Encrypted       │
                      │ - Replication Destination           │
                      └─────────────────────────────────────┘
```

### New Architecture Flow (v1.1.0)

The module now follows a proper dependency chain for domain setup:

1. **Route53 Zone** → Creates hosted zone (if needed)
2. **ACM Certificate** → Creates SSL certificate with auto-validation
3. **CloudFront Distribution** → Uses certificate and domain aliases
4. **DNS Records** → A/AAAA records pointing to CloudFront

### Component Relationships

- **Certificate Module**: Creates ACM certificate (us-east-1) with optional auto-validation via Route53
- **S3 Module**: Creates website buckets (primary + failover) and logging bucket, all with AES-256 encryption
- **CloudFront Module**: Creates distribution with OAC, origin groups for failover, security headers, and custom domain support
- **DNS Module**: Creates Route53 zone and A/AAAA records pointing to CloudFront distribution

### Smart Domain Handling

The module intelligently handles different domain types:

- **Root domains** (e.g., `example.com`) → Certificate includes both `example.com` and `www.example.com`
- **Subdomains** (e.g., `app.example.com`) → Certificate only includes `app.example.com` (no www)
- **Auto-detection** → Uses domain structure to determine appropriate certificate configuration

**Note**: Website buckets use S3-managed encryption (SSE-S3/AES-256) rather than KMS encryption due to an AWS limitation: CloudFront Origin Access Control (OAC) cannot decrypt KMS-encrypted objects because CloudFront makes anonymous requests to S3, and KMS does not support anonymous access.

### Data Flow

1. User requests content via HTTPS
2. CloudFront serves from cache or fetches from primary S3 origin
3. If primary origin returns 5xx errors, CloudFront automatically fails over to secondary origin
4. S3 replication keeps failover bucket synchronized with primary
5. All access is logged to encrypted logging bucket

## Security Model

This module implements defense-in-depth security with multiple layers of protection:

### Encryption at Rest

- **S3-Managed Encryption**: All S3 buckets use SSE-S3 (AES-256) encryption
- **CloudFront OAC Compatibility**: Website buckets use AES-256 instead of KMS due to AWS limitation - CloudFront OAC cannot decrypt KMS-encrypted objects because CloudFront makes anonymous requests to S3, and KMS does not support anonymous access
- **Automatic Encryption**: All objects are automatically encrypted at rest using AES-256 algorithm
- **No Additional Cost**: S3-managed encryption has no additional cost compared to KMS

### Encryption in Transit

- **HTTPS Only**: CloudFront enforces HTTPS for all viewer connections
- **TLS 1.2 Minimum**: Modern TLS protocol version required
- **Certificate Management**: ACM certificates with automatic renewal (when using custom domains)

### Access Control

- **Private S3 Buckets**: All buckets have Block Public Access enabled
- **Origin Access Control (OAC)**: CloudFront uses OAC (not legacy OAI) to access S3
- **Bucket Policies**: S3 bucket policies restrict access exclusively to CloudFront distribution
- **No Public ACLs**: Public ACLs are blocked on all buckets

### Security Headers

When `enable_security_headers = true` (default), CloudFront adds the following headers to all responses:

- **Strict-Transport-Security**: `max-age=31536000; includeSubDomains; preload`
- **X-Content-Type-Options**: `nosniff`
- **X-Frame-Options**: `DENY`
- **X-XSS-Protection**: `1; mode=block`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Content-Security-Policy**: `default-src 'self'`
- **Cache-Control**: `no-cache, no-store, must-revalidate` (configurable)

### Single Page Application (SPA) Routing

When `enable_spa_routing = true`, CloudFront is configured to support client-side routing for modern web frameworks:

- **404 Error Handling**: Redirects 404 errors to `/index.html` with 200 status code
- **403 Error Handling**: Redirects 403 errors to `/index.html` with 200 status code
- **Framework Support**: Required for React Router, Vue Router, Angular Router, Docusaurus, and other client-side routing

This allows URLs like `https://example.com/docs/getting-started` to work correctly when users navigate directly to them or refresh the page.

### SSL/HTTPS Support

**Full SSL Support**: This module provides complete SSL/HTTPS support for custom domains:

- ✅ **Custom Domain HTTPS**: Full SSL support for custom domains (e.g., `https://example.com`)
- ✅ **CloudFront Default Domain**: HTTPS works when accessing CloudFront directly (e.g., `https://d123456789.cloudfront.net`)
- ✅ **ACM Integration**: Automatic SSL certificate provisioning and validation via ACM
- ✅ **Domain Aliases**: CloudFront distribution properly configured with custom domain aliases

**Note**: If you encounter CNAME conflicts during deployment, you may need to remove conflicting CloudFront distributions that are using the same domain.

### Cache Control Headers

The module automatically adds Cache-Control headers to all responses:

- **Default**: `Cache-Control: no-cache, no-store, must-revalidate`
- **Purpose**: Prevents browser and proxy caching for dynamic content
- **Configurable**: Can be customized via the `cache_control_header` variable

**Custom Cache-Control Example:**
```hcl
module "website" {
  source = "./path/to/module"
  
  # Custom cache control for static assets
  cache_control_header = "public, max-age=31536000, immutable"
  
  # ... other variables
}
```

### High Availability

- **Multi-Region**: S3 buckets in two configurable AWS regions
- **Automatic Failover**: CloudFront origin groups fail over on 5xx status codes (500, 502, 503, 504)
- **Cross-Region Replication**: S3 replication ensures data availability in both regions
- **Versioning**: S3 versioning enabled on website buckets for replication

### Cost Optimization

- **S3 Intelligent Tiering**: Automatically moves infrequently accessed objects to cheaper storage classes
  - Objects not accessed for 30 days → Infrequent Access (IA)
  - Objects not accessed for 90 days → Archive Access
  - Objects not accessed for 180 days → Deep Archive Access
  - No retrieval fees for frequent access patterns
  - Automatic cost optimization without performance impact
- **S3 Bucket Keys**: Enabled on all buckets to reduce encryption costs by up to 99%
- **CloudFront Caching**: Reduces origin requests and data transfer costs

### Encryption Implementation

All S3 buckets use S3-managed encryption (SSE-S3) with AES-256 and S3 Bucket Keys enabled:

1. **Primary Website Bucket**: Encrypted with AES-256, bucket keys enabled
2. **Failover Website Bucket**: Encrypted with AES-256, bucket keys enabled  
3. **Logging Bucket**: Encrypted with AES-256, bucket keys enabled
4. **S3 Bucket Keys**: Enabled by default to reduce encryption costs by up to 99%
5. **Replication**: S3 replication works seamlessly with AES-256 encryption

**Why not KMS?** CloudFront Origin Access Control (OAC) is incompatible with KMS-encrypted S3 objects. When CloudFront requests objects from S3 using OAC, it makes anonymous requests. KMS requires authenticated requests to decrypt data, making it impossible for CloudFront to access KMS-encrypted objects. This is an AWS platform limitation, not a module limitation.



## Usage

### Basic Example (No Custom Domain)

```hcl
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name             = "my-unique-website-bucket"
  enable_domain           = false
  primary_region          = "us-east-1"
  failover_region         = "us-west-2"
  enable_failover         = true
  enable_replication      = true
  enable_security_headers = true
  enable_spa_routing      = true   # Enable for Docusaurus, React, Vue, Angular
  cache_control_header    = "no-cache, no-store, must-revalidate"  # Default value

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### With Custom Domain

```hcl
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name         = "my-website-bucket"
  enable_domain       = true
  domain_name         = "example.com"
  create_route53_zone = true

  tags = {
    Environment = "production"
  }
}
```

### DNS Configuration

When `enable_domain = true`, the module automatically configures:

#### For Root Domains (e.g., `example.com`)
- **Apex Domain**: `example.com` → CloudFront (A and AAAA ALIAS records)
- **WWW Subdomain**: `www.example.com` → CloudFront (A and AAAA ALIAS records)
- **ACM Certificate**: Covers both `example.com` and `www.example.com`
- **Automatic Validation**: DNS validation records created in Route 53

#### For Subdomains (e.g., `app.example.com`)
- **Subdomain Only**: `app.example.com` → CloudFront (A and AAAA ALIAS records)
- **No WWW**: Does not create `www.app.example.com` (would be invalid)
- **ACM Certificate**: Covers only `app.example.com`
- **Automatic Validation**: DNS validation records created in Route 53

**Important**: The module intelligently detects domain types and only creates appropriate DNS records and certificates. Both apex domains and subdomains use direct ALIAS records to CloudFront, avoiding problematic CNAME → ALIAS chains.

### Custom Regions (EU)

```hcl
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name     = "my-eu-website-bucket"
  primary_region  = "eu-west-1"
  failover_region = "eu-central-1"
  enable_domain   = false

  tags = {
    Environment = "production"
    Region      = "EU"
  }
}
```

### Single Region (Failover Disabled)

```hcl
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name        = "my-website-bucket"
  enable_failover    = false
  enable_replication = false
  enable_domain      = false

  tags = {
    Environment = "development"
  }
}
```

## Inputs

| Name                    | Description                                                                           | Type         | Default                       | Required |
| ----------------------- | ------------------------------------------------------------------------------------- | ------------ | ----------------------------- | -------- |
| bucket_name             | Name of the S3 bucket for website content (must be globally unique)                   | string       | n/a                           | yes      |
| enable_domain           | Enable custom domain support with ACM and Route 53                                    | bool         | false                         | no       |
| domain_name             | Primary domain name for the website (required if enable_domain is true)               | string       | null                          | no       |
| alternate_domain_names  | List of alternate domain names (CNAMEs) for CloudFront                                | list(string) | []                            | no       |
| create_route53_zone     | Create a new Route 53 hosted zone for the domain                                      | bool         | false                         | no       |
| existing_route53_zone_id | Existing Route 53 hosted zone ID (required if enable_domain is true and create_route53_zone is false) | string       | null                          | no       |
| auto_validate_certificate | Automatically validate ACM certificate using DNS records in Route53 (set to false if domain is managed outside AWS) | bool         | true                          | no       |
| logging_enabled         | Enable CloudFront access logging                                                      | bool         | true                          | no       |
| kms_key_arn             | (Deprecated) ARN of existing KMS key - not used due to CloudFront OAC incompatibility | string       | null                          | no       |
| price_class             | CloudFront price class (PriceClass_All, PriceClass_200, PriceClass_100)               | string       | "PriceClass_100"              | no       |
| comment                 | Comment for the CloudFront distribution                                               | string       | "Static website distribution" | no       |
| tags                    | Tags to apply to all resources                                                        | map(string)  | {}                            | no       |
| primary_region          | Primary AWS region for S3 bucket                                                      | string       | "us-east-1"                   | no       |
| failover_region         | Failover AWS region for S3 bucket                                                     | string       | "us-west-2"                   | no       |
| enable_failover         | Enable multi-region failover                                                          | bool         | true                          | no       |
| enable_replication      | Enable S3 cross-region replication                                                    | bool         | true                          | no       |
| enable_security_headers | Enable CloudFront response headers policy with security headers                       | bool         | true                          | no       |
| enable_spa_routing      | Enable SPA routing by redirecting 404/403 errors to index.html (for React, Vue, Angular, Docusaurus) | bool         | false                         | no       |
| wait_for_deployment     | Wait for CloudFront distribution deployment to complete (can be disabled for faster applies)          | bool         | true                          | no       |
| cache_control_header     | Cache-Control header value to add to all responses from CloudFront                                    | string       | "no-cache, no-store, must-revalidate" | no       |
| enable_intelligent_tiering | Enable S3 Intelligent Tiering for automatic cost optimization (moves infrequently accessed objects to cheaper storage classes) | bool         | true                          | no       |


### Recommended Region Pairs

- **US**: us-east-1 / us-west-2
- **Europe**: eu-west-1 / eu-central-1
- **Asia Pacific**: ap-southeast-1 / ap-northeast-1

## Outputs

| Name                       | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| cloudfront_domain_name     | Domain name of the CloudFront distribution               |
| cloudfront_distribution_id | ID of the CloudFront distribution                        |
| website_bucket_name        | Name of the primary S3 bucket containing website content |
| logging_bucket_name        | Name of the S3 bucket containing CloudFront logs         |
| route53_nameservers        | Nameservers for the Route 53 hosted zone (if created)    |
| certificate_arn            | ARN of the ACM certificate (if domain is enabled)        |
| route53_zone_id            | Route 53 hosted zone ID (if created or provided)         |

## Deployment

### Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with necessary IAM permissions (see below)

### Steps

1. **Create a Terraform configuration**:

```hcl
# main.tf
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name = "my-unique-bucket-name"

  tags = {
    Environment = "production"
  }
}

output "website_url" {
  value = "https://${module.static_website.cloudfront_domain_name}"
}
```

2. **Initialize Terraform**:

```bash
terraform init
```

3. **Review the plan**:

```bash
terraform plan
```

4. **Apply the configuration**:

```bash
terraform apply
```

5. **Upload your website content**:

```bash
aws s3 sync ./website-content s3://$(terraform output -raw website_bucket_name)/
```

6. **Access your website**:

```bash
echo "Website URL: https://$(terraform output -raw cloudfront_domain_name)"
```

### Updating Content

After uploading new content, invalidate the CloudFront cache:

```bash
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

## Required IAM Permissions

The deploying principal requires the following permissions:

### S3 Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:GetBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:PutBucketVersioning",
        "s3:GetBucketVersioning",
        "s3:PutReplicationConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:PutBucketTagging",
        "s3:GetBucketTagging"
      ],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

### CloudFront Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudfront:CreateDistribution",
    "cloudfront:GetDistribution",
    "cloudfront:UpdateDistribution",
    "cloudfront:DeleteDistribution",
    "cloudfront:TagResource",
    "cloudfront:CreateOriginAccessControl",
    "cloudfront:GetOriginAccessControl",
    "cloudfront:DeleteOriginAccessControl",
    "cloudfront:CreateResponseHeadersPolicy",
    "cloudfront:GetResponseHeadersPolicy",
    "cloudfront:DeleteResponseHeadersPolicy"
  ],
  "Resource": "*"
}
```

### KMS Permissions (Optional - Not Currently Used)

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:CreateKey",
    "kms:CreateAlias",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:PutKeyPolicy",
    "kms:EnableKeyRotation",
    "kms:TagResource"
  ],
  "Resource": "*",
  "Note": "KMS permissions are optional. The module uses S3-managed encryption (AES-256) due to CloudFront OAC compatibility requirements."
}
```

### ACM Permissions (if enable_domain = true)

```json
{
  "Effect": "Allow",
  "Action": [
    "acm:RequestCertificate",
    "acm:DescribeCertificate",
    "acm:DeleteCertificate",
    "acm:AddTagsToCertificate"
  ],
  "Resource": "*"
}
```

### Route 53 Permissions (if create_route53_zone = true)

```json
{
  "Effect": "Allow",
  "Action": [
    "route53:CreateHostedZone",
    "route53:GetHostedZone",
    "route53:DeleteHostedZone",
    "route53:ChangeResourceRecordSets",
    "route53:GetChange",
    "route53:ListResourceRecordSets",
    "route53:ChangeTagsForResource"
  ],
  "Resource": "*"
}
```

### IAM Permissions (for S3 replication)

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:GetRole",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:GetRolePolicy"
  ],
  "Resource": "arn:aws:iam::*:role/*"
}
```

## Important: CloudFront OAC and KMS Encryption Incompatibility

### Why This Module Uses AES-256 Instead of KMS

This module uses S3-managed encryption (SSE-S3/AES-256) for website buckets instead of customer-managed KMS keys due to an AWS platform limitation:

**The Issue**: CloudFront Origin Access Control (OAC) cannot access KMS-encrypted S3 objects.

**Why**: When CloudFront uses OAC to fetch objects from S3, it makes **anonymous requests** to S3. KMS requires **authenticated requests** with proper IAM permissions to decrypt data. Since CloudFront's requests are anonymous (by design of OAC), KMS cannot decrypt the objects, resulting in 403 Forbidden errors.

**The Solution**: Use S3-managed encryption (SSE-S3) with AES-256 algorithm. This provides:

- Encryption at rest for all objects
- No additional cost (included with S3)
- Full compatibility with CloudFront OAC
- Automatic encryption for all new objects

**Security Note**: While AES-256 doesn't provide the same level of key management control as KMS (you can't rotate keys on your schedule or use custom key policies), it still provides strong encryption at rest using the AES-256 algorithm, which is the same encryption algorithm used by KMS.

**If You Need KMS**: If your compliance requirements mandate customer-managed keys, you would need to use CloudFront Origin Access Identity (OAI, the legacy method) instead of OAC, or use a different architecture such as Lambda@Edge to handle decryption. However, OAC is the recommended approach by AWS for new deployments.

### Migrating from KMS to AES-256

If you previously deployed this module with KMS encryption, note that:

1. Changing bucket encryption settings only affects **new objects**
2. Existing objects retain their original encryption
3. You must re-upload objects to apply the new encryption:

```bash
# Re-upload all objects
aws s3 sync ./website-content s3://your-bucket-name/ --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation --distribution-id YOUR_DIST_ID --paths "/*"
```

## Troubleshooting

### Direct S3 Access Returns 403

This is expected behavior. S3 buckets are private and can only be accessed through CloudFront. To verify:

```bash
# This should fail (403 Forbidden)
curl https://my-bucket.s3.amazonaws.com/index.html

# This should succeed
curl https://d111111abcdef8.cloudfront.net/index.html
```

### Bucket Cleanup and Force Destroy

All S3 buckets are created with `force_destroy = true` for easier cleanup during development and testing:

- **Development/Testing**: `terraform destroy` will automatically delete buckets and all contents
- **Production**: Consider setting `force_destroy = false` for additional safety
- **Data Recovery**: Ensure you have backups before destroying production buckets

**Note**: Force destroy will permanently delete all objects, versions, and delete markers in the bucket.

### CNAME Already Exists Error

If you get a `CNAMEAlreadyExists` error during deployment, it means the domain is already associated with another CloudFront distribution.

**Solutions:**
1. **Remove conflicting distribution:** Find and delete the old CloudFront distribution using the same domain
2. **Use different domain:** Configure a different domain name for this deployment  
3. **Import existing distribution:** If you own the conflicting distribution, import it into Terraform

**Find conflicting distributions:**
```bash
aws cloudfront list-distributions --query "DistributionList.Items[?Aliases.Items[?contains(@, 'your-domain.com')]]"
```

### CloudFront Returns 403

Check that:

1. The S3 bucket policy allows access from CloudFront OAC
2. The CloudFront distribution is using the correct OAC
3. Objects exist in the S3 bucket

```bash
# List objects in bucket
aws s3 ls s3://$(terraform output -raw website_bucket_name)/

# Check CloudFront distribution status
aws cloudfront get-distribution \
  --id $(terraform output -raw cloudfront_distribution_id) \
  --query 'Distribution.Status'
```

### Replication Not Working

Verify:

1. Versioning is enabled on both buckets
2. IAM role has correct permissions
3. Objects are being created in the primary bucket

```bash
# Check replication status
aws s3api get-bucket-replication \
  --bucket $(terraform output -raw website_bucket_name)
```

### Objects Encrypted with Wrong Algorithm

If you previously deployed with KMS encryption and switched to AES-256, existing objects retain their original encryption. You must re-upload objects for them to use the new encryption setting:

```bash
# Re-upload objects to apply new encryption
aws s3 sync ./website-content s3://$(terraform output -raw website_bucket_name)/ --delete

# Or copy in-place to re-encrypt
aws s3 cp s3://bucket/file.html s3://bucket/file.html --metadata-directive REPLACE
```

### Cache Invalidation

To clear CloudFront cache after updating content:

```bash
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

## Lessons Learned

### S3 Bucket Encryption Settings Are Not Retroactive

When you change an S3 bucket's default encryption settings, the change only applies to **new objects** uploaded after the change. Existing objects retain their original encryption method. This means:

- If you change from KMS to AES-256, existing objects stay KMS-encrypted
- If you change from AES-256 to KMS, existing objects stay AES-256-encrypted
- To re-encrypt existing objects, you must re-upload them or use S3 copy-in-place

**Example**:

```bash
# Copy in-place to re-encrypt with new bucket default
aws s3 cp s3://bucket/file.html s3://bucket/file.html --metadata-directive REPLACE
```

### KMS Key Deletion Makes Data Permanently Inaccessible

If you delete a KMS key, **all data encrypted with that key becomes permanently unrecoverable**, including:

- All versions of versioned objects
- All objects in all buckets encrypted with that key
- No recovery is possible after the deletion waiting period expires

**Best Practices**:

- Never delete KMS keys unless absolutely certain no data needs to be accessed
- Disable keys instead of deleting them
- Use the maximum waiting period (30 days) to allow for recovery
- Monitor for errors after disabling a key before considering deletion

### CloudFront OAC and KMS Are Incompatible

CloudFront Origin Access Control (OAC) cannot access KMS-encrypted S3 objects because:

1. CloudFront makes anonymous requests to S3 when using OAC
2. KMS requires authenticated requests with IAM permissions to decrypt data
3. Anonymous requests cannot be authenticated for KMS decryption

This is an AWS platform limitation, not a bug. The solution is to use S3-managed encryption (SSE-S3/AES-256) for objects accessed via CloudFront OAC.

## License

MIT Licensed. See [LICENSE](./LICENSE) for full details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Authors

Created and maintained by Damien Burks.
