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
- **💰 Cost Optimized**: S3 Bucket Keys enabled by default to reduce encryption costs by up to 99%
- **🚀 SPA Support**: Built-in support for Single Page Applications (React, Vue, Angular, Docusaurus)
- **🛡️ Cache Control**: Configurable Cache-Control headers for optimal caching behavior
- **🔥 WAF Protection**: Optional AWS WAF Web ACL with comprehensive security rules and logging

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
│   - WWW subdomain → CloudFront              │
└──────┬──────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│   CloudFront Distribution                   │
│   - HTTPS Only + Custom Domain              │
│   - ACM Certificate (Auto-validated)        │
│   - Security Headers (HSTS, CSP, etc.)      │
│   - Cache-Control Headers                   │
│   - SPA Routing Support                     │
│   - WAF Web ACL (Optional)                  │
│   - Origin Group (Multi-Region Failover)    │
└──────┬──────────────────────────────────────┘
       │
       ├─ Primary Origin (OAC) ──────────────┐
       │                                      ▼
       │              ┌─────────────────────────────────────┐
       │              │ S3 Bucket - Primary Region          │
       │              │ - Private + AES-256 Encrypted       │
       │              │ - S3 Bucket Keys Enabled            │
       │              │ - Replicates to Failover            │
       │              └─────────────────────────────────────┘
       │
       └─ Failover Origin (OAC) ─────────────┐
                                              ▼
                      ┌─────────────────────────────────────┐
                      │ S3 Bucket - Failover Region         │
                      │ - Private + AES-256 Encrypted       │
                      │ - S3 Bucket Keys Enabled            │
                      │ - Replication Destination           │
                      └─────────────────────────────────────┘
```

### Component Relationships

- **KMS Module**: Creates customer-managed KMS keys for encryption (optional - creates keys if not provided)
- **S3 Module**: Creates website buckets (primary + failover) and logging bucket, all with AES-256 encryption and S3 Bucket Keys
- **CloudFront Module**: Creates distribution with OAC, origin groups for failover, security headers, and custom domain support
- **DNS Module**: Creates Route53 zone, ACM certificate, and A/AAAA records pointing to CloudFront distribution

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
- **S3 Bucket Keys**: Enabled by default to reduce encryption costs by up to 99%
- **CloudFront OAC Compatibility**: Website buckets use AES-256 instead of KMS due to AWS limitation
- **Automatic Encryption**: All objects are automatically encrypted at rest using AES-256 algorithm

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
- **Content-Security-Policy**: Configurable (default allows common external resources)
- **Cache-Control**: `no-cache, no-store, must-revalidate` (configurable)

### AWS WAF Protection

When `enable_waf = true`, the module creates and configures:

- **WAF Web ACL**: Comprehensive security rules for CloudFront protection
- **Rate Limiting**: Protection against DDoS and brute force attacks
- **IP Reputation**: Blocks known malicious IP addresses
- **Geographic Restrictions**: Optional country-based access control
- **SQL Injection Protection**: Blocks common SQL injection attempts
- **XSS Protection**: Prevents cross-site scripting attacks
- **CloudWatch Logging**: Detailed WAF logs with KMS encryption
- **Metrics**: CloudWatch metrics for monitoring WAF activity

**WAF Rules Included:**

- AWS Managed Core Rule Set
- AWS Managed Known Bad Inputs Rule Set
- AWS Managed SQL Database Rule Set
- AWS Managed Linux Operating System Rule Set
- Rate limiting (2000 requests per 5 minutes per IP)
- IP reputation list blocking

### Single Page Application (SPA) Routing

When `enable_spa_routing = true`, CloudFront is configured to support client-side routing for modern web frameworks:

- **404 Error Handling**: Redirects 404 errors to `/index.html` with 200 status code
- **403 Error Handling**: Redirects 403 errors to `/index.html` with 200 status code
- **Framework Support**: Required for React Router, Vue Router, Angular Router, Docusaurus, and other client-side routing

This allows URLs like `https://example.com/docs/getting-started` to work correctly when users navigate directly to them or refresh the page.

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
  enable_waf              = false  # Enable for advanced security protection
  cache_control_header    = "no-cache, no-store, must-revalidate"  # Default value

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### With Custom Domain and WAF Protection

```hcl
module "static_website" {
  source = "github.com/your-org/terraform-aws-static-website"

  bucket_name         = "my-website-bucket"
  enable_domain       = true
  domain_name         = "example.com"
  create_route53_zone = true
  enable_waf          = true  # Enable WAF for production security

  tags = {
    Environment = "production"
  }
}
```

### DNS Configuration

When `enable_domain = true`, the module automatically configures:

- **Apex Domain**: `example.com` → CloudFront (A and AAAA ALIAS records)
- **WWW Subdomain**: `www.example.com` → CloudFront (A and AAAA ALIAS records)
- **ACM Certificate**: Covers both apex and www subdomains
- **Automatic Validation**: DNS validation records created in Route 53

**Important**: Both the apex domain and www subdomain use direct ALIAS records to CloudFront, avoiding problematic CNAME → ALIAS chains that can cause DNS resolution issues.

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

| Name                      | Description                                                                                                         | Type         | Default                               | Required |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------- | -------- |
| bucket_name               | Name of the S3 bucket for website content (must be globally unique)                                                 | string       | n/a                                   | yes      |
| enable_domain             | Enable custom domain support with ACM and Route 53                                                                  | bool         | false                                 | no       |
| domain_name               | Primary domain name for the website (required if enable_domain is true)                                             | string       | null                                  | no       |
| alternate_domain_names    | List of alternate domain names (CNAMEs) for CloudFront                                                              | list(string) | []                                    | no       |
| create_route53_zone       | Create a new Route 53 hosted zone for the domain                                                                    | bool         | false                                 | no       |
| existing_route53_zone_id  | Existing Route 53 hosted zone ID (required if enable_domain is true and create_route53_zone is false)               | string       | null                                  | no       |
| auto_validate_certificate | Automatically validate ACM certificate using DNS records in Route53 (set to false if domain is managed outside AWS) | bool         | true                                  | no       |
| logging_enabled           | Enable CloudFront access logging                                                                                    | bool         | true                                  | no       |
| kms_key_arn               | ARN of existing KMS key for S3 encryption (creates new keys if not provided)                                        | string       | null                                  | no       |
| price_class               | CloudFront price class (PriceClass_All, PriceClass_200, PriceClass_100)                                             | string       | "PriceClass_100"                      | no       |
| comment                   | Comment for the CloudFront distribution                                                                             | string       | "Static website distribution"         | no       |
| tags                      | Tags to apply to all resources                                                                                      | map(string)  | {}                                    | no       |
| primary_region            | Primary AWS region for S3 bucket                                                                                    | string       | "us-east-1"                           | no       |
| failover_region           | Failover AWS region for S3 bucket                                                                                   | string       | "us-west-2"                           | no       |
| enable_failover           | Enable multi-region failover                                                                                        | bool         | true                                  | no       |
| enable_replication        | Enable S3 cross-region replication                                                                                  | bool         | true                                  | no       |
| enable_security_headers   | Enable CloudFront response headers policy with security headers                                                     | bool         | true                                  | no       |
| enable_spa_routing        | Enable SPA routing by redirecting 404/403 errors to index.html (for React, Vue, Angular, Docusaurus)                | bool         | false                                 | no       |
| wait_for_deployment       | Wait for CloudFront distribution deployment to complete (can be disabled for faster applies)                        | bool         | true                                  | no       |
| ignore_alias_conflicts    | Temporarily disable domain aliases to avoid CNAME conflicts during updates                                          | bool         | false                                 | no       |
| cache_control_header      | Cache-Control header value to add to all responses from CloudFront                                                  | string       | "no-cache, no-store, must-revalidate" | no       |
| content_security_policy   | Content Security Policy header value                                                                                | string       | (see default in variables.tf)         | no       |
| enable_waf                | Enable AWS WAF Web ACL for CloudFront protection (advanced security feature)                                        | bool         | false                                 | no       |

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

## Important: CloudFront OAC and KMS Encryption Incompatibility

### Why This Module Uses AES-256 Instead of KMS

This module uses S3-managed encryption (SSE-S3/AES-256) for website buckets instead of customer-managed KMS keys due to an AWS platform limitation:

**The Issue**: CloudFront Origin Access Control (OAC) cannot access KMS-encrypted S3 objects.

**Why**: When CloudFront uses OAC to fetch objects from S3, it makes **anonymous requests** to S3. KMS requires **authenticated requests** with proper IAM permissions to decrypt data. Since CloudFront's requests are anonymous (by design of OAC), KMS cannot decrypt the objects, resulting in 403 Forbidden errors.

**The Solution**: Use S3-managed encryption (SSE-S3) with AES-256 algorithm. This provides:

- Encryption at rest for all objects
- S3 Bucket Keys enabled by default (up to 99% cost reduction)
- No additional cost (included with S3)
- Full compatibility with CloudFront OAC
- Automatic encryption for all new objects

## Troubleshooting

### Direct S3 Access Returns 403

This is expected behavior. S3 buckets are private and can only be accessed through CloudFront. To verify:

```bash
# This should fail (403 Forbidden)
curl https://my-bucket.s3.amazonaws.com/index.html

# This should succeed
curl https://d111111abcdef8.cloudfront.net/index.html
```

### CNAME Already Exists Error

If you get a `CNAMEAlreadyExists` error during deployment, it means the domain is already associated with another CloudFront distribution.

**Quick Fix:**

```hcl
module "website" {
  source = "./path/to/module"

  # Temporarily disable aliases to avoid conflicts
  ignore_alias_conflicts = true

  # ... other variables
}
```

**Permanent Solutions:**

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

### Cache Invalidation

To clear CloudFront cache after updating content:

```bash
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

### WAF Blocking Legitimate Traffic

If WAF is blocking legitimate requests:

1. **Check WAF logs**:

```bash
aws logs filter-log-events \
  --log-group-name "aws-waf-logs-$(terraform output -raw website_bucket_name)" \
  --start-time $(date -d '1 hour ago' +%s)000
```

2. **Review blocked requests** in CloudWatch Logs
3. **Adjust WAF rules** if needed by modifying the CloudFront module
4. **Temporarily disable WAF** by setting `enable_waf = false`

**Common WAF Issues:**

- API endpoints being blocked by SQL injection rules
- Large file uploads blocked by size limits
- Legitimate automated tools blocked by rate limiting

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

### WAF Permissions (if enable_waf = true)

```json
{
  "Effect": "Allow",
  "Action": [
    "wafv2:CreateWebACL",
    "wafv2:GetWebACL",
    "wafv2:UpdateWebACL",
    "wafv2:DeleteWebACL",
    "wafv2:PutLoggingConfiguration",
    "wafv2:GetLoggingConfiguration",
    "wafv2:DeleteLoggingConfiguration",
    "wafv2:TagResource",
    "logs:CreateLogGroup",
    "logs:DeleteLogGroup",
    "logs:PutRetentionPolicy",
    "kms:CreateKey",
    "kms:DescribeKey",
    "kms:PutKeyPolicy",
    "kms:CreateAlias",
    "kms:DeleteAlias"
  ],
  "Resource": "*"
}
```

## License

MIT Licensed. See [LICENSE](./LICENSE) for full details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Authors

Created and maintained by [Your Name].
