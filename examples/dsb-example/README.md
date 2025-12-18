# Basic Example

This example demonstrates a basic deployment of the AWS static website module without a custom domain.

## Features

- Multi-region S3 buckets (us-east-1 and us-west-2)
- CloudFront distribution with origin failover
- Security headers enabled (HSTS, CSP, X-Frame-Options, etc.)
- S3 cross-region replication
- CloudFront access logging
- KMS encryption for all S3 buckets

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions

## Usage

1. Set the bucket name (must be globally unique):

```bash
export TF_VAR_bucket_name="my-unique-website-bucket-name"
```

2. Initialize Terraform:

```bash
terraform init
```

3. Review the plan:

```bash
terraform plan
```

4. Apply the configuration:

```bash
terraform apply
```

5. Upload your website content to the primary S3 bucket:

```bash
aws s3 sync . s3://$(terraform output -raw website_bucket_name)/ \
  --exclude ".git/*" \
  --exclude ".terraform/*" \
  --exclude "*.tf" \
  --exclude "*.md"
```

6. Access your website:

```bash
echo "Website URL: $(terraform output -raw website_url)"
```

## Testing Failover

To test the failover functionality:

1. Upload a test file to the primary bucket
2. Wait for replication to complete (usually a few minutes)
3. Verify the file exists in the failover bucket
4. The CloudFront distribution will automatically failover to the secondary origin if the primary returns 5xx errors

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

Note: You may need to empty the S3 buckets before destroying if they contain objects.

## Outputs

- `cloudfront_domain_name`: The CloudFront distribution domain name
- `cloudfront_distribution_id`: The CloudFront distribution ID for cache invalidation
- `website_bucket_name`: The primary S3 bucket name
- `website_url`: The full HTTPS URL to access your website
