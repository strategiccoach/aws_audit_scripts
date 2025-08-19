# AWS S3 File Inventory & Security Audit Tool

A comprehensive set of Ruby scripts that scan all S3 buckets in your AWS account to create a detailed database of files, assess public access risks, and help with file lifecycle management.

## Scripts Overview

- **`audit.rb`** - Main inventory script that scans S3 buckets and creates SQLite database
- **`csv_file.rb`** - Data export script that converts inventory data to CSV format with filtering options

## Table of Contents

- [Prerequisites](#prerequisites)
- [AWS Credentials Setup](#aws-credentials-setup-mac)
- [Required AWS Permissions](#required-aws-permissions)
- [Running the Main Audit Script](#how-to-run-the-script)
- [CSV Export Script](#csv-export-script-csv_filerb)
- [Analyzing Results](#analyzing-results)
- [Workflow Examples](#workflow-examples)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

## Prerequisites

### Ruby Installation
Make sure Ruby is installed on your Mac. You can check by running:
```bash
ruby --version
```

If Ruby is not installed, install it using Homebrew:
```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Ruby
brew install ruby
```

### Required Gems
Install the required Ruby gems:
```bash
gem install aws-sdk-s3 sqlite3
```

## AWS Credentials Setup (Mac)

### Option 1: AWS CLI (Recommended)

1. **Install AWS CLI using Homebrew:**
   ```bash
   brew install awscli
   ```

2. **Configure your credentials:**
   ```bash
   aws configure
   ```
   
   You'll be prompted to enter:
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region name (e.g., `us-east-1`)
   - Default output format (leave blank or enter `json`)

3. **Test your configuration:**
   ```bash
   aws s3 ls
   ```

### Option 2: Environment Variables

Set your AWS credentials as environment variables:
```bash
export AWS_ACCESS_KEY_ID="your-access-key-here"
export AWS_SECRET_ACCESS_KEY="your-secret-key-here"
export AWS_DEFAULT_REGION="us-east-1"
```

To make these permanent, add them to your shell profile:
```bash
# For bash users
echo 'export AWS_ACCESS_KEY_ID="your-access-key-here"' >> ~/.bash_profile
echo 'export AWS_SECRET_ACCESS_KEY="your-secret-key-here"' >> ~/.bash_profile
echo 'export AWS_DEFAULT_REGION="us-east-1"' >> ~/.bash_profile

# For zsh users (macOS Catalina and newer)
echo 'export AWS_ACCESS_KEY_ID="your-access-key-here"' >> ~/.zshrc
echo 'export AWS_SECRET_ACCESS_KEY="your-secret-key-here"' >> ~/.zshrc
echo 'export AWS_DEFAULT_REGION="us-east-1"' >> ~/.zshrc
```

### Option 3: Manual Credentials File

Create the AWS credentials file manually:
```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = your-access-key-here
aws_secret_access_key = your-secret-key-here
EOF

cat > ~/.aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

## Required AWS Permissions

Your AWS user/role needs the following permissions:

### Minimal Required Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "*"
        }
    ]
}
```

### Recommended Full Permissions (for complete audit)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:GetObjectTagging",
                "s3:GetPublicAccessBlock",
                "s3:GetBucketPolicy",
                "s3:GetObjectAcl",
                "s3:GetBucketAcl"
            ],
            "Resource": "*"
        }
    ]
}
```

## How to Run the Script

1. **Navigate to the script directory:**
   ```bash
   cd /path/to/your/aws/scripts
   ```

2. **Make sure the script is executable:**
   ```bash
   chmod +x audit.rb
   ```

3. **Run the script:**
   ```bash
   ruby audit.rb
   ```

4. **Follow the prompts:**
   - The script will display information about what it will do
   - Type `y` and press Enter to proceed
   - The script will begin scanning all your S3 buckets

## What the Script Does

1. **Creates SQLite Database**: Creates `aws_s3_inventory.db` in the current directory
2. **Scans All Buckets**: Lists and processes every S3 bucket in your account
3. **Analyzes Security**: Checks for public access configurations at bucket and object level
4. **Extracts Metadata**: Captures file sizes, modification dates, ownership information
5. **Smart Organization**: Attempts to identify responsible persons and departments from tags and paths
6. **Generates Reports**: Provides summary statistics and sample queries for analysis

## Output Files

After running, you'll have:
- `aws_s3_inventory.db` - SQLite database with all inventory data
- Console output with summary statistics and sample queries

## Analyzing Results

### Using SQLite Command Line
```bash
# Open the database
sqlite3 aws_s3_inventory.db

# View table structure
.schema

# Run sample queries (provided by the script output)
```

### Sample Queries

**Find files without identified owners:**
```sql
SELECT b.name as bucket, f.filename, f.directory_path, f.size, f.last_modified 
FROM files f 
JOIN buckets b ON f.bucket_id = b.id 
WHERE f.responsible_person IS NULL AND f.is_active = 1 
ORDER BY f.size DESC LIMIT 10;
```

**Find publicly accessible files:**
```sql
SELECT b.name as bucket, f.filename, f.directory_path, f.public_access_method, f.size 
FROM files f 
JOIN buckets b ON f.bucket_id = b.id 
WHERE f.is_publicly_accessible = 1 AND f.is_active = 1 
ORDER BY f.size DESC;
```

## Troubleshooting

### Common Issues

**"Access Denied" errors:**
- Check your AWS credentials are correctly configured
- Verify your IAM user/role has the required permissions
- Ensure you're using the correct AWS region

**"Gem not found" errors:**
- Install missing gems: `gem install aws-sdk-s3 sqlite3`
- If using system Ruby, you might need `sudo`

**Script runs but finds no buckets:**
- Verify your AWS region configuration
- Check that you have S3 buckets in your account
- Ensure your credentials have `s3:ListAllMyBuckets` permission

**Script takes too long:**
- The script processes every file in every bucket
- Large accounts may take hours to complete
- You can interrupt with Ctrl+C and resume later (existing data is preserved)

### Getting Help

If you encounter issues:
1. Check your AWS credentials: `aws s3 ls`
2. Verify Ruby and gem installations: `ruby --version`, `gem list`
3. Check the script's error output for specific AWS error messages

## Security Notes

- This script only reads data from S3 (no modifications)
- Credentials are accessed through standard AWS credential chain
- The SQLite database contains metadata about your files - keep it secure
- Consider running this on a scheduled basis to maintain current inventory

## CSV Export Script (csv_file.rb)

After running the main audit script, you can use `csv_file.rb` to export your S3 inventory data to CSV format with various filtering options.

### Purpose
The CSV export script reads from the SQLite database created by `audit.rb` and exports the data to CSV format with powerful filtering capabilities. This is useful for:
- Creating reports for management
- Sharing data with teams who prefer spreadsheets
- Further analysis in Excel, Google Sheets, or other tools
- Generating targeted lists (e.g., files for cleanup, security review)
- **Security auditing** - Identify and export publicly accessible files by access method
- **Compliance reporting** - Generate permission-based reports for security reviews

### Prerequisites
- The `audit.rb` script must have been run first to create `aws_s3_inventory.db`
- Ruby with the `csv` gem (usually included with Ruby)

### Basic Usage

**Export all data:**
```bash
ruby csv_file.rb
```

**Export specific bucket:**
```bash
ruby csv_file.rb -b my-bucket-name -o my-bucket-export.csv
```

**Export with custom output filename:**
```bash
ruby csv_file.rb -o custom_export_2024.csv
```

### Filtering Options

**Filter by ownership:**
```bash
# Files without responsible person
ruby csv_file.rb --no-owner

# Files assigned to specific person
ruby csv_file.rb -p "john.doe@company.com"

# Files from specific department
ruby csv_file.rb -D engineering
```

**Filter by age and size:**
```bash
# Files older than 1 year
ruby csv_file.rb --older-than 365

# Files larger than 100MB
ruby csv_file.rb --larger-than 100

# Combined: Large old files
ruby csv_file.rb --older-than 180 --larger-than 50
```

**Filter by project or purpose:**
```bash
# Files from specific project
ruby csv_file.rb -P "website-redesign"

# Files marked for deletion
ruby csv_file.rb --deletable
```

**Filter by file permissions:**
```bash
# Only publicly accessible files
ruby csv_file.rb --public

# Only private files
ruby csv_file.rb --private

# Files public via specific access method
ruby csv_file.rb --access-method bucket_policy
ruby csv_file.rb --access-method object_acl
ruby csv_file.rb --access-method mixed
```

**Limit and order results:**
```bash
# Export only top 100 largest files
ruby csv_file.rb --larger-than 10 --order-by size --limit 100

# Show SQL query being executed
ruby csv_file.rb --verbose
```

### Complete Command Reference

```bash
ruby csv_file.rb [options]

Options:
  -d, --database PATH     Path to SQLite database (default: aws_s3_inventory.db)
  -o, --output FILE       Output CSV filename (default: auto-generated with timestamp)
  -b, --bucket BUCKET     Filter by specific bucket name
  -p, --person PERSON     Filter by responsible person
  -D, --department DEPT   Filter by department
  -P, --project PROJECT   Filter by project name
  --deletable             Only export files marked for deletion
  --no-owner              Only export files without responsible person
  --public                Only export publicly accessible files
  --private               Only export private files
  --access-method METHOD  Filter by access method (bucket_policy, bucket_acl, object_acl, mixed, none)
  --older-than DAYS       Only export files older than X days
  --larger-than MB        Only export files larger than X MB
  --limit COUNT           Limit number of records exported
  --order-by FIELD        Order results by field (default: bucket_name, key)
  -v, --verbose           Show SQL query being executed
  -h, --help              Show help message
```

### Example Use Cases

**Security audit - Find public files:**
```bash
# Export all publicly accessible files
ruby csv_file.rb --public -o all_public_files.csv

# Export large public files for priority review
ruby csv_file.rb --public --larger-than 10 -o large_public_files.csv

# Export files made public via bucket policy (high risk)
ruby csv_file.rb --access-method bucket_policy -o bucket_policy_public.csv

# Export files made public via object ACL
ruby csv_file.rb --access-method object_acl -o object_acl_public.csv
```

**Cleanup preparation - Files for deletion:**
```bash
# Export old, large files without owners for cleanup review
ruby csv_file.rb --no-owner --older-than 730 --larger-than 50 -o cleanup_candidates.csv
```

**Department reports:**
```bash
# Export all engineering files
ruby csv_file.rb -D engineering -o engineering_files.csv

# Export marketing files from specific project
ruby csv_file.rb -D marketing -P "campaign-2024" -o marketing_campaign_files.csv
```

**Cost analysis:**
```bash
# Export largest files for cost optimization
ruby csv_file.rb --larger-than 100 --order-by size --limit 200 -o largest_files.csv
```

### CSV Output Format

The exported CSV includes these columns:
- `id` - Internal database ID
- `bucket_name` - S3 bucket name
- `key` - S3 object key (file path)
- `size` - File size in bytes
- `last_modified` - Last modification date
- `etag` - S3 ETag
- `storage_class` - S3 storage class
- `owner_id` - AWS owner ID
- `owner_display_name` - AWS owner display name
- `responsible_person` - Identified responsible person
- `department` - Identified department
- `project_name` - Identified project
- `file_purpose` - File purpose (if tagged)
- `retention_policy` - Retention policy (if set)
- `review_date` - Review date (if set)
- `can_be_deleted` - Whether marked for deletion
- `deletion_approved_by` - Who approved deletion
- `notes` - Additional notes
- `is_publicly_accessible` - Whether file is publicly accessible (1/0)
- `public_access_method` - How file is public (bucket_policy, bucket_acl, object_acl, mixed, none)
- `public_access_checked_at` - When permissions were last checked
- `created_at` - Database record creation time
- `updated_at` - Database record update time

### Output Summary

Each export includes summary statistics:
- Total files and size exported
- Breakdown by bucket
- Ownership status
- Files marked for deletion
- **Public access analysis** - Count and size of public files, breakdown by access method
- Age analysis
- Department breakdown (if available)

## Workflow Examples

Here are common workflows combining both scripts:

### Complete Security Audit Workflow
```bash
# Step 1: Run the main audit
ruby audit.rb

# Step 2: Export all public files for security review
ruby csv_file.rb --public -o all_public_files_review.csv

# Step 3: Export high-risk public files (large files public via bucket policy)
ruby csv_file.rb --access-method bucket_policy --larger-than 1 -o high_risk_bucket_policy.csv

# Step 4: Export public files via object ACLs for review
ruby csv_file.rb --access-method object_acl -o public_via_object_acl.csv

# Step 5: Export unowned files for assignment
ruby csv_file.rb --no-owner --larger-than 10 -o unowned_files_for_assignment.csv

# Step 6: Export large private files to verify they should be private
ruby csv_file.rb --private --larger-than 100 -o large_private_files_verify.csv
```

### File Cleanup and Cost Optimization Workflow
```bash
# Step 1: Generate cleanup candidates report
ruby csv_file.rb --no-owner --older-than 365 --larger-than 50 -o cleanup_candidates.csv

# Step 2: Generate department-specific reports for review
ruby csv_file.rb -D engineering --older-than 180 -o engineering_old_files.csv
ruby csv_file.rb -D marketing --older-than 180 -o marketing_old_files.csv

# Step 3: After manual review, export confirmed deletion candidates
ruby csv_file.rb --deletable -o confirmed_for_deletion.csv
```

### Departmental Reporting Workflow
```bash
# Generate reports for each department
for dept in engineering marketing sales finance; do
    ruby csv_file.rb -D $dept -o "${dept}_files_report.csv"
done

# Generate summary of largest files by department
ruby csv_file.rb --larger-than 100 --order-by size -o largest_files_all_depts.csv
```

### Regular Monitoring Workflow
```bash
# Create monthly monitoring script
#!/bin/bash
DATE=$(date +%Y%m%d)
REPORT_DIR="reports/$DATE"
mkdir -p $REPORT_DIR

# Run fresh audit
ruby audit.rb

# Generate standard reports
ruby csv_file.rb --no-owner -o "$REPORT_DIR/unowned_files_$DATE.csv"
ruby csv_file.rb --older-than 730 -o "$REPORT_DIR/very_old_files_$DATE.csv"
ruby csv_file.rb --larger-than 1000 --limit 100 -o "$REPORT_DIR/largest_files_$DATE.csv"

echo "Monthly S3 audit reports generated in $REPORT_DIR"
```

### Security-Focused Monitoring Workflow
```bash
# Weekly security check script
#!/bin/bash
DATE=$(date +%Y%m%d)
SECURITY_DIR="security_reports/$DATE"
mkdir -p $SECURITY_DIR

# Run fresh audit
ruby audit.rb

# Generate security-focused reports
ruby csv_file.rb --public -o "$SECURITY_DIR/all_public_files_$DATE.csv"
ruby csv_file.rb --access-method bucket_policy -o "$SECURITY_DIR/bucket_policy_public_$DATE.csv"
ruby csv_file.rb --access-method mixed -o "$SECURITY_DIR/mixed_access_public_$DATE.csv"
ruby csv_file.rb --public --larger-than 100 -o "$SECURITY_DIR/large_public_files_$DATE.csv"

# Check for new public files (compare with previous week)
echo "Security audit reports generated in $SECURITY_DIR"
echo "Review public files, especially those with bucket_policy access method"
```

## Customization

You can modify the scripts to:
- Skip specific buckets (see the hardcoded skip list in `scan_bucket_objects`)
- Change the database schema for additional metadata
- Modify ownership extraction patterns for your organization
- Add custom reporting queries
- Customize CSV export fields and filters