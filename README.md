# AWS S3 File Inventory & Security Audit Tool

A comprehensive Ruby script that scans all S3 buckets in your AWS account to create a detailed database of files, assess public access risks, and help with file lifecycle management.

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

## Customization

You can modify the script to:
- Skip specific buckets (see the hardcoded skip list in `scan_bucket_objects`)
- Change the database schema for additional metadata
- Modify ownership extraction patterns for your organization
- Add custom reporting queries