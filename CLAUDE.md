# AWS S3 File Inventory & Security Audit Tool

## Purpose
The `audit.rb` file is a comprehensive AWS S3 security audit and file inventory tool that scans all S3 buckets in an AWS account to create a detailed database of files, assess public access risks, and help with file lifecycle management.

## Key Features

### 1. S3 Bucket & File Inventory
- Scans all accessible S3 buckets in the AWS account
- Creates a SQLite database (`aws_s3_inventory.db`) with detailed file metadata
- Tracks file attributes: size, last modified date, storage class, ownership, tags
- Maintains file activity status (active/inactive based on current S3 state)

### 2. Public Access Security Assessment  
- **Bucket-level analysis**: Checks bucket policies and Public Access Block settings
- **Object-level analysis**: Evaluates individual file ACLs for public accessibility
- **Risk categorization**: Identifies files accessible via bucket policy, object ACL, or mixed methods
- **Security reporting**: Highlights large publicly accessible files as potential security risks

### 3. File Ownership & Management Intelligence
- **Smart ownership detection**: Extracts responsible persons from S3 tags and file paths
- **Department/project mapping**: Identifies organizational context from tags and naming patterns
- **Management fields**: Supports retention policies, review dates, deletion approval tracking
- **File categorization**: Groups files by extension, department, and project

### 4. Comprehensive Reporting & Analytics
- **Summary statistics**: Total files, sizes, ownership coverage, age distribution
- **SQL query templates**: Pre-built queries for common file management tasks
- **Performance tracking**: Monitors scan progress and provides detailed logging

## Security Focus
This tool serves as a defensive security measure by:
- Identifying potential data exposure risks through public access analysis
- Providing visibility into file ownership and accountability
- Supporting compliance and data governance initiatives
- Enabling systematic cleanup of old or unmanaged files

## Usage Context
Designed for security teams, DevOps engineers, and compliance officers who need to:
- Audit S3 storage for security vulnerabilities
- Manage file lifecycle and cleanup processes  
- Ensure proper data governance and ownership
- Generate reports for compliance and cost optimization

The tool requires appropriate AWS IAM permissions for S3 read operations and optionally tagging/ACL permissions for comprehensive analysis.