#!/usr/bin/env ruby

require 'aws-sdk-s3'
require 'sqlite3'
require 'json'
require 'time'
require 'logger'

class S3FileInventory
  def initialize
    @logger = Logger.new(STDOUT)
    @logger.level = Logger::INFO

    # Initialize AWS S3 client
    @s3_client = Aws::S3::Client.new

    # Initialize SQLite database
    @db_path = 'aws_s3_inventory.db'
    @db = SQLite3::Database.new(@db_path)

    setup_database
  end

  def setup_database
    @logger.info "Setting up SQLite database..."

    # Create tables
    @db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS buckets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        region TEXT,
        creation_date DATETIME,
        scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,

        -- Public access information
        has_public_read_policy BOOLEAN DEFAULT 0,
        has_public_write_policy BOOLEAN DEFAULT 0,
        block_public_acls BOOLEAN DEFAULT 1,
        ignore_public_acls BOOLEAN DEFAULT 1,
        block_public_policy BOOLEAN DEFAULT 1,
        restrict_public_buckets BOOLEAN DEFAULT 1,
        public_access_checked_at DATETIME
      );
    SQL

    @db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket_id INTEGER,
        key TEXT NOT NULL,
        filename TEXT,
        file_extension TEXT,
        directory_path TEXT,
        size INTEGER,
        last_modified DATETIME,
        etag TEXT,
        storage_class TEXT,
        owner_id TEXT,
        owner_display_name TEXT,

        -- Public access information
        is_publicly_accessible BOOLEAN DEFAULT 0,
        public_access_method TEXT, -- 'bucket_policy', 'bucket_acl', 'object_acl', 'mixed', 'none'
        public_access_checked_at DATETIME,

        -- Management fields
        responsible_person TEXT,
        department TEXT,
        project_name TEXT,
        file_purpose TEXT,
        retention_policy TEXT,
        review_date DATE,
        can_be_deleted BOOLEAN DEFAULT 0,
        deletion_approved_by TEXT,
        notes TEXT,

        -- Status tracking
        is_active BOOLEAN DEFAULT 1,
        last_verified DATETIME,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (bucket_id) REFERENCES buckets (id),
        UNIQUE(bucket_id, key)
      );
    SQL

    @db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS file_tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        tag_key TEXT,
        tag_value TEXT,
        FOREIGN KEY (file_id) REFERENCES files (id),
        UNIQUE(file_id, tag_key)
      );
    SQL

    # Create indexes for better performance
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_bucket_id ON files (bucket_id);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_responsible_person ON files (responsible_person);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_can_be_deleted ON files (can_be_deleted);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_last_modified ON files (last_modified);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_filename ON files (filename);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_file_extension ON files (file_extension);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_is_active ON files (is_active);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_is_publicly_accessible ON files (is_publicly_accessible);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_files_public_access_method ON files (public_access_method);"
    @db.execute "CREATE INDEX IF NOT EXISTS idx_buckets_has_public_read_policy ON buckets (has_public_read_policy);"

    @logger.info "Database setup complete"
  end

  def scan_all_buckets
    @logger.info "Starting S3 bucket scan..."

    begin
      # Mark all buckets as inactive initially
      @db.execute("UPDATE buckets SET is_active = 0")

      # Get list of all buckets
      buckets_response = @s3_client.list_buckets

      buckets_response.buckets.each do |bucket|
        process_bucket(bucket)
      end

      # Log inactive buckets (buckets that no longer exist)
      inactive_buckets = @db.execute("SELECT name FROM buckets WHERE is_active = 0")
      unless inactive_buckets.empty?
        @logger.info "Buckets no longer accessible:"
        inactive_buckets.each { |bucket| @logger.info "  - #{bucket[0]}" }
      end

      @logger.info "Scan complete!"
      generate_summary_report

    rescue Aws::S3::Errors::ServiceError => e
      @logger.error "AWS S3 Error: #{e.message}"
      raise
    end
  end

  private

  def process_bucket(bucket)
    @logger.info "Processing bucket: #{bucket.name}"

    # Insert or update bucket info
    bucket_id = insert_bucket(bucket)

    begin
      # Get bucket region
      region = get_bucket_region(bucket.name)

      # Update bucket with region info
      @db.execute("UPDATE buckets SET region = ? WHERE id = ?", [region, bucket_id])

      # Check bucket public access settings
      bucket_public_info = check_bucket_public_access(bucket.name)

      # List all objects in bucket
      scan_bucket_objects(bucket_id, bucket.name, bucket_public_info)

    rescue Aws::S3::Errors::NoSuchBucket
      @logger.warn "Bucket #{bucket.name} no longer exists"
    rescue Aws::S3::Errors::AccessDenied
      @logger.warn "Access denied to bucket #{bucket.name}"
    rescue Aws::S3::Errors::ServiceError => e
      @logger.error "Error processing bucket #{bucket.name}: #{e.message}"
    end
  end

  def insert_bucket(bucket)
    # Check if bucket exists
    existing = @db.execute("SELECT id FROM buckets WHERE name = ?", [bucket.name])

    if existing.empty?
      # Insert new bucket
      @db.execute(
        "INSERT INTO buckets (name, creation_date, scanned_at, is_active) VALUES (?, ?, ?, ?)",
        [bucket.name, bucket.creation_date.iso8601, Time.now.iso8601, 1]
      )
      bucket_id = @db.last_insert_row_id
      @logger.info "  New bucket added: #{bucket.name}"
    else
      # Update existing bucket
      bucket_id = existing.first[0]
      @db.execute(
        "UPDATE buckets SET scanned_at = ?, is_active = 1 WHERE id = ?",
        [Time.now.iso8601, bucket_id]
      )
      @logger.debug "  Updated existing bucket: #{bucket.name}"
    end

    bucket_id
  end

  def get_bucket_region(bucket_name)
    location_response = @s3_client.get_bucket_location(bucket: bucket_name)
    location_response.location_constraint || 'us-east-1'
  rescue
    'unknown'
  end

  def scan_bucket_objects(bucket_id, bucket_name, bucket_public_info)
    if ["strategic-coach-logs", "strategic-coach-replacement-files", "aws-cloudtrail-logs-304519800218-5032a52c", "heroku-tsc-logs", "rawvideo-archive", "sc-tech-support"].include?(bucket_name)
      @logger.info "Skipping bucket #{bucket_name}"
      return
    end

    continuation_token = nil
    object_count = 0
    new_objects = 0
    updated_objects = 0

    # Mark all files in this bucket as inactive initially
    @db.execute("UPDATE files SET is_active = 0 WHERE bucket_id = ?", [bucket_id])

    loop do
      params = {
        bucket: bucket_name,
        max_keys: 1000
      }
      params[:continuation_token] = continuation_token if continuation_token

      begin
        response = @s3_client.list_objects_v2(params)

        response.contents.each do |object|
          result = insert_or_update_file(bucket_id, bucket_name, object, bucket_public_info)
          case result
          when :new
            new_objects += 1
          when :updated
            updated_objects += 1
          end

          object_count += 1

          if object_count % 100 == 0
            @logger.info "  Processed #{object_count} objects from #{bucket_name} (#{new_objects} new, #{updated_objects} updated)"
          end
        end

        break unless response.is_truncated
        continuation_token = response.next_continuation_token

      rescue Aws::S3::Errors::ServiceError => e
        @logger.error "Error listing objects in #{bucket_name}: #{e.message}"
        break
      end
    end

    # Log inactive files (files that no longer exist in S3)
    inactive_files = @db.execute(
      "SELECT COUNT(*) FROM files WHERE bucket_id = ? AND is_active = 0",
      [bucket_id]
    ).first[0]

    @logger.info "  #{bucket_name} summary: #{object_count} total (#{new_objects} new, #{updated_objects} updated, #{inactive_files} no longer exist)"
  end

  def insert_or_update_file(bucket_id, bucket_name, object, bucket_public_info)
    # Ensure object.key is a string (handle StringIO conversion)
    object_key = object.key.respond_to?(:to_s) ? object.key.to_s : object.key
    
    # Try to get object tags (this requires additional permissions)
    tags = get_object_tags(bucket_name, object_key)

    # Extract potential ownership info from tags or key path
    responsible_person = extract_responsible_person(object_key, tags)
    department = extract_department(object_key, tags)
    project_name = extract_project_name(object_key, tags)

    # Extract filename and path information
    filename, file_extension, directory_path = extract_file_info(object_key)

    # Check if object is publicly accessible
    public_access_info = check_object_public_access(bucket_name, object_key, bucket_public_info)

    # Check if file already exists
    existing = @db.execute(
      "SELECT id, last_modified, etag FROM files WHERE bucket_id = ? AND key = ?",
      [bucket_id, object_key]
    )

    current_time = Time.now.iso8601

    if existing.empty?
      # Insert new file record
      sql = <<-SQL
        INSERT INTO files (
          bucket_id, key, filename, file_extension, directory_path,
          size, last_modified, etag, storage_class,
          owner_id, owner_display_name, responsible_person, department,
          project_name, is_publicly_accessible, public_access_method,
          public_access_checked_at, is_active, last_verified, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      SQL

      params = [
        bucket_id,
        object_key,
        filename,
        file_extension,
        directory_path,
        object.size,
        object.last_modified.iso8601,
        object.etag,
        object.storage_class,
        object.owner&.id,
        object.owner&.display_name,
        responsible_person,
        department,
        project_name,
        public_access_info[:is_public] ? 1 : 0,
        public_access_info[:method],
        current_time,
        1, # is_active
        current_time, # last_verified
        current_time # updated_at
      ]

      @db.execute(sql, params)
      file_id = @db.last_insert_row_id
      insert_file_tags(file_id, tags) unless tags.empty?

      return :new
    else
      # Update existing file
      file_id, existing_last_modified, existing_etag = existing.first

      # Check if file has actually changed
      file_changed = (existing_last_modified != object.last_modified.iso8601) ||
                     (existing_etag != object.etag)

      if file_changed
        # File has changed, update all fields including public access
        sql = <<-SQL
          UPDATE files SET
            filename = ?, file_extension = ?, directory_path = ?,
            size = ?, last_modified = ?, etag = ?, storage_class = ?,
            owner_id = ?, owner_display_name = ?,
            responsible_person = COALESCE(responsible_person, ?),
            department = COALESCE(department, ?),
            project_name = COALESCE(project_name, ?),
            is_publicly_accessible = ?, public_access_method = ?,
            public_access_checked_at = ?, is_active = 1,
            last_verified = ?, updated_at = ?
          WHERE id = ?
        SQL

        params = [
          filename,
          file_extension,
          directory_path,
          object.size,
          object.last_modified.iso8601,
          object.etag,
          object.storage_class,
          object.owner&.id,
          object.owner&.display_name,
          responsible_person, # Only update if current value is NULL
          department,         # Only update if current value is NULL
          project_name,       # Only update if current value is NULL
          public_access_info[:is_public] ? 1 : 0,
          public_access_info[:method],
          current_time,       # public_access_checked_at
          current_time,       # last_verified
          current_time,       # updated_at
          file_id
        ]

        @db.execute(sql, params)

        # Update tags (remove old ones, add new ones)
        @db.execute("DELETE FROM file_tags WHERE file_id = ?", [file_id])
        insert_file_tags(file_id, tags) unless tags.empty?

        return :updated
      else
        # File hasn't changed, just mark as active and update verification time
        # Still check public access in case policies changed
        sql = <<-SQL
UPDATE files SET
  is_publicly_accessible = ?,
  public_access_method = ?,
  public_access_checked_at = ?,
  is_active = 1,
  last_verified = ?
WHERE id = ?
SQL

        @db.execute(sql, [
          public_access_info[:is_public] ? 1 : 0,
          public_access_info[:method],
          current_time,
          current_time,
          file_id
        ])

        return :unchanged
      end
    end
  end

  def extract_file_info(s3_key)
    # Convert to string if it's a StringIO or other object
    s3_key = s3_key.to_s if s3_key.respond_to?(:to_s)
    
    # Handle empty or root keys
    return [nil, nil, nil] if s3_key.nil? || s3_key.empty?

    # Split the key into parts
    parts = s3_key.split('/')

    # If key ends with '/', it's likely a directory
    if s3_key.end_with?('/')
      directory_path = s3_key
      filename = nil
      file_extension = nil
    else
      # Extract filename (last part)
      filename = parts.last

      # Extract file extension
      if filename && filename.include?('.')
        file_extension = File.extname(filename).downcase.gsub('.', '')
      else
        file_extension = nil
      end

      # Extract directory path (everything except the filename)
      if parts.length > 1
        directory_path = parts[0..-2].join('/') + '/'
      else
        directory_path = '/' # Root directory
      end
    end

    [filename, file_extension, directory_path]
  end

  def check_bucket_public_access(bucket_name)
    public_info = {
      has_public_read_policy: false,
      has_public_write_policy: false,
      block_public_acls: true,
      ignore_public_acls: true,
      block_public_policy: true,
      restrict_public_buckets: true
    }

    begin
      # Check Public Access Block settings
      begin
        pab_response = @s3_client.get_public_access_block(bucket: bucket_name)
        pab = pab_response.public_access_block_configuration

        public_info[:block_public_acls] = pab.block_public_acls
        public_info[:ignore_public_acls] = pab.ignore_public_acls
        public_info[:block_public_policy] = pab.block_public_policy
        public_info[:restrict_public_buckets] = pab.restrict_public_buckets
      rescue Aws::S3::Errors::NoSuchPublicAccessBlockConfiguration
        # If no PAB is set, defaults are all false (less restrictive)
        public_info[:block_public_acls] = false
        public_info[:ignore_public_acls] = false
        public_info[:block_public_policy] = false
        public_info[:restrict_public_buckets] = false
      end

      # Check bucket policy for public access
      unless public_info[:block_public_policy]
        begin
          policy_response = @s3_client.get_bucket_policy(bucket: bucket_name)
          policy_string = policy_response.policy.respond_to?(:read) ? policy_response.policy.read : policy_response.policy.to_s
          policy = JSON.parse(policy_string)

          policy['Statement']&.each do |statement|
            next unless statement['Effect'] == 'Allow'

            principals = Array(statement['Principal'])
            if principals.include?('*') || principals.include?({'AWS' => '*'})
              actions = Array(statement['Action'])

              # Check for read permissions
              read_actions = ['s3:GetObject', 's3:GetObjectVersion', 's3:ListBucket']
              if actions.include?('s3:*') || (actions & read_actions).any?
                public_info[:has_public_read_policy] = true
              end

              # Check for write permissions
              write_actions = ['s3:PutObject', 's3:DeleteObject', 's3:PutObjectAcl']
              if actions.include?('s3:*') || (actions & write_actions).any?
                public_info[:has_public_write_policy] = true
              end
            end
          end
        rescue Aws::S3::Errors::NoSuchBucketPolicy
          # No bucket policy exists
        rescue JSON::ParserError
          @logger.warn "Could not parse bucket policy for #{bucket_name}"
        end
      end

    rescue Aws::S3::Errors::ServiceError => e
      @logger.warn "Could not check public access for bucket #{bucket_name}: #{e.message}"
    end

    public_info
  end

  def check_object_public_access(bucket_name, object_key, bucket_public_info)
    access_info = {
      is_public: false,
      method: 'none'
    }

    # If bucket has public read policy and public policies are not blocked
    if bucket_public_info[:has_public_read_policy] && !bucket_public_info[:block_public_policy]
      access_info[:is_public] = true
      access_info[:method] = 'bucket_policy'
      return access_info
    end

    # Check object ACL (if not blocked by bucket settings)
    unless bucket_public_info[:block_public_acls] && bucket_public_info[:ignore_public_acls]
      begin
        acl_response = @s3_client.get_object_acl(bucket: bucket_name, key: object_key)

        acl_response.grants.each do |grant|
          if grant.grantee&.type == 'Group'
            case grant.grantee.uri
            when 'http://acs.amazonaws.com/groups/global/AllUsers'
              access_info[:is_public] = true
              access_info[:method] = access_info[:method] == 'none' ? 'object_acl' : 'mixed'
            when 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
              # Authenticated users (not fully public, but worth noting)
              # Could add a separate field for this if needed
            end
          end
        end

      rescue Aws::S3::Errors::ServiceError => e
        # If we can't check ACL, assume it's not public via ACL
        @logger.debug "Could not check ACL for #{bucket_name}/#{object_key}: #{e.message}"
      end
    end

    access_info
  end

  def get_object_tags(bucket_name, object_key)
    begin
      response = @s3_client.get_object_tagging(bucket: bucket_name, key: object_key)
      tags = {}
      response.tag_set.each do |tag|
        tags[tag.key.downcase] = tag.value
      end
      tags
    rescue Aws::S3::Errors::ServiceError
      # If we can't get tags, return empty hash
      {}
    end
  end

  def insert_file_tags(file_id, tags)
    tags.each do |key, value|
      @db.execute(
        "INSERT OR REPLACE INTO file_tags (file_id, tag_key, tag_value) VALUES (?, ?, ?)",
        [file_id, key, value]
      )
    end
  end

  def extract_responsible_person(key, tags)
    # Convert to string if it's a StringIO or other object
    key = key.to_s if key.respond_to?(:to_s)
    
    # Check tags first
    return tags['owner'] if tags['owner']
    return tags['responsible'] if tags['responsible']
    return tags['created_by'] if tags['created_by']

    # Try to extract from path
    parts = key.split('/')

    # Common patterns: users/username/, team-name/, department/
    if parts.length > 1
      case parts[0].downcase
      when 'users', 'user'
        return parts[1] if parts[1]
      when 'teams', 'team'
        return parts[1] if parts[1]
      end

      # Look for email patterns in path
      parts.each do |part|
        return part if part.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
      end
    end

    nil
  end

  def extract_department(key, tags)
    # Convert to string if it's a StringIO or other object
    key = key.to_s if key.respond_to?(:to_s)
    
    return tags['department'] if tags['department']
    return tags['team'] if tags['team']
    return tags['division'] if tags['division']

    # Common department names in paths
    departments = %w[engineering marketing sales finance hr legal operations devops data]
    key_lower = key.downcase

    departments.each do |dept|
      return dept if key_lower.include?(dept)
    end

    nil
  end

  def extract_project_name(key, tags)
    # Convert to string if it's a StringIO or other object
    key = key.to_s if key.respond_to?(:to_s)
    
    return tags['project'] if tags['project']
    return tags['application'] if tags['application']
    return tags['service'] if tags['service']

    # Try to extract project from path structure
    parts = key.split('/')
    if parts.length > 2 && %w[projects project apps applications].include?(parts[0].downcase)
      return parts[1]
    end

    nil
  end

  def generate_summary_report
    @logger.info "\n" + "="*50
    @logger.info "S3 INVENTORY SUMMARY REPORT"
    @logger.info "="*50

    # Bucket summary
    bucket_count = @db.execute("SELECT COUNT(*) FROM buckets").first[0]
    @logger.info "Total buckets: #{bucket_count}"

    # File summary
    file_count = @db.execute("SELECT COUNT(*) FROM files").first[0]
    total_size = @db.execute("SELECT SUM(size) FROM files").first[0] || 0
    @logger.info "Total files: #{file_count}"
    @logger.info "Total size: #{format_bytes(total_size)}"

    # Files with responsible person identified
    files_with_owner = @db.execute("SELECT COUNT(*) FROM files WHERE responsible_person IS NOT NULL").first[0]
    @logger.info "Files with identified responsible person: #{files_with_owner} (#{(files_with_owner.to_f / file_count * 100).round(1)}%)"

    # Old files (>1 year)
    old_files = @db.execute("SELECT COUNT(*) FROM files WHERE last_modified < datetime('now', '-1 year')").first[0]
    @logger.info "Files older than 1 year: #{old_files} (#{(old_files.to_f / file_count * 100).round(1)}%)"

    # Large files (>100MB)
    large_files = @db.execute("SELECT COUNT(*) FROM files WHERE size > 104857600").first[0]
    @logger.info "Files larger than 100MB: #{large_files}"

    @logger.info "\nDatabase saved to: #{@db_path}"
    @logger.info "Use SQL queries to analyze and manage your files!"

    print_sample_queries
  end

  def format_bytes(bytes)
    units = %w[B KB MB GB TB]
    size = bytes.to_f
    unit_index = 0

    while size >= 1024 && unit_index < units.length - 1
      size /= 1024
      unit_index += 1
    end

    "#{size.round(2)} #{units[unit_index]}"
  end

  def print_sample_queries
    @logger.info "\n" + "-"*50
    @logger.info "SAMPLE SQL QUERIES FOR FILE MANAGEMENT"
    @logger.info "-"*50

    queries = [
      {
        title: "Find files without identified responsible person",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.size, f.last_modified FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.responsible_person IS NULL AND f.is_active = 1 ORDER BY f.size DESC LIMIT 10;"
      },
      {
        title: "Find largest files by department",
        query: "SELECT department, COUNT(*) as file_count, SUM(size) as total_size FROM files WHERE department IS NOT NULL AND is_active = 1 GROUP BY department ORDER BY total_size DESC;"
      },
      {
        title: "Find old files that might be candidates for deletion",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.responsible_person, f.last_modified, f.size FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.last_modified < datetime('now', '-2 years') AND f.can_be_deleted = 0 AND f.is_active = 1 ORDER BY f.last_modified ASC LIMIT 20;"
      },
      {
        title: "Summary by responsible person",
        query: "SELECT responsible_person, COUNT(*) as file_count, SUM(size) as total_size, MAX(last_modified) as latest_file FROM files WHERE responsible_person IS NOT NULL AND is_active = 1 GROUP BY responsible_person ORDER BY total_size DESC;"
      },
      {
        title: "Files by extension (top 10)",
        query: "SELECT file_extension, COUNT(*) as file_count, SUM(size) as total_size, AVG(size) as avg_size FROM files WHERE file_extension IS NOT NULL AND is_active = 1 GROUP BY file_extension ORDER BY file_count DESC LIMIT 10;"
      },
      {
        title: "Recently modified files (last 30 days)",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.last_modified, f.size FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.last_modified > datetime('now', '-30 days') AND f.is_active = 1 ORDER BY f.last_modified DESC LIMIT 20;"
      },
      {
        title: "Find publicly accessible files",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.public_access_method, f.size, f.last_modified FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.is_publicly_accessible = 1 AND f.is_active = 1 ORDER BY f.size DESC LIMIT 20;"
      },
      {
        title: "Find buckets with public access enabled",
        query: "SELECT name, has_public_read_policy, has_public_write_policy, block_public_acls, block_public_policy FROM buckets WHERE (has_public_read_policy = 1 OR has_public_write_policy = 1) AND is_active = 1;"
      },
      {
        title: "Security risk assessment - large public files",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.size, f.public_access_method, f.responsible_person FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.is_publicly_accessible = 1 AND f.size > 10485760 AND f.is_active = 1 ORDER BY f.size DESC;"
      },
      {
        title: "Find inactive files (no longer exist in S3)",
        query: "SELECT b.name as bucket, f.filename, f.directory_path, f.last_verified FROM files f JOIN buckets b ON f.bucket_id = b.id WHERE f.is_active = 0 ORDER BY f.last_verified DESC LIMIT 10;"
      }
    ]

    queries.each do |q|
      @logger.info "\n#{q[:title]}:"
      @logger.info q[:query]
    end
  end
end

# Usage example and CLI interface
if __FILE__ == $0
  puts "AWS S3 File Inventory Script"
  puts "==========================="
  puts "This script will:"
  puts "1. Scan all S3 buckets in your AWS account"
  puts "2. Create an SQLite database with file inventory"
  puts "3. Attempt to identify file ownership from tags and paths"
  puts "4. Generate a summary report"
  puts ""
  puts "Prerequisites:"
  puts "- AWS credentials configured (via ~/.aws/credentials, IAM role, or env vars)"
  puts "- Required permissions:"
  puts "  * s3:ListAllMyBuckets"
  puts "  * s3:ListBucket"
  puts "  * s3:GetBucketLocation"
  puts "  * s3:GetObjectTagging (optional, for better ownership detection)"
  puts "  * s3:GetPublicAccessBlock (for public access checking)"
  puts "  * s3:GetBucketPolicy (for public access checking)"
  puts "  * s3:GetObjectAcl (for public access checking)"
  puts ""

  print "Do you want to proceed? (y/n): "
  response = gets.chomp.downcase

  if response == 'y' || response == 'yes'
    begin
      inventory = S3FileInventory.new
      inventory.scan_all_buckets

      puts "\nTo manage your files, you can now run SQL queries against the database:"
      puts "sqlite3 aws_s3_inventory.db"
      puts ""
      puts "Example management workflow:"
      puts "1. Review files without owners and assign responsible persons"
      puts "2. Set retention policies and review dates"
      puts "3. Mark files for deletion after approval"
      puts "4. Generate cleanup reports"

    rescue => e
      puts "Error: #{e.message}"
      puts "Error class: #{e.class}"
      puts "Backtrace:"
      puts e.backtrace.first(10).join("\n")
      puts "Please check your AWS credentials and permissions."
      exit 1
    end
  else
    puts "Operation cancelled."
  end
end
