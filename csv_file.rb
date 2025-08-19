#!/usr/bin/env ruby

require 'sqlite3'
require 'csv'
require 'time'
require 'optparse'

class S3DataExtractor
  def initialize(db_path = 'aws_s3_inventory.db')
    @db_path = db_path
    @output_file = nil
    @filter_options = {}

    unless File.exist?(@db_path)
      puts "Error: Database file '#{@db_path}' not found."
      puts "Please run the S3 inventory script first to create the database."
      exit 1
    end

    @db = SQLite3::Database.new(@db_path)
    @db.results_as_hash = true
  end

  def extract_to_csv(output_file = nil, options = {})
    @output_file = output_file || generate_output_filename
    @filter_options = options

    puts "Extracting data from: #{@db_path}"
    puts "Creating CSV file: #{@output_file}"

    # Get data with bucket names instead of bucket_id
    data = fetch_file_data

    if data.empty?
      puts "No data found matching the specified criteria."
      return
    end

    # Create CSV file
    create_csv_file(data)

    puts "CSV export complete!"
    puts "Total records exported: #{data.length}"
    puts "File saved as: #{@output_file}"

    generate_summary_stats(data)
  end

  private

  def generate_output_filename
    timestamp = Time.now.strftime("%Y%m%d_%H%M%S")
    "s3_inventory_export_#{timestamp}.csv"
  end

  def fetch_file_data
    # Build the SQL query with optional filters
    sql = build_query

    puts "Executing query..."
    puts "SQL: #{sql}" if @filter_options[:verbose]

    @db.execute(sql)
  end

  def build_query
    base_query = <<-SQL
      SELECT
        f.id,
        b.name as bucket_name,
        f.key,
        f.size,
        f.last_modified,
        f.etag,
        f.storage_class,
        f.owner_id,
        f.owner_display_name,
        f.responsible_person,
        f.department,
        f.project_name,
        f.file_purpose,
        f.retention_policy,
        f.review_date,
        f.can_be_deleted,
        f.deletion_approved_by,
        f.notes,
        f.is_publicly_accessible,
        f.public_access_method,
        f.public_access_checked_at,
        f.created_at,
        f.updated_at
      FROM files f
      JOIN buckets b ON f.bucket_id = b.id
    SQL

    # Add WHERE conditions based on filter options
    conditions = []

    if @filter_options[:bucket]
      conditions << "b.name = '#{@filter_options[:bucket]}'"
    end

    if @filter_options[:responsible_person]
      conditions << "f.responsible_person = '#{@filter_options[:responsible_person]}'"
    end

    if @filter_options[:department]
      conditions << "f.department = '#{@filter_options[:department]}'"
    end

    if @filter_options[:project]
      conditions << "f.project_name = '#{@filter_options[:project]}'"
    end

    if @filter_options[:can_be_deleted]
      conditions << "f.can_be_deleted = 1"
    end

    if @filter_options[:older_than_days]
      days = @filter_options[:older_than_days]
      conditions << "f.last_modified < datetime('now', '-#{days} days')"
    end

    if @filter_options[:larger_than_mb]
      bytes = @filter_options[:larger_than_mb] * 1024 * 1024
      conditions << "f.size > #{bytes}"
    end

    if @filter_options[:no_owner]
      conditions << "f.responsible_person IS NULL"
    end

    if @filter_options[:publicly_accessible]
      conditions << "f.is_publicly_accessible = 1"
    end

    if @filter_options[:private_only]
      conditions << "(f.is_publicly_accessible = 0 OR f.is_publicly_accessible IS NULL)"
    end

    if @filter_options[:access_method]
      conditions << "f.public_access_method = '#{@filter_options[:access_method]}'"
    end

    # Add WHERE clause if we have conditions
    unless conditions.empty?
      base_query += " WHERE " + conditions.join(" AND ")
    end

    # Add ORDER BY
    order_by = @filter_options[:order_by] || "b.name, f.key"
    base_query += " ORDER BY #{order_by}"

    # Add LIMIT if specified
    if @filter_options[:limit]
      base_query += " LIMIT #{@filter_options[:limit]}"
    end

    base_query
  end

  def create_csv_file(data)
    CSV.open(@output_file, 'w', write_headers: true, headers: get_csv_headers) do |csv|
      data.each do |row|
        csv_row = [
          row['id'],
          row['bucket_name'],
          row['key'],
          row['size'],
          row['last_modified'],
          row['etag'],
          row['storage_class'],
          row['owner_id'],
          row['owner_display_name'],
          row['responsible_person'],
          row['department'],
          row['project_name'],
          row['file_purpose'],
          row['retention_policy'],
          row['review_date'],
          row['can_be_deleted'],
          row['deletion_approved_by'],
          row['notes'],
          row['is_publicly_accessible'],
          row['public_access_method'],
          row['public_access_checked_at'],
          row['created_at'],
          row['updated_at']
        ]
        csv << csv_row
      end
    end
  end

  def get_csv_headers
    [
      'id',
      'bucket_name',
      'key',
      'size',
      'last_modified',
      'etag',
      'storage_class',
      'owner_id',
      'owner_display_name',
      'responsible_person',
      'department',
      'project_name',
      'file_purpose',
      'retention_policy',
      'review_date',
      'can_be_deleted',
      'deletion_approved_by',
      'notes',
      'is_publicly_accessible',
      'public_access_method',
      'public_access_checked_at',
      'created_at',
      'updated_at'
    ]
  end

  def generate_summary_stats(data)
    puts "\n" + "="*50
    puts "EXPORT SUMMARY STATISTICS"
    puts "="*50

    # Basic stats
    total_files = data.length
    total_size = data.sum { |row| row['size'] || 0 }

    puts "Total files exported: #{total_files}"
    puts "Total size: #{format_bytes(total_size)}"

    # Files by bucket
    buckets = data.group_by { |row| row['bucket_name'] }
    puts "\nFiles by bucket:"
    buckets.each do |bucket, files|
      bucket_size = files.sum { |f| f['size'] || 0 }
      puts "  #{bucket}: #{files.length} files (#{format_bytes(bucket_size)})"
    end

    # Files with/without responsible person
    files_with_owner = data.count { |row| row['responsible_person'] }
    files_without_owner = total_files - files_with_owner

    puts "\nOwnership status:"
    puts "  Files with responsible person: #{files_with_owner}"
    puts "  Files without responsible person: #{files_without_owner}"

    # Files marked for deletion
    files_marked_for_deletion = data.count { |row| row['can_be_deleted'] == 1 }
    if files_marked_for_deletion > 0
      deletion_size = data.select { |row| row['can_be_deleted'] == 1 }
                         .sum { |row| row['size'] || 0 }
      puts "\nDeletion candidates:"
      puts "  Files marked for deletion: #{files_marked_for_deletion}"
      puts "  Potential space savings: #{format_bytes(deletion_size)}"
    end

    # Public access analysis
    public_files = data.count { |row| row['is_publicly_accessible'] == 1 }
    if public_files > 0
      public_size = data.select { |row| row['is_publicly_accessible'] == 1 }
                       .sum { |row| row['size'] || 0 }
      puts "\nPublic access analysis:"
      puts "  Publicly accessible files: #{public_files}"
      puts "  Total size of public files: #{format_bytes(public_size)}"
      
      # Breakdown by access method
      access_methods = data.select { |row| row['is_publicly_accessible'] == 1 }
                          .group_by { |row| row['public_access_method'] || 'unknown' }
      
      puts "  Public access methods:"
      access_methods.each do |method, files|
        method_size = files.sum { |f| f['size'] || 0 }
        puts "    #{method}: #{files.length} files (#{format_bytes(method_size)})"
      end
    else
      puts "\nPublic access analysis:"
      puts "  No publicly accessible files found"
    end

    # Age analysis
    current_time = Time.now
    old_files = data.count do |row|
      if row['last_modified']
        file_time = Time.parse(row['last_modified'])
        (current_time - file_time) > (365 * 24 * 60 * 60) # 1 year in seconds
      else
        false
      end
    end

    puts "\nAge analysis:"
    puts "  Files older than 1 year: #{old_files}"

    # Department breakdown (if available)
    departments = data.group_by { |row| row['department'] || 'Unknown' }
    if departments.keys.length > 1
      puts "\nFiles by department:"
      departments.each do |dept, files|
        dept_size = files.sum { |f| f['size'] || 0 }
        puts "  #{dept}: #{files.length} files (#{format_bytes(dept_size)})"
      end
    end
  end

  def format_bytes(bytes)
    return "0 B" if bytes.nil? || bytes == 0

    units = %w[B KB MB GB TB]
    size = bytes.to_f
    unit_index = 0

    while size >= 1024 && unit_index < units.length - 1
      size /= 1024
      unit_index += 1
    end

    "#{size.round(2)} #{units[unit_index]}"
  end

  public

  def close
    @db.close if @db
  end
end

# Command-line interface
def parse_options
  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options]"
    opts.separator ""
    opts.separator "Extract S3 inventory data from SQLite database to CSV format"
    opts.separator ""
    opts.separator "Options:"

    opts.on("-d", "--database PATH", "Path to SQLite database (default: aws_s3_inventory.db)") do |path|
      options[:database] = path
    end

    opts.on("-o", "--output FILE", "Output CSV filename (default: auto-generated)") do |file|
      options[:output] = file
    end

    opts.on("-b", "--bucket BUCKET", "Filter by specific bucket name") do |bucket|
      options[:bucket] = bucket
    end

    opts.on("-p", "--person PERSON", "Filter by responsible person") do |person|
      options[:responsible_person] = person
    end

    opts.on("-D", "--department DEPT", "Filter by department") do |dept|
      options[:department] = dept
    end

    opts.on("-P", "--project PROJECT", "Filter by project name") do |project|
      options[:project] = project
    end

    opts.on("--deletable", "Only export files marked for deletion") do
      options[:can_be_deleted] = true
    end

    opts.on("--no-owner", "Only export files without responsible person") do
      options[:no_owner] = true
    end

    opts.on("--public", "Only export publicly accessible files") do
      options[:publicly_accessible] = true
    end

    opts.on("--private", "Only export private files") do
      options[:private_only] = true
    end

    opts.on("--access-method METHOD", "Filter by access method (bucket_policy, bucket_acl, object_acl, mixed, none)") do |method|
      options[:access_method] = method
    end

    opts.on("--older-than DAYS", Integer, "Only export files older than X days") do |days|
      options[:older_than_days] = days
    end

    opts.on("--larger-than MB", Integer, "Only export files larger than X MB") do |mb|
      options[:larger_than_mb] = mb
    end

    opts.on("--limit COUNT", Integer, "Limit number of records exported") do |count|
      options[:limit] = count
    end

    opts.on("--order-by FIELD", "Order results by field (default: bucket_name, key)") do |field|
      options[:order_by] = field
    end

    opts.on("-v", "--verbose", "Show SQL query being executed") do
      options[:verbose] = true
    end

    opts.on("-h", "--help", "Show this help message") do
      puts opts
      exit
    end

    opts.separator ""
    opts.separator "Examples:"
    opts.separator "  #{$0}                                    # Export all data"
    opts.separator "  #{$0} -b my-bucket -o bucket-export.csv  # Export specific bucket"
    opts.separator "  #{$0} --no-owner --older-than 365       # Export unowned files older than 1 year"
    opts.separator "  #{$0} --deletable -D engineering        # Export deletable files from engineering"
    opts.separator "  #{$0} --larger-than 100 --limit 50      # Export 50 largest files over 100MB"
    opts.separator "  #{$0} --public --larger-than 10         # Export public files larger than 10MB"
    opts.separator "  #{$0} --access-method bucket_policy     # Export files public via bucket policy"
  end.parse!

  options
end

# Main execution
if __FILE__ == $0
  options = parse_options

  begin
    db_path = options[:database] || 'aws_s3_inventory.db'
    extractor = S3DataExtractor.new(db_path)

    filter_options = options.reject { |k, v| [:database, :output].include?(k) }
    extractor.extract_to_csv(options[:output], filter_options)

  rescue => e
    puts "Error: #{e.message}"
    exit 1
  ensure
    extractor&.close
  end
end
