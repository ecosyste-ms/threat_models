#!/usr/bin/env ruby

require 'dotenv/load'
require 'octokit'
require 'json'
require 'csv'
require 'fileutils'
require 'time'
require 'base64'
require 'net/http'

# Check for API token
if ENV['GITHUB_API_TOKEN'].nil? || ENV['GITHUB_API_TOKEN'].empty?
  puts "Error: GITHUB_API_TOKEN is not set."
  puts "Please create a .env file with your GitHub token:"
  puts "  cp .env.example .env"
  puts "  # Then add your token to the .env file"
  exit(1)
end

# Initialize Octokit client with authentication
client = Octokit::Client.new(access_token: ENV['GITHUB_API_TOKEN'])

# Configure auto-pagination to handle large result sets
Octokit.auto_paginate = true

# Create output directories
output_dir = 'threat_model_findings'
downloads_dir = File.join(output_dir, 'downloads')
FileUtils.mkdir_p(downloads_dir)

# Initialize results storage
all_results = []
download_errors = []

# Optimized search queries (GitHub search is case-insensitive)
search_queries = [
  # Filename searches for different naming conventions
  'filename:threat-model.md',
  'filename:threat_model.md',
  'filename:threatmodel.md',
  
  # Using in:path to catch files in subdirectories
  'threat-model.md in:path',
  'threat_model.md in:path',
  'threatmodel.md in:path',
  
  # MDX files
  'filename:threat-model.mdx',
  'filename:threat_model.mdx',
  'filename:threatmodel.mdx',
  
  # Markdown files with .markdown extension
  'filename:threat-model.markdown',
  'filename:threat_model.markdown',
  
  # Path-based searches for files containing these patterns
  'threat-model in:path extension:md',
  'threat_model in:path extension:md',
  'threatmodel in:path extension:md'
]

puts "GitHub Threat Model Optimized Search"
puts "Using API token: #{ENV['GITHUB_API_TOKEN'] ? 'Present' : 'Missing'}"
puts "Output directory: #{output_dir}"
puts "Total search queries: #{search_queries.count}"
puts "=" * 60

# Function to save results (overwrites previous files)
def save_results(results, output_dir, errors = [])
  # Always use the same filenames (no timestamp) to overwrite previous results
  
  # Save as JSON
  json_file = File.join(output_dir, "threat_models.json")
  File.write(json_file, JSON.pretty_generate(results))
  puts "Saved #{results.count} results to #{json_file}"
  
  # Save as CSV
  csv_file = File.join(output_dir, "threat_models.csv")
  CSV.open(csv_file, 'w') do |csv|
    csv << ['Repository', 'Owner', 'File Path', 'HTML URL', 'Size', 'Downloaded']
    results.each do |item|
      csv << [
        item[:repository],
        item[:owner],
        item[:path],
        item[:html_url],
        item[:size],
        item[:downloaded] ? 'Yes' : 'No'
      ]
    end
  end
  puts "Saved CSV to #{csv_file}"
  
  # Save errors if any
  if errors.any?
    errors_file = File.join(output_dir, "download_errors.json")
    File.write(errors_file, JSON.pretty_generate(errors))
    puts "Saved #{errors.count} download errors to #{errors_file}"
  end
end

# Function to download file content
def download_file_content(item, token)
  begin
    branches = ['HEAD', 'main', 'master', 'develop']
    
    branches.each do |branch|
      raw_url = "https://raw.githubusercontent.com/#{item[:repository]}/#{branch}/#{item[:path]}"
      
      uri = URI.parse(raw_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 10
      
      request = Net::HTTP::Get.new(uri)
      request['Authorization'] = "token #{token}"
      request['User-Agent'] = 'Threat-Model-Collector'
      
      response = http.request(request)
      
      if response.code == '200'
        return response.body
      end
    end
    
    return nil
  rescue => e
    return nil
  end
end

# Function to check if file already downloaded
def file_already_downloaded?(repo, path, downloads_dir)
  safe_repo = repo.gsub('/', '_')
  safe_filename = path.gsub('/', '_')
  file_path = File.join(downloads_dir, safe_repo, safe_filename)
  
  File.exist?(file_path) && File.size(file_path) > 0
end

# Function to save downloaded content
def save_downloaded_file(content, repo, path, downloads_dir)
  safe_repo = repo.gsub('/', '_')
  repo_dir = File.join(downloads_dir, safe_repo)
  FileUtils.mkdir_p(repo_dir)
  
  safe_filename = path.gsub('/', '_')
  file_path = File.join(repo_dir, safe_filename)
  
  File.write(file_path, content)
  return file_path
end

# Process search results
def process_search_results(items)
  items.map do |item|
    {
      repository: item.repository.full_name,
      owner: item.repository.owner.login,
      path: item.path,
      html_url: item.html_url,
      download_url: item.download_url,
      size: item.size,
      sha: item.sha,
      downloaded: false
    }
  end
end

# Track statistics
total_found_sum = 0
total_retrieved = 0

# Execute searches
puts "\nExecuting searches..."
search_queries.each_with_index do |query, index|
  begin
    print "\rSearch #{index + 1}/#{search_queries.count}: #{query.ljust(40)} "
    
    results = client.search_code(query, per_page: 100)
    total_found = results.total_count
    retrieved = results.items.length
    
    total_found_sum += total_found
    total_retrieved += retrieved
    
    print "Found: #{total_found.to_s.rjust(4)} Retrieved: #{retrieved.to_s.rjust(3)}\n"
    
    if results.items.any?
      processed_items = process_search_results(results.items)
      all_results.concat(processed_items)
    end
    
    sleep(1)
    
  rescue Octokit::TooManyRequests => e
    reset_time = Time.at(e.response_headers['x-ratelimit-reset'].to_i)
    wait_time = (reset_time - Time.now).to_i + 5
    puts "\nRate limit hit. Waiting #{wait_time}s..."
    sleep(wait_time)
    retry
  rescue => e
    puts "\nError: #{e.message}"
  end
end

# Remove duplicates
original_count = all_results.count
all_results.uniq! { |r| "#{r[:repository]}/#{r[:path]}" }
duplicates_removed = original_count - all_results.count

puts "\n" + "=" * 60
puts "Search Results:"
puts "- Total found across all searches: #{total_found_sum}"
puts "- Total retrieved: #{total_retrieved}"
puts "- After removing #{duplicates_removed} duplicates: #{all_results.count} unique files"

# Download files
if all_results.any?
  puts "\n" + "=" * 60
  puts "Downloading #{all_results.count} files..."
  
  successful = 0
  
  all_results.each_with_index do |result, index|
    # Check if already downloaded
    if file_already_downloaded?(result[:repository], result[:path], downloads_dir)
      print "\rProgress: #{index + 1}/#{all_results.count} - Skipping (already downloaded): #{result[:repository]}/#{result[:path]}".ljust(100) + " "
      result[:downloaded] = true
      successful += 1
    else
      print "\rProgress: #{index + 1}/#{all_results.count} - Downloading: #{result[:repository]}/#{result[:path]}".ljust(100) + " "
      
      content = download_file_content(result, ENV['GITHUB_API_TOKEN'])
      
      if content
        save_downloaded_file(content, result[:repository], result[:path], downloads_dir)
        result[:downloaded] = true
        successful += 1
      else
        download_errors << result
      end
      
      sleep(0.1)
    end
  end
  
  puts "\n\nDownload Summary:"
  puts "- Successfully downloaded: #{successful}"
  puts "- Failed: #{download_errors.count}"
  
  # Save results
  save_results(all_results, output_dir, download_errors)
  
  # Create summary
  summary_file = File.join(output_dir, "summary.txt")
  File.open(summary_file, 'w') do |f|
    f.puts "Threat Model Search Summary - #{Time.now}"
    f.puts "=" * 60
    f.puts "Found: #{all_results.count} unique files"
    f.puts "Downloaded: #{successful} files"
    f.puts "\nTop 20 repositories:"
    
    all_results.group_by { |r| r[:repository] }
               .transform_values(&:count)
               .sort_by { |_, count| -count }
               .first(20)
               .each { |repo, count| f.puts "  #{repo}: #{count} files" }
    
    # Check for specific files
    mullvad = all_results.find { |r| r[:repository] == 'mullvad/mullvadvpn-app' }
    f.puts "\nMullvad file: #{mullvad ? "Found at #{mullvad[:path]}" : "Not found"}"
  end
  
  puts "\nFiles saved to: #{downloads_dir}"
  puts "Summary saved to: #{summary_file}"
end

puts "\nDone!"