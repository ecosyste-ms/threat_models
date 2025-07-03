#!/usr/bin/env ruby

require 'pathname'
require 'json'

class ThreatModelHeadingAnalyzer
  def initialize(base_dir)
    @base_dir = Pathname.new(base_dir)
    @headings_by_level = {}
    @heading_counts = Hash.new(0)
    @files_processed = 0
    @file_headings = {}
    @filename_patterns = Hash.new(0)
    @filenames = []
  end

  def analyze
    puts "Analyzing threat model files in: #{@base_dir}"
    
    # Find all markdown files
    markdown_files = Dir.glob(@base_dir.join('**', '*.md'))
    
    puts "Found #{markdown_files.length} markdown files"
    
    markdown_files.each do |file_path|
      process_file(file_path)
    end
    
    generate_report
  end

  private

  def process_file(file_path)
    relative_path = Pathname.new(file_path).relative_path_from(@base_dir)
    
    begin
      content = File.read(file_path, encoding: 'UTF-8')
      headings = extract_headings(content)
      
      # Always analyze filename patterns
      analyze_filename(relative_path.to_s)
      
      unless headings.empty?
        @file_headings[relative_path.to_s] = headings
        @files_processed += 1
        puts "DEBUG: Processed file #{@files_processed}: #{relative_path}" if @files_processed <= 3
        
        headings.each do |heading_info|
          level = heading_info[:level]
          text = heading_info[:text]
          
          @headings_by_level[level] ||= []
          @headings_by_level[level] << {
            text: text,
            file: relative_path.to_s,
            normalized: normalize_heading(text)
          }
          
          @heading_counts[normalize_heading(text)] += 1
        end
      end
      
    rescue => e
      puts "Error processing #{relative_path}: #{e.message}"
    end
  end

  def extract_headings(content)
    headings = []
    
    content.each_line.with_index do |line, index|
      line = line.strip
      
      # Match markdown headings (# ## ### etc.)
      if match = line.match(/^(#+)\s+(.+)$/)
        level = match[1].length
        text = match[2].strip
        
        headings << {
          level: level,
          text: text,
          line_number: index + 1
        }
      end
    end
    
    headings
  end

  def normalize_heading(text)
    # Remove common variations for counting
    text.downcase
        .gsub(/[^\w\s]/, '')
        .gsub(/\s+/, ' ')
        .strip
  end

  def analyze_filename(filepath)
    @filenames << filepath
    
    # Extract just the actual filename without extension and without repo path
    actual_filename = File.basename(filepath, '.md')
    filename = actual_filename.downcase
    
    # Analyze common patterns
    patterns = {
      'threat_model' => filename.include?('threat') && filename.include?('model'),
      'threat_modeling' => filename.include?('threat') && filename.include?('modeling'),
      'security' => filename.include?('security'),
      'stride' => filename.include?('stride'),
      'threat' => filename.include?('threat'),
      'model' => filename.include?('model'),
      'risk' => filename.include?('risk'),
      'attack' => filename.include?('attack'),
      'vulnerability' => filename.include?('vulnerability'),
      'asset' => filename.include?('asset'),
      'readme' => filename.include?('readme'),
      'doc' => filename.include?('doc'),
      'index' => filename.include?('index')
    }
    
    patterns.each do |pattern, matches|
      @filename_patterns[pattern] += 1 if matches
    end
  end

  def generate_report
    puts "\n" + "="*80
    puts "THREAT MODEL HEADING ANALYSIS REPORT"
    puts "="*80
    
    puts "\nSUMMARY:"
    puts "- Files processed: #{@files_processed}"
    puts "- Total markdown files found: #{@filenames.length}"
    puts "- Total unique headings: #{@heading_counts.keys.length}"
    puts "- Heading levels found: #{@headings_by_level.keys.sort.join(', ')}"
    
    # Most common headings
    puts "\nMOST COMMON HEADINGS:"
    @heading_counts.sort_by { |_, count| -count }.first(20).each do |heading, count|
      puts "#{count.to_s.rjust(3)}: #{heading}"
    end
    
    # Headings by level
    @headings_by_level.keys.sort.each do |level|
      puts "\n#{'='*40}"
      puts "LEVEL #{level} HEADINGS (H#{level})"
      puts "#{'='*40}"
      
      # Group by normalized text and count
      level_counts = Hash.new(0)
      @headings_by_level[level].each do |heading|
        level_counts[heading[:normalized]] += 1
      end
      
      # Show most common for this level
      level_counts.sort_by { |_, count| -count }.first(15).each do |normalized, count|
        # Find an example of the original text
        example = @headings_by_level[level].find { |h| h[:normalized] == normalized }
        puts "#{count.to_s.rjust(3)}: #{example[:text]}"
      end
      
      puts "\nTotal H#{level} headings: #{@headings_by_level[level].length}"
    end
    
    # Filename patterns
    puts "\n" + "="*80
    puts "FILENAME PATTERNS"
    puts "="*80
    
    analyze_filename_patterns
    
    # Common patterns
    puts "\n" + "="*80
    puts "COMMON HEADING PATTERNS"
    puts "="*80
    
    analyze_patterns
    
    # Save detailed data to JSON
    save_detailed_data
  end

  def analyze_filename_patterns
    puts "\nFILENAME PATTERN ANALYSIS:"
    puts "Total files analyzed: #{@filenames.length}"
    
    @filename_patterns.sort_by { |_, count| -count }.each do |pattern, count|
      percentage = (count.to_f / @filenames.length * 100).round(1)
      puts "#{count.to_s.rjust(3)} (#{percentage.to_s.rjust(5)}%): #{pattern}"
    end
    
    puts "\nMOST COMMON FILENAMES:"
    filename_counts = Hash.new(0)
    @filenames.each do |filepath|
      # Extract just the actual filename, not the full path
      full_filename = File.basename(filepath, '.md').downcase
      
      # Many files have flattened paths in their names (e.g., docs_threat_model)
      # Extract the core filename by taking the last meaningful parts
      clean_filename = if full_filename.include?('_')
        parts = full_filename.split('_')
        # Take the last 1-2 parts that contain meaningful content
        if parts.last.match?(/threat|model|security|risk|attack|stride|readme/)
          # If the last part is meaningful, use it plus the previous part if relevant
          if parts.length > 1 && parts[-2].match?(/threat|model|security|risk|attack|stride|readme|doc/)
            [parts[-2], parts[-1]].join('_')
          else
            parts.last
          end
        else
          # Fall back to original logic
          meaningful_parts = parts.select { |part| part.match?(/threat|model|security|risk|attack|stride|readme|doc/) }
          meaningful_parts.empty? ? full_filename : meaningful_parts.join('_')
        end
      else
        full_filename
      end
      
      filename_counts[clean_filename] += 1
    end
    
    filename_counts.sort_by { |_, count| -count }.first(20).each do |filename, count|
      puts "#{count.to_s.rjust(3)}: #{filename}"
    end
    
    puts "\nCOMMON FILENAME COMPONENTS:"
    word_counts = Hash.new(0)
    @filenames.each do |filepath|
      # Extract just the actual filename, not the full path
      actual_filename = File.basename(filepath, '.md').downcase
      # Split on common delimiters
      words = actual_filename.split(/[-_\s\.]+/).reject(&:empty?)
      words.each { |word| word_counts[word] += 1 }
    end
    
    word_counts.sort_by { |_, count| -count }.first(20).each do |word, count|
      puts "#{count.to_s.rjust(3)}: #{word}"
    end
  end

  def analyze_patterns
    all_headings = @heading_counts.keys
    
    # Pattern analysis
    patterns = {
      'threat' => all_headings.select { |h| h.include?('threat') },
      'security' => all_headings.select { |h| h.include?('security') },
      'attack' => all_headings.select { |h| h.include?('attack') },
      'risk' => all_headings.select { |h| h.include?('risk') },
      'model' => all_headings.select { |h| h.include?('model') },
      'assumption' => all_headings.select { |h| h.include?('assumption') },
      'scope' => all_headings.select { |h| h.include?('scope') },
      'overview' => all_headings.select { |h| h.include?('overview') },
      'introduction' => all_headings.select { |h| h.include?('introduction') },
      'conclusion' => all_headings.select { |h| h.include?('conclusion') },
      'mitigation' => all_headings.select { |h| h.include?('mitigation') },
      'control' => all_headings.select { |h| h.include?('control') },
      'vulnerability' => all_headings.select { |h| h.include?('vulnerability') },
      'asset' => all_headings.select { |h| h.include?('asset') },
      'actor' => all_headings.select { |h| h.include?('actor') }
    }
    
    patterns.each do |pattern, matches|
      if matches.length > 0
        puts "\n'#{pattern.upcase}' related headings (#{matches.length}):"
        matches.sort_by { |h| -@heading_counts[h] }.first(10).each do |heading|
          puts "  #{@heading_counts[heading].to_s.rjust(2)}: #{heading}"
        end
      end
    end
  end

  def save_detailed_data
    output_file = 'heading_analysis_results.json'
    
    puts "DEBUG: About to save - files_processed: #{@files_processed}, filenames: #{@filenames.length}, headings: #{@heading_counts.keys.length}"
    
    data = {
      summary: {
        files_processed: @files_processed,
        total_files_found: @filenames.length,
        total_headings: @heading_counts.keys.length,
        levels_found: @headings_by_level.keys.sort
      },
      heading_counts: @heading_counts,
      headings_by_level: @headings_by_level,
      file_headings: @file_headings,
      filename_patterns: @filename_patterns,
      filenames: @filenames
    }
    
    File.write(output_file, JSON.pretty_generate(data))
    puts "\nDetailed results saved to: #{output_file}"
  end
end

# Run the analysis
if __FILE__ == $0
  base_dir = ARGV[0] || File.join(File.dirname(__FILE__), 'downloads')
  analyzer = ThreatModelHeadingAnalyzer.new(base_dir)
  analyzer.analyze
end