# GitHub Threat Model Investigation

An investigation into threat modeling practices across GitHub repositories, including tools to collect and analyze threat model documentation files from open-source projects.

## Key Findings

Based on analysis of 583 threat model files from GitHub repositories, here are the major insights:

### Documentation Structure Patterns

**Most Common Heading Types:**
- **H4 Headings**: "Mitigation" (201 occurrences), "Description" (116), "Id" (116)
- **H3 Headings**: "Inputs" (193), "Branches and code coverage" (171), "Function call analysis" (143)
- **H1 Headings**: "Threat Model" (47), "Threat Modeling" (7)
- **H2 Headings**: "References" (29), "Introduction" (21), "Summary" (19)

### Filename Conventions

**Most Popular Naming Patterns:**
- `threat_model` (118 files) - underscore separator
- `threat-model` (62 files) - hyphen separator  
- `threatmodel` (23 files) - no separator
- `readme` (19 files) - general documentation
- `threat_modeling` (16 files) - process-focused

**File Pattern Analysis:**
- 86.6% of files contain both "threat" and "model" in filename
- 25.2% include "doc" or "docs" in the path
- 16.5% use "threat_modeling" (process vs artifact naming)
- 12.0% include "security" in the filename

### Content Themes

**Threat-Related Headings (591 total):**
- "threat model" (61), "threats" (29), "threat modeling" (17)
- Common specific threats: elevation of privilege, memory exhaustion, DoS attacks

**Risk & Security Headings (227 total):**
- "risks_identified" (73), "risk_assessment" (70)
- "security controls" (5), "security goals" (3)

**Attack Vectors (230 headings):**
- Focus on algorithmic complexity attacks, DoS attacks, JSON vulnerabilities
- "attack description" (6), "attack trees" (6), "attack scenarios" (3)

### Methodology Adoption

**STRIDE Framework:**
- 84 explicit "STRIDE" heading references
- Well-established categorization approach

**Technical Implementation:**
- Heavy emphasis on code-level analysis (branches, function calls, inputs)
- Structured data breach analysis (technical assets, probability assessments)
- Integration with development workflows

### International Scope

The dataset includes threat models in multiple languages:
- English (majority)
- Russian ("Моделирование угроз" - 16 files)
- Chinese (在线银行应用相关内容)
- Japanese (本章の目的 - 36 files)

### Documentation Quality Indicators

**Standardization:**
- Consistent use of "Mitigation" as H4 heading suggests tool-generated content
- Structured format indicates mature threat modeling practices
- High occurrence of "References" sections shows research-backed approaches

**Comprehensiveness:**
- Average of 6.5 headings per file across 6 heading levels
- Balance between high-level strategy (H1-H2) and implementation details (H4-H6)
- Integration of both theoretical frameworks and practical implementation guidance

## Setup

1. Install dependencies:
   ```bash
   bundle install
   ```

2. Set up your GitHub token:
   - Copy `.env.example` to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Get a GitHub Personal Access Token from https://github.com/settings/tokens
   - Generate a new token with `repo` scope
   - Add it to your `.env` file

## Usage

Run the script:
```bash
ruby threat_model_collector.rb
```

## Features

- **Smart Search**: Searches for multiple filename patterns (threat-model.md, threat_model.md, threatmodel.md)
- **Incremental Downloads**: Skips files that have already been downloaded
- **Clean Output**: Replaces old CSV/JSON files instead of creating timestamped versions
- **Rate Limit Handling**: Automatically handles GitHub API rate limits
- **Deduplication**: Removes duplicate files from search results
- **Progress Tracking**: Shows real-time download progress

## Output

The script creates a `threat_model_findings` directory containing:
- `threat_models.json` - All search results in JSON format
- `threat_models.csv` - Search results in CSV for easy analysis
- `summary.txt` - Summary statistics
- `downloads/` - Downloaded threat model files organized by repository
- `download_errors.json` - Any download failures (if applicable)

## Search Strategy

The script uses multiple search queries to maximize coverage:
- Direct filename matches: `filename:threat-model.md`
- Path-based searches: `threat-model.md in:path`
- Extension-specific searches: `threat-model in:path extension:md`
- Support for .md, .mdx, and .markdown files

Note: GitHub's search API is case-insensitive and limited to 1000 results per query.

## Analysis Tools

### Heading Analyzer

The repository includes `heading_analyzer.rb`, a comprehensive analysis tool that extracts and analyzes heading patterns from downloaded threat model files.

#### Usage

```bash
ruby heading_analyzer.rb [directory]
```

If no directory is specified, it defaults to `threat_model_findings/downloads`.

#### Features

- **Heading Extraction**: Analyzes all markdown files and extracts headings (H1-H6)
- **Pattern Analysis**: Identifies common heading patterns and themes
- **Filename Analysis**: Analyzes filename patterns and common components
- **Statistical Summary**: Provides detailed statistics on heading usage
- **JSON Export**: Saves detailed results to `heading_analysis_results.json`

#### Output Sections

1. **Summary Statistics**: Total files processed, unique headings, heading levels found
2. **Most Common Headings**: Top 20 most frequently used headings across all files
3. **Headings by Level**: Analysis of H1-H6 headings with frequency counts
4. **Filename Patterns**: Analysis of filename conventions and common components
5. **Thematic Analysis**: Headings grouped by themes (threat, security, attack, risk, etc.)

#### Example Output

```
SUMMARY:
- Files processed: 540
- Total markdown files found: 583
- Total unique headings: 3,543
- Heading levels found: 1, 2, 3, 4, 5, 6

FILENAME PATTERN ANALYSIS:
505 ( 86.6%): threat_model
505 ( 86.6%): threat
505 ( 86.6%): model
147 ( 25.2%): doc
 96 ( 16.5%): threat_modeling
```

The analysis reveals standardized threat modeling documentation patterns with emphasis on:
- Mitigation strategies (most common H4 heading)
- Technical implementation details
- STRIDE methodology
- Risk assessment frameworks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.