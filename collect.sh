#!/bin/bash

# collect.sh - Collects all text-based files into a single output.txt file
# Each file section starts with **filename**

# Set the output file
OUTPUT_FILE="output.txt"

# Clear the output file if it exists
> "$OUTPUT_FILE"

echo "Collecting files into $OUTPUT_FILE..."

# Function to add file content to output
add_file_to_output() {
    local file="$1"
    
    # Skip if file doesn't exist or is not readable
    if [[ ! -f "$file" || ! -r "$file" ]]; then
        echo "Skipping (not readable): $file"
        return
    fi
    
    # Skip the output file itself
    if [[ "$file" == "./$OUTPUT_FILE" || "$file" == "$OUTPUT_FILE" ]]; then
        echo "Skipping (output file): $file"
        return
    fi
    
    # Skip binary files and common binary extensions
    case "${file##*.}" in
        exe|bin|so|dylib|dll|a|o|class|jar|zip|tar|gz|bz2|xz|7z|rar|deb|rpm|dmg|iso|img)
            echo "Skipping (binary extension): $file"
            return
            ;;
    esac
    
    # For Python files and other text files, skip the binary check or make it more specific
    case "${file##*.}" in
        py|go|md|yml|yaml|txt|mod|sum|conf|config|cfg|ini|json|sh)
            # These are known text files, skip binary check
            ;;
        *)
            # Check if file is binary using file command (only for unknown extensions)
            if file "$file" 2>/dev/null | grep -q "executable\|ELF\|Mach-O\|PE32"; then
                echo "Skipping (binary file): $file"
                return
            fi
            ;;
    esac
    
    echo "Processing: $file"
    
    # Add filename header
    echo "**$file**" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Add file content
    cat "$file" >> "$OUTPUT_FILE"
    
    # Add separator
    echo "" >> "$OUTPUT_FILE"
    echo "---" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Find and process all relevant files
# Include: .py, .go, .md, .yml, .yaml, .txt, .mod, .sum, Dockerfile, docker-compose files

echo "Scanning for files..."

# Use a single find command to get all relevant files
find . -type f \( \
    -name "*.py" -o \
    -name "*.go" -o \
    -name "*.md" -o \
    -name "*.yml" -o \
    -name "*.yaml" -o \
    -name "*.txt" -o \
    -name "*.mod" -o \
    -name "*.sum" -o \
    -name "Dockerfile*" -o \
    -name "docker-compose*" -o \
    -name "*.conf" -o \
    -name "*.config" -o \
    -name "*.cfg" -o \
    -name "*.ini" -o \
    -name "requirements.txt" -o \
    -name "package.json" -o \
    -name "package-lock.json" -o \
    -name "*.sh" -o \
    -name ".gitignore" -o \
    -name "LICENSE*" -o \
    -name "COPYING*" -o \
    -name "*.json" \
\) | sort | while read -r file; do
    add_file_to_output "$file"
done

echo ""
echo "Collection complete! Output saved to: $OUTPUT_FILE"
echo "Total lines in output file: $(wc -l < "$OUTPUT_FILE")"
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
