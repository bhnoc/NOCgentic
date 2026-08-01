#!/bin/bash

# Default to 10 concurrent tests
CONCURRENT=10

# Parse command line arguments
while getopts "n:" opt; do
    case $opt in
        n) CONCURRENT="$OPTARG" ;;
        *) echo "Usage: $0 [-n CONCURRENT] mirror_file"; exit 1 ;;
    esac
done
shift $((OPTIND-1))

if [ -z "$1" ]; then
    echo "Usage: $0 [-n CONCURRENT] mirror_file"
    exit 1
fi

# Parse your HTML file and extract only http:// URLs
grep -o 'http://[^"]*' "$1" > /tmp/http_mirrors.txt
total_mirrors=$(wc -l < /tmp/http_mirrors.txt)

echo "Found $total_mirrors mirrors to test"
echo "Testing with $CONCURRENT concurrent connections..."
echo "========================"

# Counter for progress
completed=0
# Use temp file for results
results_file="/tmp/mirror_results_$$.txt"

# Function to test a single mirror
test_mirror() {
    local mirror="$1"
    local index="$2"
    local total="$3"
    local host=$(echo "$mirror" | sed -e 's|^[a-z]*://||' -e 's|/.*$||')
    
    echo "Testing ($index/$total): $mirror"
    
    if curl_output=$(curl -I -s -o /dev/null -w "%{http_code} %{time_total}\n" --connect-timeout 5 "$mirror" 2>&1); then
        http_code=$(echo "$curl_output" | awk '{print $1}')
        time_total=$(echo "$curl_output" | awk '{print $2}')
        echo "✓ HTTP $http_code, Time: ${time_total}s - $mirror"
        echo "$time_total $http_code $mirror" >> "$results_file"
    else
        echo "✗ Failed - $mirror"
        echo "999.999 FAILED $mirror" >> "$results_file"
    fi
    
    # Update progress
    ((completed++))
    echo "Progress: $completed/$total completed"
}

export -f test_mirror
export completed
export results_file

# Test mirrors in parallel
index=0
while IFS= read -r mirror; do
    ((index++))
    echo "$mirror|$index|$total_mirrors" >> /tmp/mirror_queue_$$.txt
done < /tmp/http_mirrors.txt

cat /tmp/mirror_queue_$$.txt | xargs -P "$CONCURRENT" -I {} bash -c '
    mirror=$(echo "{}" | cut -d"|" -f1)
    index=$(echo "{}" | cut -d"|" -f2) 
    total=$(echo "{}" | cut -d"|" -f3)
    test_mirror "$mirror" "$index" "$total"
'

echo ""
echo "================================"
echo "Summary sorted by response time:"
echo "================================"

# Sort and display top results
cat "$results_file" | sort -n | head -10

echo ""
echo "================================"
echo "BEST MIRROR FOUND:"
echo "================================"

# Extract best mirror
best_mirror=$(cat "$results_file" | grep -v "FAILED" | sort -n | head -1 | awk '{print $3}')
best_time=$(cat "$results_file" | grep -v "FAILED" | sort -n | head -1 | awk '{print $1}')

if [ -n "$best_mirror" ]; then
    echo "$best_mirror"
    echo "Response time: ${best_time}s"
    echo ""
    echo "================================"
    echo "COPY AND PASTE THIS COMMAND:"
    echo "================================"
    echo ""
    echo "sudo tee /etc/apt/sources.list.d/custom-mirror.list << 'EOF'"
    echo "deb $best_mirror noble main restricted universe multiverse"
    echo "deb-src $best_mirror noble main restricted universe multiverse"
    echo ""
    echo "deb $best_mirror noble-updates main restricted universe multiverse"
    echo "deb-src $best_mirror noble-updates main restricted universe multiverse"
    echo ""
    echo "deb $best_mirror noble-security main restricted universe multiverse"
    echo "deb-src $best_mirror noble-security main restricted universe multiverse"
    echo "EOF"
    echo ""
    echo "sudo rm -rf /var/lib/apt/lists/*"
    echo "sudo apt update"
    echo ""
else
    echo "No working mirrors found!"
fi

# Cleanup
rm -f /tmp/mirror_queue_$$.txt "$results_file"