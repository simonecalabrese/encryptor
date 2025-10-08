#!/bin/bash

ENCRYPTOR="./encryptor"
PASSWORD="super_strong_passw"
TMP_DIR="./tmp_test"
mkdir -p "$TMP_DIR"

# Exit on error.
set -e

# Helper: Compare two files by MD5 hash.
compare_files() {
    local file1=$1
    local file2=$2
    local hash1
    local hash2
    hash1=$(md5sum "$file1" | cut -d ' ' -f 1)
    hash2=$(md5sum "$file2" | cut -d ' ' -f 1)

    if [[ "$hash1" != "$hash2" ]]; then
        echo "❌ Files differ: $file1 vs $file2"
        exit 1
    fi
}

# Helper: Create a file with specified size.
create_file_with_size() {
    local file="$1"
    local size="$2"

    if command -v mkfile >/dev/null 2>&1; then
        # mkfile only accepts sizes like 1m, 512k — lowercase only
        mkfile "${size,,}" "$file"
    elif command -v truncate >/dev/null 2>&1; then
        truncate -s "$size" "$file"
    elif command -v gtruncate >/dev/null 2>&1; then
        gtruncate -s "$size" "$file"
    elif command -v dd >/dev/null 2>&1; then
        # Parse size into bytes for dd (manual parsing)
        local bs=1
        local count="$size"

        if [[ "$size" =~ ^([0-9]+)([KkMmGg])$ ]]; then
            count="${BASH_REMATCH[1]}"
            unit="${BASH_REMATCH[2]}"
            case "$unit" in
                [Kk]) bs=1K ;;
                [Mm]) bs=1M ;;
                [Gg]) bs=1G ;;
            esac
        fi

        dd if=/dev/zero of="$file" bs="$bs" count="$count" status=none
    else
        echo "Error: No suitable command found to create file." >&2
        return 1
    fi
}



# Test 1: Simple text file
test_simple_text_file() {
    echo "Running Test 1: Simple text file"
    local input="$TMP_DIR/simple.txt"
    local enc="$TMP_DIR/simple.enc"
    local dec="$TMP_DIR/simple.dec"

    echo "Hello, World!" > "$input"

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 1 passed"
}

# Test 2: Empty file
test_empty_file() {
    echo "Running Test 2: Empty file"
    local input="$TMP_DIR/empty.txt"
    local enc="$TMP_DIR/empty.enc"
    local dec="$TMP_DIR/empty.dec"

    > "$input"  # create 0-byte file

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 2 passed"
}

# Test 3: File with all byte values
test_all_bytes_file() {
    echo "Running Test 3: All-byte file"
    local input="$TMP_DIR/all_bytes.bin"
    local enc="$TMP_DIR/all_bytes.enc"
    local dec="$TMP_DIR/all_bytes.dec"

    # Create file with 0x00 to 0xFF
    for i in $(seq 0 255); do
        printf '%b' "\\x$(printf '%02x' $i)" >> "$input"
    done

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 3 passed"
}

# Test 4: 1B file
test_1b_file() {
    echo "Running Test 4: 1B file"
    local input="$TMP_DIR/1b.txt"
    local enc="$TMP_DIR/1b.enc"
    local dec="$TMP_DIR/1b.dec"

    echo -n "a" > "$input"

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 4 passed"
}

# Test 5: 1KB file
test_1kb_file() {
    echo "Running Test 5: 1KB file"
    local input="$TMP_DIR/1kb.txt"
    local enc="$TMP_DIR/1kb.enc"
    local dec="$TMP_DIR/1kb.dec"

    create_file_with_size "$input" 1K

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 5 passed"
}

# Test 6: 1MB file
test_1mb_file() {
    echo "Running Test 6: 1MB file"
    local input="$TMP_DIR/1mb.txt"
    local enc="$TMP_DIR/1mb.enc"
    local dec="$TMP_DIR/1mb.dec"

    # Create file
    create_file_with_size "$input" 1M

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 6 passed"
}

# Test 7: 1GB file
test_1gb_file() {
    echo "Running Test 7: 1GB file"
    local input="$TMP_DIR/1gb.txt"
    local enc="$TMP_DIR/1gb.enc"
    local dec="$TMP_DIR/1gb.dec"

    # Create file
    create_file_with_size "$input" 1G

    $ENCRYPTOR "$input" "$enc" "$PASSWORD"
    $ENCRYPTOR -d "$enc" "$dec" "$PASSWORD"

    compare_files "$input" "$dec"
    echo "✅ Test 7 passed"
}

# Clean tmp dir
clean_up() {
    echo "Cleaning up..."
    rm -rf "$TMP_DIR"
}

# Run tests
test_simple_text_file
test_empty_file
test_all_bytes_file
test_1b_file
test_1kb_file
test_1mb_file
sleep 1
test_1gb_file

clean_up

echo "✅ All tests passed!"