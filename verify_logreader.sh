# verify_logreader

#!/bin/bash

# === Configuration ===
# The username for the dedicated log reader account (should match setup script)
LOG_READER_USER="log-reader"
# The target directory containing the log files (should match setup script)
LOG_DIR="/var/log/webapp"
# Log file pattern within the target directory
LOG_FILES_PATTERN="*.log"
# A temporary file name for testing write permissions
TEST_WRITE_FILE="verify_write_test.tmp"
# A file outside the allowed directory to test access denial
FORBIDDEN_FILE="/etc/shadow"
# === End Configuration ===

# --- Helper Functions ---
log_info() {
    echo "[INFO] $1"
}

log_ok() {
    echo "[ OK ] $1"
}

log_fail() {
    echo "[FAIL] $1" >&2
    # Increment a failure counter if needed, or exit on first failure
    # For comprehensive testing, we might want to continue and report all failures.
    # exit 1
}

log_warn() {
    echo "[WARN] $1" >&2
}

# Function to check if a user exists
check_user_exists() {
    if id "$1" &>/dev/null; then
        log_ok "User '$1' exists."
    else
        log_fail "User '$1' does not exist."
    fi
}

# Function to check if a directory exists
check_dir_exists() {
    if [ -d "$1" ]; then
        log_ok "Directory '$1' exists."
    else
        log_fail "Directory '$1' does not exist. Cannot perform further checks."
        exit 1 # Exit because subsequent tests depend on the directory
    fi
}

# Function to check specific ACL entry using getfacl and grep
# Usage: check_acl <path> <acl_type_and_user> <expected_perms>
# Example: check_acl "$LOG_DIR" "user:$LOG_READER_USER" "r-x"
check_acl() {
    local path="$1"
    local acl_user="$2"
    local expected_perms="$3"
    local acl_output

    acl_output=$(getfacl -p "$path" 2>/dev/null | grep "^$acl_user:")

    if [ -z "$acl_output" ]; then
        log_fail "ACL entry for '$acl_user' not found on '$path'."
        return
    fi

    # Extract permissions part (e.g., r-x from user:log-reader:r-x)
    local actual_perms=$(echo "$acl_output" | cut -d':' -f3)

    if [ "$actual_perms" == "$expected_perms" ]; then
        log_ok "ACL check passed for '$acl_user' on '$path' (Expected: '$expected_perms', Found: '$actual_perms')."
    else
        log_fail "ACL check failed for '$acl_user' on '$path' (Expected: '$expected_perms', Found: '$actual_perms')."
    fi
}

# Function to check specific *default* ACL entry
# Usage: check_default_acl <path> <acl_type_and_user> <expected_perms>
check_default_acl() {
    local path="$1"
    local acl_user="$2"
    local expected_perms="$3"
    local acl_output

    acl_output=$(getfacl -dp "$path" 2>/dev/null | grep "^default:$acl_user:")

     if [ -z "$acl_output" ]; then
        log_fail "Default ACL entry for '$acl_user' not found on '$path'."
        return
    fi

    # Extract permissions part (e.g., r-x from default:user:log-reader:r-x)
    local actual_perms=$(echo "$acl_output" | cut -d':' -f3)

    if [ "$actual_perms" == "$expected_perms" ]; then
        log_ok "Default ACL check passed for '$acl_user' on '$path' (Expected: '$expected_perms', Found: '$actual_perms')."
    else
        log_fail "Default ACL check failed for '$acl_user' on '$path' (Expected: '$expected_perms', Found: '$actual_perms')."
    fi
}

# Function to test a command execution as the target user
# Usage: test_command_as_user <user> <expected_outcome (0 for success, non-0 for failure)> <command_with_args...>
test_command_as_user() {
    local user="$1"
    local expected_outcome="$2"
    shift 2 # Remove user and expected_outcome from arguments
    local command_to_run="$@"
    local test_desc="Attempting '$command_to_run' as user '$user'"

    log_info "$test_desc..."

    # Execute the command as the specified user. Redirect stdout/stderr to /dev/null
    # unless debugging is needed. Add timeout to prevent hangs?
    sudo -u "$user" -- $command_to_run &> /dev/null
    local actual_outcome=$?

    if [ "$actual_outcome" -eq "$expected_outcome" ]; then
         log_ok "$test_desc - Succeeded as expected (Outcome: $actual_outcome)."
    elif [ "$expected_outcome" -eq 0 ] && [ "$actual_outcome" -ne 0 ]; then
        log_fail "$test_desc - Failed unexpectedly (Expected outcome: 0, Got: $actual_outcome)."
    elif [ "$expected_outcome" -ne 0 ] && [ "$actual_outcome" -eq 0 ]; then
        log_fail "$test_desc - Succeeded unexpectedly (Expected non-zero outcome, Got: 0)."
    else # Expected non-zero, got different non-zero - usually OK for permission denied
         log_ok "$test_desc - Failed as expected (Outcome: $actual_outcome)."
    fi
}
# --- End Helper Functions ---

# === Verification Steps ===
log_info "Starting verification for user '$LOG_READER_USER' on directory '$LOG_DIR'."

# Check if running as root (sudo) - needed for getfacl and sudo -u
if [ "$(id -u)" -ne 0 ]; then
    log_fail "This verification script must be run as root or using sudo."
    exit 1
fi

# 1. Verify User and Directory Existence
check_user_exists "$LOG_READER_USER"
check_dir_exists "$LOG_DIR" # Exits if directory not found

# 2. Verify Directory ACLs
log_info "Verifying ACLs on directory '$LOG_DIR'..."
check_acl "$LOG_DIR" "user:$LOG_READER_USER" "r-x"

# 3. Verify File ACLs (on one existing log file, if possible)
log_info "Verifying ACLs on existing log files in '$LOG_DIR'..."
# Find the first file matching the pattern to test
first_log_file=$(find "$LOG_DIR" -maxdepth 1 -type f -name "$LOG_FILES_PATTERN" -print -quit)
if [ -n "$first_log_file" ]; then
    check_acl "$first_log_file" "user:$LOG_READER_USER" "r--" # Note: r-- is typical, check getfacl output if needed
else
    log_warn "No files matching '$LOG_FILES_PATTERN' found in '$LOG_DIR'. Cannot verify specific file ACLs."
fi

# 4. Verify Default ACLs on Directory
log_info "Verifying default ACLs on directory '$LOG_DIR'..."
check_default_acl "$LOG_DIR" "user:$LOG_READER_USER" "r--" # Default for new files
check_default_acl "$LOG_DIR" "user:$LOG_READER_USER" "r-x" # Default for new directories

# 5. Test Allowed Actions as log-reader
log_info "Testing allowed actions as user '$LOG_READER_USER'..."
test_command_as_user "$LOG_READER_USER" 0 ls -ld "$LOG_DIR" # Check directory listing allowed
if [ -n "$first_log_file" ]; then
    test_command_as_user "$LOG_READER_USER" 0 cat "$first_log_file" # Check reading allowed file
else
     log_warn "Skipping read test on specific file as none were found."
fi

# 6. Test Denied Actions as log-reader
log_info "Testing denied actions as user '$LOG_READER_USER'..."
# Attempt to write a file in the directory (should fail)
test_command_as_user "$LOG_READER_USER" 1 touch "$LOG_DIR/$TEST_WRITE_FILE"
# Clean up the test file if it was somehow created (shouldn't happen)
rm -f "$LOG_DIR/$TEST_WRITE_FILE"

# Attempt to read a forbidden file (should fail)
test_command_as_user "$LOG_READER_USER" 1 cat "$FORBIDDEN_FILE"

# Attempt to delete a log file (should fail, requires write permission on directory)
if [ -n "$first_log_file" ]; then
    test_command_as_user "$LOG_READER_USER" 1 rm "$first_log_file"
else
    log_warn "Skipping delete test on specific file as none were found."
fi

# 7. Test Default ACLs by creating a new file (as root) and checking read access
log_info "Testing default ACL inheritance..."
TEMP_NEW_FILE="$LOG_DIR/new_test_file.log"
echo "Test content" > "$TEMP_NEW_FILE"
if [ $? -ne 0 ]; then
    log_warn "Failed to create temporary file '$TEMP_NEW_FILE' as root. Cannot test default ACL read."
else
    log_info "Created temporary file '$TEMP_NEW_FILE' as root."
    # Verify ACL was inherited correctly on the new file
    check_acl "$TEMP_NEW_FILE" "user:$LOG_READER_USER" "r--"
    # Test if log-reader can read the new file
    test_command_as_user "$LOG_READER_USER" 0 cat "$TEMP_NEW_FILE"
    # Clean up
    rm -f "$TEMP_NEW_FILE"
    log_info "Cleaned up temporary file '$TEMP_NEW_FILE'."
fi


# === Completion ===
# Check if any log_fail calls were made (requires tracking failures)
# For now, just indicate completion. A more robust script could count failures.
log_info "Verification process completed. Review output for any [FAIL] messages."

exit 0 # Or exit with non-zero if failures occurred
