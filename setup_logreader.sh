# setup_logreader

#!/bin/bash

# === Configuration ===
# The username for the dedicated log reader account
LOG_READER_USER="log-reader"
# The target directory containing the log files
LOG_DIR="/var/log/webapp"
# Log file pattern within the target directory
LOG_FILES_PATTERN="*.log"
# === End Configuration ===

# --- Helper Functions ---
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
    exit 1
}

# Function to check if a command was successful
check_command_success() {
    if [ $? -ne 0 ]; then
        log_error "Previous command failed. Exiting."
    fi
}
# --- End Helper Functions ---

# === Pre-flight Checks ===
log_info "Starting least privilege setup for user '$LOG_READER_USER' on directory '$LOG_DIR'."

# Check if running as root (sudo)
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root or using sudo."
fi

# Check if ACL tools (getfacl, setfacl) are installed
if ! command -v setfacl &> /dev/null || ! command -v getfacl &> /dev/null; then
    log_error "'setfacl' or 'getfacl' command not found. Please install ACL utilities (e.g., 'sudo apt update && sudo apt install acl' on Debian/Ubuntu, 'sudo yum install acl' on CentOS/RHEL)."
fi

# Check if the target directory's filesystem supports ACLs
# We attempt to read ACLs; if it fails, ACLs might not be mounted.
if ! getfacl "$LOG_DIR" &> /dev/null; then
    # If the directory doesn't exist yet, we can't check its mount point effectively here.
    # We'll check again after potentially creating it.
    # If it *does* exist and getfacl fails, it's likely an ACL mount issue.
    if [ -d "$LOG_DIR" ]; then
       log_warn "Could not read ACLs from '$LOG_DIR'. Filesystem may not be mounted with ACL support (e.g., add 'acl' to mount options in /etc/fstab). Continuing, but ACLs may not apply."
    fi
fi
# === End Pre-flight Checks ===


# === Resource Setup ===

# 1. Create Target Directory if it doesn't exist
if [ ! -d "$LOG_DIR" ]; then
    log_info "Directory '$LOG_DIR' does not exist. Creating it."
    # Create the directory. Set permissions so only owner (root) and group can access initially.
    mkdir -p "$LOG_DIR"
    check_command_success
    chown root:root "$LOG_DIR" # Or appropriate owner/group if webapp runs as specific user
    check_command_success
    chmod 770 "$LOG_DIR" # Owner: rwx, Group: rwx, Other: --- (adjust group if needed)
    check_command_success
    log_info "Directory '$LOG_DIR' created."

    # Re-check ACL support now that the directory exists
    if ! getfacl "$LOG_DIR" &> /dev/null; then
         log_warn "Could not read ACLs from newly created '$LOG_DIR'. Filesystem may not be mounted with ACL support (e.g., add 'acl' to mount options in /etc/fstab). Continuing, but ACLs may not apply."
    fi
else
    log_info "Directory '$LOG_DIR' already exists."
fi

# 2. Create Log Reader User if it doesn't exist
if ! id "$LOG_READER_USER" &>/dev/null; then
    log_info "User '$LOG_READER_USER' does not exist. Creating user."
    # Create a system user with no login shell (or /bin/bash if needed for interactive checks)
    # -r creates a system user
    # -s /sbin/nologin prevents interactive login (use /bin/bash if testing requires login)
    # -d /home/$LOG_READER_USER specifies home dir (optional, can use /dev/null)
    # -M Do not create the user's home directory
    useradd -r -s /bin/bash -M "$LOG_READER_USER"
    check_command_success
    log_info "User '$LOG_READER_USER' created."
else
    log_info "User '$LOG_READER_USER' already exists."
fi

# === Apply Permissions (ACLs) ===

log_info "Applying ACLs for user '$LOG_READER_USER' on '$LOG_DIR'..."

# 3. Grant Read/Execute on the directory itself
# -m modifies ACLs
# u:user:permissions
setfacl -m "u:$LOG_READER_USER:rx" "$LOG_DIR"
check_command_success
log_info "Granted 'rx' permissions on '$LOG_DIR' for user '$LOG_READER_USER'."

# 4. Grant Read on existing log files matching the pattern
# Use find to handle cases where there are many files or no files matching
# Important: Only apply to files, not directories within LOG_DIR
find "$LOG_DIR" -maxdepth 1 -type f -name "$LOG_FILES_PATTERN" -exec setfacl -m "u:$LOG_READER_USER:r" {} +
# We don't check_command_success directly as find might return non-zero if no files match, which isn't an error here.
# Check if setfacl failed during find execution (less precise)
if [ $? -ne 0 ]; then
    log_warn "Potentially failed to set ACLs on some existing log files (or no files matched '$LOG_FILES_PATTERN'). Check permissions manually if needed."
else
    log_info "Granted 'r' permission on existing files matching '$LOG_FILES_PATTERN' in '$LOG_DIR' for user '$LOG_READER_USER'."
fi


# 5. Set Default ACLs for the directory
# These apply to *new* files/directories created *within* LOG_DIR
# -d modifies default ACLs
# Default for new files: read (r)
setfacl -d -m "u:$LOG_READER_USER:r" "$LOG_DIR"
check_command_success
# Default for new directories: read/execute (rx)
setfacl -d -m "u:$LOG_READER_USER:rx" "$LOG_DIR"
check_command_success
log_info "Set default ACLs on '$LOG_DIR' for user '$LOG_READER_USER' (new files: r, new dirs: rx)."

# === Completion ===
log_info "Least privilege setup for user '$LOG_READER_USER' completed successfully."

exit 0
