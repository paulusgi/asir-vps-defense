#!/bin/bash
###############################################################################
#                                                                             #
#     █████╗ ███████╗██╗██████╗     ██╗   ██╗██████╗ ███████╗                 #
#    ██╔══██╗██╔════╝██║██╔══██╗    ██║   ██║██╔══██╗██╔════╝                 #
#    ███████║███████╗██║██████╔╝    ██║   ██║██████╔╝███████╗                 #
#    ██╔══██║╚════██║██║██╔══██╗    ╚██╗ ██╔╝██╔═══╝ ╚════██║                 #
#    ██║  ██║███████║██║██║  ██║     ╚████╔╝ ██║     ███████║                 #
#    ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚══════╝                 #
#                                                                             #
#                      D E F E N S E   S Y S T E M                            #
#                                                                             #
###############################################################################
#
# NAME:         deploy.sh
# VERSION:      3.0.0
# AUTHOR:       Pau Ginesta
# LICENSE:      PolyForm Noncommercial 1.0.0
#
# DESCRIPTION:
#   Orchestrates the deployment of a hardened VPS infrastructure (honeypot)
#   with built-in observability and security hardening:
#
#   • Docker and Docker Compose installation
#   • Firewall hardening (UFW)
#   • Real SSH: public key only, admin only (the honeypot, Cowrie, is on port 22)
#   • Private panel (Nginx + PHP-FPM + MySQL), reachable only through an SSH tunnel
#   • Observability stack (Loki + Promtail)
#   • Fail2Ban with strict policies (35-day ban, 2 attempts)
#
# USAGE:
#   sudo ./deploy.sh
#
# REQUIREMENTS:
#   • Operating system: Debian 11+ / Ubuntu 20.04+
#   • Run as root (sudo)
#   • Internet connection
#
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# Avoid interactive prompts from apt/dpkg
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="ASIR VPS Defense"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly BACKUP_VG_NAME="backups"
readonly BACKUP_LV_NAME="backups"
readonly BACKUP_MOUNTPOINT="/srv/backups"
readonly BACKUP_RETENTION_DEFAULT=7
readonly BACKUP_LOOP_FILE="/var/lib/asir-vps-defense/backups.img"
readonly BACKUP_LOOP_DEFAULT_SIZE="20G"
readonly SSH_PUBKEY_REGEX='^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]'

# State and log paths
readonly STATE_DIR="/var/lib/asir-vps-defense"
readonly LOG_FILE="/var/log/asir-vps-defense/install.log"

# Create the required directories
mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
printf '\n===== %s · %s %s =====\n' "$(date -Is)" "$SCRIPT_NAME" "$SCRIPT_VERSION" >> "$LOG_FILE"

# =============================================================================
# ANSI COLOR PALETTE
# =============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'  # Reset / no color

# =============================================================================
# ERROR HANDLING
# =============================================================================

trap 'handle_error $LINENO' ERR

handle_error() {
    local line_num="$1"
    echo -e "\n${RED}[FATAL ERROR]${NC} Unexpected failure at line ${BOLD}$line_num${NC}" >&2
    echo -e "${DIM}Last 25 lines of the log:${NC}" >&2
    tail -n 25 "$LOG_FILE" >&2
    echo -e "\n${YELLOW}Full log available at:${NC} $LOG_FILE" >&2
    exit 1
}

# =============================================================================
# GLOBAL STATE VARIABLES
# =============================================================================

SECURE_ADMIN=""
CURRENT_REAL_USER=""

# =============================================================================
# LOGGING FUNCTIONS (Unicode icons for readability)
# =============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC}  $1"
}

log_success() {
    echo -e "${GREEN}✓${NC}  $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

log_error() {
    echo -e "${RED}✗${NC}  $1"
}

log_step() {
    # For the main steps of the process
    echo -e "\n${CYAN}→${NC} ${BOLD}$1${NC}"
}

# =============================================================================
# SPINNER AND QUIET EXECUTION
# =============================================================================

run_quiet() {
    local msg="$1"; shift
    local spinner='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0

    "$@" >>"$LOG_FILE" 2>&1 &
    local pid=$!

    # If the command could not be started, fail early
    if [ -z "$pid" ]; then
        printf "\r  %-55s [${RED}✗${NC}]\n" "$msg"
        log_error "Could not start the command: $*"
        return 1
    fi

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  %-55s [${CYAN}%s${NC}]" "$msg" "${spinner:i%10:1}"
        i=$((i + 1))
        sleep 0.15
    done

    # Capture the exit status before errexit can abort
    set +e
    wait "$pid"
    local status=$?
    set -e

    if [ $status -eq 0 ]; then
        printf "\r  %-55s [${GREEN}✓${NC}]  \n" "$msg"
    else
        printf "\r  %-55s [${RED}✗${NC}]\n" "$msg"
        echo -e "\nLast lines of the log:" >&2
        tail -n 25 "$LOG_FILE" >&2
        return $status
    fi
}

# =============================================================================
# PERMISSION CHECKS
# =============================================================================

check_mode() {
    # Checks that a file or directory has the expected mode
    # Usage: check_mode "/path/file" "600" "optional label"
    local path="$1"
    local expected="$2"
    local label="${3:-$path}"
    
    if [ -e "$path" ]; then
        local mode
        mode=$(stat -c "%a" "$path")
        if [ "$mode" != "$expected" ]; then
            log_warn "Wrong permissions on ${label}: mode ${RED}$mode${NC}, expected ${GREEN}$expected${NC}"
            return 1
        fi
    fi
    return 0
}

# =============================================================================
# SSH KEY MANAGEMENT
# =============================================================================

collect_public_keys_for_user() {
    # Collects every SSH public key available on the system
    local user="$1"
    declare -A seen
    declare -A file_seen
    PUBLIC_KEY_CANDIDATES=()
    local files=()
    
    # Prefer find so keys injected by the provider are covered; fall back if find is missing
    if command -v find >/dev/null 2>&1; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find /root /home -maxdepth 4 -type f \( -name "authorized_keys" -o -name "*.pub" -o -name "id_*" \) 2>/dev/null)
    else
        files+=(
            "/home/$user/.ssh/authorized_keys"
            "/home/$CURRENT_REAL_USER/.ssh/authorized_keys"
            "/root/.ssh/authorized_keys"
        )
        for ak in /home/*/.ssh/authorized_keys; do
            [ -f "$ak" ] && files+=("$ak")
        done
        for base in "/home/$user/.ssh" "/home/$CURRENT_REAL_USER/.ssh" "/root/.ssh" /home/*/.ssh; do
            [ -d "$base" ] || continue
            for pub in "$base"/*.pub; do
                [ -f "$pub" ] && files+=("$pub")
            done
        done
    fi

    # Explicit key paths, to ensure coverage even if find was filtered
    files+=(
        "/home/$user/.ssh/authorized_keys"
        "/home/$CURRENT_REAL_USER/.ssh/authorized_keys"
        "/root/.ssh/authorized_keys"
    )

    # Deduplicate the file list
    local unique_files=()
    for f in "${files[@]}"; do
        [ -n "$f" ] || continue
        if [ -z "${file_seen[$f]:-}" ]; then
            unique_files+=("$f")
            file_seen[$f]=1
        fi
    done

    # Extract the keys from each candidate file (authorized_keys or *.pub)
    for file in "${unique_files[@]}"; do
        [ -s "$file" ] || continue
        while IFS= read -r line; do
            [[ "$line" =~ $SSH_PUBKEY_REGEX ]] || continue
            if [ -z "${seen[$line]:-}" ]; then
                PUBLIC_KEY_CANDIDATES+=("$line")
                seen[$line]=1
            fi
        done < <(grep -hE "$SSH_PUBKEY_REGEX" "$file" 2>/dev/null || true)
    done
}

choose_public_key_for_user() {
    # Interactive menu to pick an SSH public key
    local user="$1"
    local purpose="$2"
    collect_public_keys_for_user "$user"
    local candidates=("${PUBLIC_KEY_CANDIDATES[@]}")

    if [ ${#candidates[@]} -gt 0 ]; then
        echo "" >&2
        echo -e "${CYAN}[SSH] Found ${BOLD}${#candidates[@]}${NC}${CYAN} SSH key(s) for ${BOLD}$user${NC}${CYAN} (${purpose}):${NC}" >&2
        echo "" >&2
        local i=1
        for key in "${candidates[@]}"; do
            # Fingerprint + comment: the first characters are identical for every key of a type
            local key_type="${key%% *}"
            local key_id
            key_id=$(ssh-keygen -lf /dev/stdin <<<"$key" 2>/dev/null | cut -d' ' -f2-) || key_id="${key:0:50}..."
            echo -e "  ${GREEN}[$i]${NC} ${DIM}${key_type}${NC} ${key_id}" >&2
            ((i++))
        done
        echo "" >&2
        echo -e "  ${YELLOW}[M]${NC} Enter a key manually" >&2
        echo -e "  ${RED}[Q]${NC} Quit without choosing" >&2
        echo "" >&2
        echo -n -e "${CYAN}Select an option: ${NC}" >&2
        read -r choice < /dev/tty

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#candidates[@]} ]; then
            printf '%s' "${candidates[$((choice-1))]}"
            return 0
        elif [[ "$choice" =~ ^[Mm]$ ]]; then
            candidates=()
        elif [[ "$choice" =~ ^[Qq]$ ]]; then
            return 1
        else
            return 1
        fi
    fi

    # Manual entry (when nothing was detected or M was chosen)
    echo "" >&2
    echo -n -e "${CYAN}Paste an SSH public key (ssh-rsa/ssh-ed25519) or press ENTER to skip: ${NC}" >&2
    read -r manual < /dev/tty
    if [[ "$manual" =~ $SSH_PUBKEY_REGEX ]] && ssh-keygen -lf /dev/stdin <<<"$manual" >/dev/null 2>&1; then
        printf '%s' "$manual"
        return 0
    fi
    return 1
}

# =============================================================================
# CREDENTIAL ENCRYPTION (age)
# =============================================================================

install_age_if_missing() {
    if command -v age >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing 'age' to encrypt the credentials..."
    if ! run_quiet "Installing age (modern encryption)" apt-get install -y age; then
        log_warn "Could not install age. The credentials will be shown in plain text."
        return 1
    fi
    return 0
}

# =============================================================================
# PERMISSION AUDIT
# =============================================================================

audit_permissions() {
    local base="$1"
    local issues=0

    log_info "Running the permission audit on ${BOLD}$base${NC}"
    echo ""

    # Secret files
    echo -e "  ${CYAN}Checking secrets...${NC}"
    check_mode "$base/.env" 600 ".env" || issues=1
    check_mode "$base/mysql/init" 755 "mysql/init (directory)" || issues=1
    if find "$base/mysql/init" -type d ! -perm 755 -print -quit | grep -q .; then 
        issues=1
        log_warn "Directory(ies) in mysql/init without mode 755"
    fi
    if find "$base/mysql/init" -type f ! -perm 644 -print -quit | grep -q .; then 
        issues=1
        log_warn "Files in mysql/init without mode 644"
    fi

    # PHP and Loki configs
    echo -e "  ${CYAN}Checking configuration files...${NC}"
    check_mode "$base/php/conf.d/custom.ini" 644 "php/conf.d/custom.ini" || issues=1
    check_mode "$base/php/pool.d/www.conf" 644 "php/pool.d/www.conf" || issues=1
    check_mode "$base/loki/config.yml" 644 "loki/config.yml" || issues=1

    # Webroot
    echo -e "  ${CYAN}Checking the webroot...${NC}"
    if find "$base/src" -type d ! -perm 755 -print -quit | grep -q .; then 
        issues=1
        log_warn "Directories in src without mode 755"
    fi
    if find "$base/src" -type f ! -perm 644 -print -quit | grep -q .; then 
        issues=1
        log_warn "Files in src without mode 644"
    fi

    # Admin credentials
    echo -e "  ${CYAN}Checking sensitive files...${NC}"
    if [ -f "/home/$SECURE_ADMIN/admin_credentials.txt" ]; then
        check_mode "/home/$SECURE_ADMIN/admin_credentials.txt" 600 "admin_credentials.txt" || issues=1
        log_warn "admin_credentials.txt is present; save its contents and delete it from the server"
    else
        log_info "admin_credentials.txt not found (already removed)"
    fi

    # Admin SSH
    if [ -d "/home/$SECURE_ADMIN/.ssh" ]; then
        check_mode "/home/$SECURE_ADMIN/.ssh" 700 ".ssh" || issues=1
        check_mode "/home/$SECURE_ADMIN/.ssh/authorized_keys" 600 "authorized_keys" || issues=1
    fi

    echo ""
    if [ $issues -eq 0 ]; then
        log_success "Audit complete: ${GREEN}no problems found${NC}"
    else
        log_warn "Audit complete: ${YELLOW}wrong permissions found${NC}"
    fi

    return $issues
}

# =============================================================================
# STATE MANAGEMENT (idempotency)
# =============================================================================

load_env_if_present() {
    # Load the .env variables into the current environment
    if [ -f .env ]; then
        # If .env was sanitized (contains REDACTED), do not load it, but do NOT delete it
        # The file must exist for the backup
        if grep -q 'REDACTED' .env 2>/dev/null; then
            log_warn ".env was sanitized by a previous deploy (this is expected)."
            return
        fi
        set -a
        # shellcheck source=/dev/null
        . ./.env
        set +a
    fi
}

mark_step_done() {
    local step="$1"
    touch "$STATE_DIR/$step"
}

is_step_done() {
    local step="$1"
    [ -f "$STATE_DIR/$step" ]
}

# =============================================================================
# USER INTERFACE
# =============================================================================

print_section() {
    local title="$1"
    local width=58  # Inner width of the box (without the ║ borders)
    local title_len=${#title}
    local padding_left=$(( (width - title_len) / 2 ))
    local padding_right=$(( width - title_len - padding_left ))
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    printf "${GREEN}║${NC}%${padding_left}s${BOLD}%s${NC}%${padding_right}s${GREEN}║${NC}\n" "" "$title" ""
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════╗
    ║     █████╗ ███████╗██╗██████╗     ██╗   ██╗██████╗ ███████╗   ║
    ║    ██╔══██╗██╔════╝██║██╔══██╗    ██║   ██║██╔══██╗██╔════╝   ║
    ║    ███████║███████╗██║██████╔╝    ██║   ██║██████╔╝███████╗   ║
    ║    ██╔══██║╚════██║██║██╔══██╗    ╚██╗ ██╔╝██╔═══╝ ╚════██║   ║
    ║    ██║  ██║███████║██║██║  ██║     ╚████╔╝ ██║     ███████║   ║
    ║    ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚══════╝   ║
    ║                                                               ║
    ║               D E F E N S E   S Y S T E M                     ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "                    ${DIM}Version ${SCRIPT_VERSION}${NC}"
    echo ""
}

# =============================================================================
# CONTEXT DETECTION
# =============================================================================

detect_context() {
    # Identify the real human user running the script (even behind sudo)
    if [ -n "${SUDO_USER:-}" ]; then
        CURRENT_REAL_USER="$SUDO_USER"
    else
        CURRENT_REAL_USER=$(whoami)
    fi
    log_info "Real user detected: ${BOLD}$CURRENT_REAL_USER${NC}"
}

# =============================================================================
# SYSTEM CHECKS
# =============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo ""
        log_error "This script must be run as ${BOLD}root${NC}"
        echo ""
        echo -e "  ${CYAN}Correct usage:${NC}"
        echo -e "    ${YELLOW}sudo ./deploy.sh${NC}"
        echo ""
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        if [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
            log_info "Operating system: ${BOLD}$OS $VER${NC}"
        else
            log_error "Unsupported operating system: ${BOLD}$OS${NC}"
            echo ""
            echo -e "  ${CYAN}Supported systems:${NC}"
            echo -e "    • Debian 12 / 13"
            echo -e "    • Ubuntu 22.04 / 24.04"
            echo ""
            exit 1
        fi
    else
        log_error "Cannot detect the operating system (/etc/os-release does not exist)"
        exit 1
    fi
}

# =============================================================================
# APT PACKAGE MANAGEMENT
# =============================================================================

wait_for_apt_locks() {
    log_info "Checking that the package manager is available..."
    
    local elapsed=0
    local spinner='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local spin_i=0
    local showed_msg=false
    
    # Check only the lock files (what actually blocks apt)
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
       || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
       || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
       || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        
        if [ "$showed_msg" = false ]; then
            log_info "The system is running automatic updates..."
            echo -e "  ${DIM}Waiting for them to finish (this can take several minutes)...${NC}"
            showed_msg=true
        fi
        
        local mins=$((elapsed / 60))
        local secs=$((elapsed % 60))
        printf "\r  ${CYAN}%s${NC} Waiting for locks... [%d:%02d]" "${spinner:spin_i%10:1}" "$mins" "$secs"
        spin_i=$((spin_i + 1))
        sleep 3
        elapsed=$((elapsed + 3))
    done
    
    # Success message if there was a wait
    if [ "$showed_msg" = true ]; then
        echo ""
        log_success "Package manager available"
    fi
    
    # Configure needrestart so it does not ask
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i "s/^#\$nrconf{restart} = .*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf 2>/dev/null || true
    fi
}

# =============================================================================
# DEPENDENCY INSTALLATION
# =============================================================================

install_dependencies() {
    wait_for_apt_locks
    
    log_step "Installing system dependencies"
    
    if ! run_quiet "Updating repositories" apt-get update -y; then
        log_warn "apt-get update failed, possibly an active lock. Waiting and retrying..."
        wait_for_apt_locks
        run_quiet "Updating repositories (retry)" apt-get update -y
    fi

    # Install with retry and verification
    if ! run_quiet "Installing base packages (psmisc, curl, git, ufw, fail2ban, rsyslog, lvm2, xz-utils, cron, rsync)" apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" psmisc curl git ufw fail2ban rsyslog lvm2 xz-utils cron rsync; then
        log_warn "Installation failed. Waiting and retrying..."
        wait_for_apt_locks
        run_quiet "Installing base packages (retry)" apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" psmisc curl git ufw fail2ban rsyslog lvm2 xz-utils cron rsync
    fi

    # Critical check: Fail2Ban must be present
    if ! command -v fail2ban-client &> /dev/null; then
        log_error "CRITICAL: Fail2Ban was not installed correctly"
        echo ""
        echo -e "  ${CYAN}Try installing it manually:${NC}"
        echo -e "    ${YELLOW}apt-get install -y fail2ban${NC}"
        echo ""
        exit 1
    fi

    # Make sure rsyslog is running so /var/log/auth.log is written
    if systemctl list-unit-files | grep -q rsyslog.service; then
        systemctl enable --now rsyslog >/dev/null 2>&1 || log_warn "Could not start rsyslog automatically"
    fi

    # Install Docker if it is not present
    if ! command -v docker &> /dev/null; then
        log_step "Installing Docker (this can take a few minutes)"
        run_quiet "Downloading and installing Docker" bash -c 'curl -fsSL https://get.docker.com | sh'
        log_success "Docker installed"
    else
        log_info "Docker is already installed"
    fi
}

ensure_lvm_tools() {
    # Load the dm-mod module for device-mapper (required by LVM)
    modprobe dm-mod 2>/dev/null || true
    
    if command -v pvcreate >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing lvm2 to manage backups..."
    wait_for_apt_locks
    run_quiet "Installing lvm2" apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" lvm2
    
    # Reload the module after installing
    modprobe dm-mod 2>/dev/null || true
}

# =============================================================================
# CREDENTIAL ENCRYPTION
# =============================================================================

encrypt_credentials_file() {
    local cred_file="$1"

    if [ ! -f "$cred_file" ]; then
        log_warn "Credentials file not found: ${BOLD}$cred_file${NC}"
        return 1
    fi

    echo ""
    echo -e "${CYAN}[ENCRYPTION] Credential encryption${NC}"
    echo -e "${DIM}Select an SSH public key to encrypt the credentials.${NC}"
    echo -e "${DIM}Only the matching private key will be able to decrypt them.${NC}"
    echo ""
    
    local selected_key=""
    selected_key=$(choose_public_key_for_user "$SECURE_ADMIN" "credential encryption") || selected_key=""

    if [ -z "$selected_key" ]; then
        log_warn "No SSH key was selected for encryption"
        log_info "The credentials will be shown at the end and then deleted"
        return 1
    fi

    if ! install_age_if_missing; then
        log_warn "The 'age' tool is not available"
        log_info "The credentials will be shown at the end and then deleted"
        return 1
    fi

    if age -r "$selected_key" -o "${cred_file}.age" "$cred_file"; then
        chmod 600 "${cred_file}.age"
        chown "$SECURE_ADMIN:$SECURE_ADMIN" "${cred_file}.age"
        shred -u "$cred_file"
        log_success "Credentials encrypted to ${BOLD}${cred_file}.age${NC}"
        log_info "Plain-text file securely deleted"
        return 0
    else
        log_warn "Encryption with age failed"
        return 1
    fi
}

# =============================================================================
# FIREWALL CONFIGURATION (UFW)
# =============================================================================

setup_firewall() {
    log_step "Configuring the firewall (UFW)"
    
    ufw default deny incoming
    ufw default allow outgoing
    
    # Port 22: the Cowrie honeypot is ALWAYS on port 22 (to capture as many attacks as possible)
    # The real SSH goes on an alternative port (default: 2929)
    ufw allow 22/tcp comment 'Cowrie Honeypot'
    
    # Enable UFW non-interactively and verify
    ufw --force enable
    if ufw status | grep -q "Status: active"; then
        log_success "Firewall configured and active"
        echo -e "  ${DIM}Policy: DENY incoming / ALLOW outgoing${NC}"
        echo -e "  ${DIM}Open port: 22/tcp (Cowrie honeypot)${NC}"
        echo -e "  ${DIM}Note: the real SSH port is opened in the next step${NC}"
    else
        log_warn "UFW is not active; check the configuration"
    fi
}

# =============================================================================
# REAL SSH SERVER (admin only, public key only)
# =============================================================================

# Port 22 belongs to the Cowrie honeypot. This is the real OpenSSH server:
# only the admin may log in, and only with a public key.

# Post-quantum hybrid key exchange first, using only what this OpenSSH supports
# (mlkem768x25519 needs OpenSSH 9.9+, sntrup761x25519 needs 8.5+).
select_kex_algorithms() {
    local supported algo list=""
    supported=$(ssh -Q kex 2>/dev/null || true)
    for algo in mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
                curve25519-sha256 curve25519-sha256@libssh.org; do
        if grep -qxF "$algo" <<<"$supported"; then
            list="${list:+$list,}$algo"
        fi
    done
    echo "${list:-curve25519-sha256,curve25519-sha256@libssh.org}"
}

render_sshd_config() {
    local admin="$1"
    local port="$2"
    local kex="$3"
    cat <<EOF
# ==============================================================================
# ASIR VPS Defense - real SSH server (generated by deploy.sh on $(date))
# Port 22 is the Cowrie honeypot; this server listens on port $port.
# Only '$admin' may log in, and only with a public key.
# Drop-ins in /etc/ssh/sshd_config.d/ are intentionally not included, so a
# cloud-init file cannot turn password logins back on.
# ==============================================================================
Port $port
AllowUsers $admin
PermitRootLogin no

PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes

# Only local forwards (ssh -L), which the panel tunnel needs
AllowTcpForwarding local
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no

MaxAuthTries 1
MaxSessions 4
MaxStartups 5:30:10
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

KexAlgorithms $kex
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

LogLevel VERBOSE
UseDNS no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
}

configure_ssh() {
    local REAL_USER=$1
    local SSH_PORT=${2:-22}

    log_step "Configuring the real SSH server (admin only, public key only)"

    # Never lock the admin out: a public key must be in place before passwords go away
    if [ ! -s "/home/$REAL_USER/.ssh/authorized_keys" ]; then
        log_error "No public key found in /home/$REAL_USER/.ssh/authorized_keys; SSH was left untouched"
        exit 1
    fi

    local kex candidate
    kex=$(select_kex_algorithms)
    candidate=$(mktemp /etc/ssh/sshd_config.asir.XXXXXX)
    render_sshd_config "$REAL_USER" "$SSH_PORT" "$kex" > "$candidate"
    chmod 644 "$candidate"

    # Validate before touching the live file: a broken sshd_config means losing remote access
    if ! sshd -t -f "$candidate"; then
        rm -f "$candidate"
        log_error "The generated sshd_config failed validation; the current SSH configuration was left untouched"
        exit 1
    fi

    # Keep the distribution's original file once, so re-runs never overwrite it
    if [ ! -f /etc/ssh/sshd_config.asir-original ]; then
        cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.asir-original
        log_info "Original sshd_config saved as /etc/ssh/sshd_config.asir-original"
    fi
    mv -f "$candidate" /etc/ssh/sshd_config

    # Ubuntu 22.10+ starts sshd through ssh.socket, which ignores Port: use the classic service
    if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        systemctl disable --now ssh.socket
        systemctl enable ssh.service
        log_info "ssh.socket disabled; sshd now runs as ssh.service"
    fi
    systemctl restart ssh
    systemctl is-active --quiet ssh

    log_success "Real SSH listening on port $SSH_PORT (public key only)"
    echo -e "  ${DIM}Allowed user: ${BOLD}$REAL_USER${NC}${DIM} · key exchange: ${kex%%,*} first${NC}"
    echo -e "  ${YELLOW}Only $REAL_USER can log in over SSH from now on.${NC}"
    echo -e "  ${YELLOW}Before closing this session, open a NEW terminal and test:${NC} ssh -p $SSH_PORT $REAL_USER@<server-ip>"
}

# =============================================================================
# FAIL2BAN
# =============================================================================

configure_fail2ban() {
    local SSH_PORT="${1:-22}"
    log_step "Configuring Fail2Ban"

    systemctl stop fail2ban 2>/dev/null || true

    # rsyslog keeps writing auth.log for Promtail and the panel
    if [ ! -f /var/log/auth.log ]; then
        touch /var/log/auth.log
        chown syslog:adm /var/log/auth.log 2>/dev/null || true
        chmod 640 /var/log/auth.log
    fi

    # Cowrie's log lives on the host (bind-mounted into the container)
    mkdir -p /var/log/cowrie
    touch /var/log/cowrie/cowrie.log
    chmod 644 /var/log/cowrie/cowrie.log

    touch /var/log/fail2ban.log
    chmod 644 /var/log/fail2ban.log

    # Cowrie filter: from the repository, or the same definition inline
    if [ -f "$SCRIPT_DIR/fail2ban/filter.d/cowrie.conf" ]; then
        cp "$SCRIPT_DIR/fail2ban/filter.d/cowrie.conf" /etc/fail2ban/filter.d/cowrie.conf
    else
        log_warn "cowrie.conf not found in $SCRIPT_DIR/fail2ban/filter.d/; writing it inline"
        cat > /etc/fail2ban/filter.d/cowrie.conf <<'COWRIE_FILTER'
[Definition]
failregex = ^.*New connection: <HOST>:\d+ .*$
ignoreregex =
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S(?:\.%%f)?%%z
COWRIE_FILTER
    fi
    chmod 644 /etc/fail2ban/filter.d/cowrie.conf

    cat > /etc/fail2ban/jail.local <<EOF
# ==============================================================================
# ASIR VPS Defense - Fail2Ban jails (generated by deploy.sh on $(date))
# ==============================================================================

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
findtime = 10m

# Real SSH (port $SSH_PORT). It only accepts the admin's public key, so every
# attempt by anyone else logs one "Invalid user" or "not allowed" line.
# Two attempts in 10 minutes: banned from that port for 35 days.
# The admin's own failed keys do not count ("normal" mode).
[sshd]
enabled  = true
mode     = normal
port     = $SSH_PORT
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 2
bantime  = 35d

# Honeypot (port 22). Whoever connects to Cowrie 5 times in 10 minutes is a
# known attacker: they are blocked from the real host (real SSH and every other
# host service) for 7 days, but NOT from Cowrie, so they keep feeding the
# honeypot. Docker forwards port 22 to the container through the FORWARD path,
# which a host-level (input) ban does not touch.
[cowrie]
enabled   = true
filter    = cowrie
logpath   = /var/log/cowrie/cowrie.log
banaction = %(banaction_allports)s
maxretry  = 5
bantime   = 7d
EOF

    if ! fail2ban-client -t >/dev/null 2>&1; then
        fail2ban-client -t || true
        log_error "Fail2Ban configuration test failed"
        exit 1
    fi
    systemctl restart fail2ban
    systemctl is-active --quiet fail2ban
    systemctl enable fail2ban

    log_success "Fail2Ban configured"
    echo -e "  ${DIM}Real SSH (port $SSH_PORT): 35-day ban after 2 failed attempts in 10 min${NC}"
    echo -e "  ${DIM}Honeypot: 7-day ban from the real host after 5 connections in 10 min (Cowrie stays reachable)${NC}"
}

# =============================================================================
# SECURE ADMIN CREATION
# =============================================================================

create_secure_admin() {
    log_step "Creating the secure admin"

    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}[ADMIN] REAL ADMIN SETUP (you)${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    echo -n -e "  ${CYAN}Admin username (e.g. sys_ops):${NC} "
    read -r SECURE_ADMIN < /dev/tty

    if [ -z "$SECURE_ADMIN" ]; then
        log_error "The username cannot be empty"
        exit 1
    fi

    if id "$SECURE_ADMIN" &>/dev/null; then
        log_warn "User ${BOLD}$SECURE_ADMIN${NC} already exists. It will be reused."
    else
        useradd -m -s /bin/bash "$SECURE_ADMIN"
        usermod -aG sudo,docker "$SECURE_ADMIN"
        log_success "User ${BOLD}$SECURE_ADMIN${NC} created"
    fi

    # Set a password for sudo
    echo ""
    echo -e "  ${CYAN}[SUDO] Password for SUDO${NC}"
    echo -e "  ${DIM}SSH access uses a key, but you still need a password to elevate privileges.${NC}"
    echo ""
    
    while true; do
        echo -n -e "  ${CYAN}Sudo password:${NC} "
        read -r -s ADMIN_PASS < /dev/tty
        echo ""
        echo -n -e "  ${CYAN}Confirm password:${NC} "
        read -r -s ADMIN_PASS_CONFIRM < /dev/tty
        echo ""
        
        if [ -n "$ADMIN_PASS" ] && [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]; then
            echo "$SECURE_ADMIN:$ADMIN_PASS" | chpasswd
            log_success "Password set for ${BOLD}$SECURE_ADMIN${NC}"
            break
        else
            log_error "The passwords do not match or are empty"
            echo ""
        fi
    done

    # Set up the SSH key for the real admin (required)
    echo ""
    echo -e "  ${CYAN}[SSH] Admin SSH key (required)${NC}"
    echo -e "  ${DIM}Your account will only be able to log in with an SSH public key.${NC}"
    echo ""
    
    local SSH_KEY=""
    while true; do
        echo -e "  ${GREEN}[1]${NC} Detect existing keys and choose one"
        echo -e "  ${GREEN}[2]${NC} Enter a public key manually"
        echo ""
        echo -n -e "  ${CYAN}Option:${NC} "
        read -r key_opt < /dev/tty

        if [ "$key_opt" = "1" ]; then
            SSH_KEY=$(choose_public_key_for_user "$SECURE_ADMIN" "SSH access") || SSH_KEY=""
            if [ -n "$SSH_KEY" ]; then
                log_info "Key selected from the detected keys"
                break
            else
                log_warn "No keys were detected. Use option 2."
            fi
        elif [ "$key_opt" = "2" ]; then
            echo ""
            echo -n -e "  ${CYAN}Paste your public key (ssh-ed25519/ssh-rsa):${NC} "
            read -r manual_key < /dev/tty
            if [[ "$manual_key" =~ $SSH_PUBKEY_REGEX ]] && ssh-keygen -lf /dev/stdin <<<"$manual_key" >/dev/null 2>&1; then
                SSH_KEY="$manual_key"
                break
            else
                log_warn "Invalid key. Paste the full public key line (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256...)"
            fi
        else
            log_warn "Invalid option. Choose 1 or 2."
        fi
    done

    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    if grep -qF "$SSH_KEY" "/home/$SECURE_ADMIN/.ssh/authorized_keys" 2>/dev/null; then
        log_info "The SSH key was already authorized"
    else
        echo "$SSH_KEY" >> "/home/$SECURE_ADMIN/.ssh/authorized_keys"
        log_success "SSH key added"
    fi

    # Make sure the permissions are correct (critical step)
    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    chmod 700 "/home/$SECURE_ADMIN/.ssh"
    if [ -f "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        chmod 600 "/home/$SECURE_ADMIN/.ssh/authorized_keys"
    fi
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "/home/$SECURE_ADMIN/.ssh"
    
    log_success "SSH configuration verified for ${BOLD}$SECURE_ADMIN${NC}"

    echo "$SECURE_ADMIN" > "$STATE_DIR/secure_admin"
}

# =============================================================================
# .ENV FILE GENERATION
# =============================================================================

generate_env() {
    log_step "Generating secrets and configuration (.env)"
    
    echo ""
    echo -n -e "  ${CYAN}VPS domain (or public IP if you have no domain):${NC} "
    read -r DOMAIN_NAME < /dev/tty

    if [ -z "${DOMAIN_NAME}" ]; then
        log_error "The domain/IP cannot be empty"
        exit 1
    fi
    if echo "${DOMAIN_NAME}" | grep -q ' '; then
        log_error "The domain/IP must not contain spaces"
        exit 1
    fi
    
    # Generate random passwords
    MYSQL_ROOT_PASS=$(openssl rand -base64 24)
    MYSQL_APP_PASS=$(openssl rand -base64 24)
    
    # Create the Docker secrets (files with mode 600)
    create_docker_secrets "$PROJECT_DIR" "$MYSQL_ROOT_PASS" "$MYSQL_APP_PASS"
    
    cat > .env <<EOF
# ==============================================================================
# ASIR VPS Defense - Environment variables
# Generated on $(date)
# ==============================================================================

# Server domain/IP
DOMAIN_NAME=$DOMAIN_NAME

# MySQL (credentials managed by Docker secrets in ./secrets/)
MYSQL_DATABASE=asir_defense
MYSQL_USER=app_user

# Docker network configuration
FRONTEND_SUBNET=172.20.0.0/16
BACKEND_SUBNET=172.21.0.0/16

# GeoIP (optional)
GEOIP_LICENSE_KEY=
EOF

    chmod 600 .env
    log_success ".env file generated (credentials in Docker secrets)"
}

# =============================================================================
# REMOVING SENSITIVE CREDENTIALS FROM .env
# =============================================================================
# The MySQL credentials are only needed during the first
# `docker compose up`. Once MySQL starts, it stores them internally
# in its datadir. Keeping them in plain text is bad practice.
#
# This function:
#   1. Replaces MYSQL_ROOT_PASSWORD and MYSQL_PASSWORD with placeholders
#   2. Keeps the other variables needed for normal operation
#   3. The secrets are stored in separate files with mode 600
# =============================================================================

create_docker_secrets() {
    local project_dir="$1"
    local root_pass="$2"
    local app_pass="$3"
    
    log_step "Creating Docker secrets for the MySQL credentials"
    
    local secrets_dir="$project_dir/secrets"
    mkdir -p "$secrets_dir"
    
    # Create the secret files with restrictive permissions
    echo -n "$root_pass" > "$secrets_dir/mysql_root_password.txt"
    echo -n "$app_pass" > "$secrets_dir/mysql_app_password.txt"
    
    # Permissions: root for root_password, UID 10001 (the PHP container) for app_password
    chmod 600 "$secrets_dir/mysql_root_password.txt"
    chown root:root "$secrets_dir/mysql_root_password.txt"
    
    # PHP runs as UID 10001 and needs to read this file
    chmod 400 "$secrets_dir/mysql_app_password.txt"
    chown 10001:10001 "$secrets_dir/mysql_app_password.txt"
    
    chmod 755 "$secrets_dir"
    
    log_success "Docker secrets created in $secrets_dir"
    echo -e "  ${DIM}The passwords are read from /run/secrets/ inside the containers${NC}"
}


# =============================================================================
# GEOLITE2 DATABASE DOWNLOAD
# =============================================================================

download_geolite_mmdb() {
    # GeoLite2-City from a pinned release of the geolite2-city npm mirror (jsDelivr),
    # verified by checksum: nothing unpinned is downloaded into the server.
    local version="1.0.113"
    local sha256="daab81ed25857a4e8a342a35409015e918af46da15e569a128ac65e3f8c769ad"
    local url="https://cdn.jsdelivr.net/npm/geolite2-city@${version}/GeoLite2-City.mmdb.gz"
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p geoip

    log_step "Downloading the GeoLite2-City database"
    log_info "Source: geolite2-city@${version} on jsDelivr (no API key needed)"
    
    if ! curl -fsSL "$url" -o "$tmpdir/GeoLite2-City.mmdb.gz"; then
        log_warn "Could not download GeoLite2 from the CDN"
        log_info "Falling back to country-level data (reduced functionality)"
        rm -rf "$tmpdir"
        return 0
    fi

    if ! echo "$sha256  $tmpdir/GeoLite2-City.mmdb.gz" | sha256sum -c --status; then
        log_warn "GeoLite2 checksum mismatch; the file was discarded"
        log_info "Falling back to country-level data"
        rm -rf "$tmpdir"
        return 0
    fi

    if ! gunzip -c "$tmpdir/GeoLite2-City.mmdb.gz" > geoip/GeoLite2-City.mmdb; then
        log_warn "Could not decompress GeoLite2"
        log_info "Falling back to country-level data"
        rm -rf "$tmpdir"
        return 0
    fi

    chmod 644 geoip/GeoLite2-City.mmdb
    log_success "GeoLite2-City database downloaded: ${BOLD}geoip/GeoLite2-City.mmdb${NC}"
    rm -rf "$tmpdir"
}

# =============================================================================
# DATABASE SEED GENERATION
# =============================================================================

generate_db_seed() {
    log_step "Generating the admin panel credentials"
    
    WEB_ADMIN_PASS=$(openssl rand -base64 12)
    
    # Use a temporary PHP container to generate the bcrypt hash
    log_info "Computing a secure password hash (bcrypt)..."
    set +e
    WEB_ADMIN_HASH=$(printf '%s' "$WEB_ADMIN_PASS" | docker run --rm -i php:8.3-cli php -r 'echo password_hash(stream_get_contents(STDIN), PASSWORD_DEFAULT);' 2>>"$LOG_FILE")
    local hash_status=$?
    set -e
    if [ $hash_status -ne 0 ] || [ -z "$WEB_ADMIN_HASH" ]; then
        log_error "Could not generate the password hash"
        echo ""
        echo -e "  ${CYAN}Check the log for details:${NC}"
        echo -e "    ${YELLOW}tail -n 25 $LOG_FILE${NC}"
        echo ""
        tail -n 25 "$LOG_FILE" >&2
        exit 1
    fi
    
    cat > mysql/init/02-seed.sql <<EOF
-- ==============================================================================
-- ASIR VPS Defense - Seed file
-- Generated by deploy.sh on $(date)
-- ==============================================================================

INSERT INTO users (username, password_hash, role) VALUES 
('admin', '$WEB_ADMIN_HASH', 'admin');
EOF
    
    # Save the credentials to a protected file for the user
    local CRED_FILE="/home/$SECURE_ADMIN/admin_credentials.txt"
    
    cat > "$CRED_FILE" <<EOF
╔══════════════════════════════════════════════════════════════╗
║         ASIR VPS DEFENSE - ACCESS CREDENTIALS                ║
╚══════════════════════════════════════════════════════════════╝

Generated on: $(date)

┌──────────────────────────────────────────────────────────────┐
│ ADMIN PANEL                                                  │
├──────────────────────────────────────────────────────────────┤
│ URL:        http://localhost:8888 (SSH tunnel required)      │
│ Username:   admin                                            │
│ Password:   $WEB_ADMIN_PASS
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ DATABASE                                                     │
├──────────────────────────────────────────────────────────────┤
│ Root Password:     $MYSQL_ROOT_PASS
│ App User Password: $MYSQL_APP_PASS
└──────────────────────────────────────────────────────────────┘

NOTE: This file is owned by $SECURE_ADMIN (mode 600).
      Save these credentials and delete this file.
EOF
    
    # Lock down the file
    chown "$SECURE_ADMIN:$SECURE_ADMIN" "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    log_success "Database seed generated: ${BOLD}mysql/init/02-seed.sql${NC}"
    log_success "Credentials saved to: ${BOLD}$CRED_FILE${NC}"
    
    if encrypt_credentials_file "$CRED_FILE"; then
        log_info "Credentials encrypted. You can view or download them at the end."
    else
        log_warn "Credentials not encrypted; they will be shown at the end and then deleted"
    fi
}

# =============================================================================
# ROOT HARDENING
# =============================================================================

check_and_harden_root() {
    log_step "Checking the root security configuration"
    
    local root_issues=0
    local password_locked=false
    local ssh_denied=false
    
    # 1. Check whether the root password is locked
    local shadow_status
    shadow_status=$(grep "^root:" /etc/shadow 2>/dev/null | cut -d: -f2 | head -c1)
    if [[ "$shadow_status" == "!" ]] || [[ "$shadow_status" == "*" ]]; then
        password_locked=true
        log_success "Root password locked"
    else
        local passwd_status
        passwd_status=$(passwd -S root 2>/dev/null | awk '{print $2}')
        if [[ "$passwd_status" == "L" ]]; then
            password_locked=true
            log_success "Root password locked"
        else
            log_warn "Root password is NOT locked"
            root_issues=$((root_issues + 1))
        fi
    fi
    
    # 2. Check PermitRootLogin in SSH
    local permit_root
    permit_root=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
    if [[ "$permit_root" == "no" ]]; then
        ssh_denied=true
        log_success "SSH denies root login (PermitRootLogin no)"
    elif [[ -z "$permit_root" ]]; then
        # If it is not set, the default on many systems is "prohibit-password"
        log_info "PermitRootLogin not set explicitly (using the system default)"
    else
        log_warn "SSH allows root login (PermitRootLogin $permit_root)"
        root_issues=$((root_issues + 1))
    fi
    
    # 3. If there are problems, offer hardening
    if [ $root_issues -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}╭─────────────────────────────────────────────────────────────╮${NC}"
        echo -e "${YELLOW}│${NC}  ${BOLD}[!] ROOT CONFIGURATION CAN BE IMPROVED${NC}                     ${YELLOW}│${NC}"
        echo -e "${YELLOW}╰─────────────────────────────────────────────────────────────╯${NC}"
        echo ""
        echo -e "  ${CYAN}Recommended:${NC}"
        if [ "$password_locked" = false ]; then
            echo -e "    • Lock the root password (nobody can log in as root directly)"
        fi
        if [ "$ssh_denied" = false ]; then
            echo -e "    • Deny root login over SSH (PermitRootLogin no)"
        fi
        echo ""
        echo -e "  ${DIM}This does NOT affect sudo: you can still use 'sudo -i'${NC}"
        echo ""
        echo -n -e "  ${CYAN}Apply root hardening? (Y/n):${NC} "
        read -r CONFIRM_ROOT_HARDENING < /dev/tty
        
        if [[ "$CONFIRM_ROOT_HARDENING" =~ ^[Yy]$ ]] || [[ -z "$CONFIRM_ROOT_HARDENING" ]]; then
            # Lock the root password
            if [ "$password_locked" = false ]; then
                passwd -l root >/dev/null 2>&1
                log_success "Root password locked"
            fi
            
            # Deny root over SSH
            if [ "$ssh_denied" = false ]; then
                if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
                    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
                else
                    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
                fi
                systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
                log_success "SSH configured to deny root"
            fi
            
            log_success "Root hardening complete"
        else
            log_info "Root hardening skipped (you can do it manually later)"
        fi
    else
        log_success "Root configuration is secure"
    fi
}

# =============================================================================
# VOLUME AND BACKUP CONFIGURATION
# =============================================================================

ensure_backup_volume() {
    log_step "Preparing the logical volume for backups"

    ensure_lvm_tools || {
        log_error "Could not install lvm2; backups cannot be prepared"
        return 1
    }

    local root_dev
    root_dev=$(lsblk -nlso NAME,TYPE "$(findmnt -n -o SOURCE /)" 2>/dev/null | awk '$2 == "disk" {print "/dev/" $1; exit}' || true)

    if mountpoint -q "$BACKUP_MOUNTPOINT"; then
        log_info "Backup volume already mounted at ${BOLD}$BACKUP_MOUNTPOINT${NC}"
        return 0
    fi

    mkdir -p "$BACKUP_MOUNTPOINT"

    if vgdisplay "$BACKUP_VG_NAME" >/dev/null 2>&1; then
        log_info "Existing VG detected: ${BOLD}$BACKUP_VG_NAME${NC}"
        if ! lvdisplay "$BACKUP_VG_NAME/$BACKUP_LV_NAME" >/dev/null 2>&1; then
            log_warn "LV $BACKUP_LV_NAME does not exist in VG $BACKUP_VG_NAME, creating the LV..."
            if ! lvcreate -n "$BACKUP_LV_NAME" -l 100%FREE "$BACKUP_VG_NAME" >/dev/null 2>&1; then
                log_error "Could not create LV $BACKUP_LV_NAME in $BACKUP_VG_NAME"
                return 1
            fi
        fi
    else
        local chosen_device="${BACKUP_DEVICE:-}"
        local candidates=()

        echo ""
        echo -e "${CYAN}Detected devices (lsblk):${NC}"
        lsblk -e7 -o NAME,TYPE,SIZE,MOUNTPOINT | sed 's/^/  /'
        echo ""

        # Detect disks with no mounts and no mounted partitions (avoids the system disk)
        while IFS= read -r disk; do
            # Skip the disk if it or any of its children has a mountpoint
            if lsblk -nr -o MOUNTPOINT "$disk" | grep -q '\S'; then
                continue
            fi
            # Skip the disk that holds / (root)
            if [ -n "$root_dev" ] && [ "$disk" = "$root_dev" ]; then
                continue
            fi
            candidates+=("$disk")
        done < <(lsblk -dpno NAME,TYPE | awk '$2=="disk" {print $1}')

        if [ -z "$chosen_device" ]; then
            if [ ${#candidates[@]} -eq 1 ]; then
                chosen_device="${candidates[0]}"
                log_info "Free disk detected: ${BOLD}$chosen_device${NC}"
            elif [ ${#candidates[@]} -gt 1 ]; then
                echo ""
                echo -e "${CYAN}Disks available for backups:${NC}"
                local idx=1
                for d in "${candidates[@]}"; do
                    echo -e "  ${GREEN}[$idx]${NC} $d"
                    idx=$((idx+1))
                done
                echo -e "${YELLOW}Choose a number or type a device path (e.g. /dev/sdb):${NC} "
                read -r selection < /dev/tty
                if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le ${#candidates[@]} ]; then
                    chosen_device="${candidates[$((selection-1))]}"
                else
                    chosen_device="$selection"
                fi
            else
                echo ""
                echo -e "${YELLOW}No dedicated free disks were found.${NC}"
                echo -e "${CYAN}Safe default:${NC} create a loop file at ${BOLD}$BACKUP_LOOP_FILE${NC}${CYAN} (does not protect against disk failure).${NC}"
                echo -n -e "Create the loop now? (Y/n): "
                read -r CONF_LOOP < /dev/tty
                if [[ ! "$CONF_LOOP" =~ ^[Nn]$ ]]; then
                    echo -n -e "Loop size in GB (ENTER=${BACKUP_LOOP_DEFAULT_SIZE}): "
                    read -r LOOP_SIZE < /dev/tty
                    [ -z "$LOOP_SIZE" ] && LOOP_SIZE="$BACKUP_LOOP_DEFAULT_SIZE"
                    if create_loop_backing "$LOOP_SIZE"; then
                        chosen_device="$BACKUP_LOOP_DEVICE"
                        log_info "Using loop device ${BOLD}$chosen_device${NC} (${LOOP_SIZE})"
                    else
                        log_warn "Could not create the loop; no backups"
                        return 1
                    fi
                fi
            fi
        fi

        if [ -z "$chosen_device" ]; then
            log_warn "Skipping backup preparation (no VG available)"
            return 1
        fi
        if ! lsblk -ndo NAME "$chosen_device" >/dev/null 2>&1; then
            log_error "Invalid device: $chosen_device"
            return 1
        fi
        # Protect the system disk/partition
        if [ -n "$root_dev" ]; then
            if [ "$chosen_device" = "$root_dev" ]; then
                log_error "You cannot use the disk that holds / ($root_dev) for backups"
                return 1
            fi
            # If a partition was chosen, check its parent disk
            local parent
            parent=$(lsblk -no PKNAME "$chosen_device" 2>/dev/null || true)
            if [ -n "$parent" ] && [ "/dev/$parent" = "$root_dev" ]; then
                log_error "The selected device belongs to the system disk (/dev/$parent). Use a dedicated disk."
                return 1
            fi
        fi
        echo -n -e "${CYAN}PV+VG+LV will be created on ${BOLD}$chosen_device${NC}${CYAN}. Confirm? (type YES in capitals): ${NC}"
        read -r CONFIRM_BACKUP_LVM < /dev/tty
        if [ "$CONFIRM_BACKUP_LVM" != "YES" ]; then
            log_warn "Operation cancelled by the user"
            return 1
        fi
        
        # Wipe old signatures and wait for the device to be ready
        wipefs -a "$chosen_device" >/dev/null 2>&1 || true
        sleep 1
        
        if ! pvcreate -f "$chosen_device" >/dev/null 2>&1; then
            log_error "pvcreate failed on $chosen_device"
            return 1
        fi
        if ! vgcreate "$BACKUP_VG_NAME" "$chosen_device" >/dev/null 2>&1; then
            log_error "vgcreate failed for $BACKUP_VG_NAME"
            return 1
        fi
        if ! lvcreate -n "$BACKUP_LV_NAME" -l 100%FREE "$BACKUP_VG_NAME" >/dev/null 2>&1; then
            log_error "lvcreate failed for $BACKUP_LV_NAME"
            return 1
        fi
    fi

    local lv_path="/dev/$BACKUP_VG_NAME/$BACKUP_LV_NAME"
    local fs_type
    fs_type=$(blkid -o value -s TYPE "$lv_path" 2>/dev/null || true)
    if [ -z "$fs_type" ]; then
        log_info "Creating an ext4 file system on $lv_path"
        mkfs.ext4 -L backups "$lv_path" >/dev/null
    fi

    local uuid
    uuid=$(blkid -o value -s UUID "$lv_path")
    if ! grep -q "$BACKUP_MOUNTPOINT" /etc/fstab; then
        echo "UUID=$uuid $BACKUP_MOUNTPOINT ext4 defaults,nofail 0 2" >> /etc/fstab
        if command -v systemctl >/dev/null 2>&1; then
            log_info "Reloading systemd after updating fstab"
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    fi

    if mount "$BACKUP_MOUNTPOINT"; then
        log_success "Backup volume mounted at ${BOLD}$BACKUP_MOUNTPOINT${NC}"
        chmod 750 "$BACKUP_MOUNTPOINT"
        mark_step_done "backups_prepared"
    else
        log_error "Could not mount $BACKUP_MOUNTPOINT"
        return 1
    fi
}

create_loop_backing() {
    local size="$1"
    local dir
    dir=$(dirname "$BACKUP_LOOP_FILE")
    mkdir -p "$dir"
    
    # If the user typed only a number, assume GB
    if [[ "$size" =~ ^[0-9]+$ ]]; then
        size="${size}G"
        log_info "Interpreted as ${size}"
    fi
    
    # Make sure the loop module is loaded
    modprobe loop 2>/dev/null || true
    
    # Create a sparse file
    if ! fallocate -l "$size" "$BACKUP_LOOP_FILE" 2>/dev/null && ! truncate -s "$size" "$BACKUP_LOOP_FILE" 2>/dev/null; then
        log_error "Could not create the file $BACKUP_LOOP_FILE (size: $size)"
        return 1
    fi
    # Attach it to a free loop device
    BACKUP_LOOP_DEVICE=$(losetup -f --show "$BACKUP_LOOP_FILE")
    if [ -z "$BACKUP_LOOP_DEVICE" ]; then
        log_error "Could not assign a loop device"
        return 1
    fi
    
    # Wait for the device to become available
    sleep 1
    
    log_info "Loop created: $BACKUP_LOOP_DEVICE (${BACKUP_LOOP_FILE})"
    return 0
}

ensure_backups_script() {
    local dir="$1"
    local owner="${2:-}"
    local path="$dir/backups.sh"
    # backups.sh ships with the project; nothing is downloaded to be run as root
    if [ ! -f "$path" ] && [ -f "$SCRIPT_DIR/backups.sh" ]; then
        cp "$SCRIPT_DIR/backups.sh" "$path"
    fi
    if [ ! -f "$path" ]; then
        log_warn "backups.sh is not in $dir; backups will have to be managed by hand"
        return 0
    fi
    chmod 750 "$path"
    if [ -n "$owner" ]; then
        chown "$owner:$owner" "$path" 2>/dev/null || true
    fi
}

prompt_initial_backup() {
    local project_dir="$1"
    if [ ! -d "$project_dir" ]; then
        log_warn "Project directory not found for the initial backup"
        return
    fi
    if [ ! -x "$project_dir/backups.sh" ]; then
        log_warn "$project_dir/backups.sh not found; skipping the initial backup"
        return
    fi
    if ! mountpoint -q "$BACKUP_MOUNTPOINT"; then
        log_warn "Backups not configured (volume not mounted)"
        return
    fi
    echo ""
    echo -n -e "${CYAN}Create an initial backup now? (Y/n): ${NC}"
    read -r CREATE_BACKUP_NOW < /dev/tty
    if [[ "$CREATE_BACKUP_NOW" =~ ^[Nn]$ ]]; then
        log_info "Initial backup skipped by the user"
        return
    fi
    if BACKUP_ROOT="$BACKUP_MOUNTPOINT" BACKUP_RETENTION="$BACKUP_RETENTION_DEFAULT" "$project_dir/backups.sh" create --retention "$BACKUP_RETENTION_DEFAULT"; then
        log_success "Initial backup created in $BACKUP_MOUNTPOINT"
    else
        log_warn "Initial backup failed; check the log"
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main() {
    clear
    print_banner
    print_section "INSTALLER v${SCRIPT_VERSION}"
    
    check_root
    detect_context
    detect_os

    # Recover the secure admin user from previous runs (if any)
    if [ -z "$SECURE_ADMIN" ] && [ -f "$STATE_DIR/secure_admin" ]; then
        SECURE_ADMIN=$(cat "$STATE_DIR/secure_admin")
        log_info "Admin user recovered from a previous session: ${BOLD}$SECURE_ADMIN${NC}"
    fi

    # If everything is already done, still allow pending backups to be set up and the audit to run
    if is_step_done "prep_done" && is_step_done "users_done" && is_step_done "project_done" \
       && is_step_done "env_done" && is_step_done "seed_done" && is_step_done "final_done"; then
        local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
        if [ -d "$PROJECT_DIR" ]; then
            cd "$PROJECT_DIR" || exit 1
            ensure_backups_script "$PROJECT_DIR" "$SECURE_ADMIN"
            load_env_if_present
            print_section "PENDING BACKUPS"
            if ensure_backup_volume; then
                prompt_initial_backup "$PROJECT_DIR"
                mark_step_done "backups_prepared"
                mark_step_done "backups_done"
            else
                log_warn "Backups not configured (prepare a disk and run again)"
            fi
            print_section "PERMISSION AUDIT"
            log_info "Complete installation detected. Running the audit and finishing..."
            audit_permissions "$PROJECT_DIR" || log_warn "The permission audit found problems (see above)"
            exit 0
        fi
    fi
    
    # =========================================================================
    # STEP 1: System preparation
    # =========================================================================
    print_section "STEP 1/5: SYSTEM PREPARATION"
    if is_step_done "prep_done"; then
        log_info "Previous preparation detected"
        log_info "Skipping the reinstall of dependencies and firewall"
    else
        install_dependencies
        setup_firewall
        mark_step_done "prep_done"
    fi
    
    # =========================================================================
    # STEP 2: User and security configuration
    # =========================================================================
    print_section "STEP 2/5: USERS AND SECURITY"
    
    # Ask for the SSH port BEFORE configuring (if it is not configured yet)
    local SSH_PORT="22"
    if ! is_step_done "users_done"; then
        echo ""
        echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
        echo -e "${CYAN}│${NC}  ${BOLD}[SSH] REAL SSH PORT SETUP (admin)${NC}                          ${CYAN}│${NC}"
        echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
        echo ""
        echo -e "  ${RED}⚠  Port 22 is reserved for Cowrie (honeypot): do NOT use it here${NC}"
        echo ""
        echo -e "  Choose the port for your ${BOLD}real SSH${NC} (admin access):"
        echo -e "    • ${WHITE}2929${NC}        → Recommended: free of bots, admin access only"
        echo -e "    • ${WHITE}Other port${NC}  → Any free port between 1024 and 65535"
        echo -e "    • ${RED}NOT 22${NC}      → Taken by the Cowrie honeypot"
        echo ""
        echo -n -e "  ${CYAN}Real SSH port (ENTER for 2929):${NC} "
        read -r SSH_PORT < /dev/tty
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT="2929"
        fi
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
            log_warn "Invalid port. Using the default port 2929."
            SSH_PORT="2929"
        fi
        log_info "SSH port selected: ${BOLD}$SSH_PORT${NC}"
        
        # Open the real SSH port in UFW
        # Port 22 always stays open for Cowrie (honeypot)
        if [ "$SSH_PORT" != "22" ]; then
            ufw allow "$SSH_PORT"/tcp comment 'Real SSH (admin)' || log_warn "Could not open port $SSH_PORT in UFW"
            log_info "Port 22 kept open → Cowrie honeypot"
            log_info "Port $SSH_PORT open → real SSH (admin)"
        else
            log_warn "Real SSH on port 22 overlaps with Cowrie. An alternative port is recommended (e.g. 2929)"
        fi
    fi
    
    if is_step_done "users_done"; then
        log_info "Users and security already configured"
        if [ -z "$SECURE_ADMIN" ]; then
            log_error "Could not recover SECURE_ADMIN from the previous state"
            echo ""
            echo -e "  ${CYAN}To redo this step, delete the state file:${NC}"
            echo -e "    ${YELLOW}rm -f $STATE_DIR/users_done${NC}"
            echo ""
            exit 1
        fi
        # Recover the SSH port from the existing configuration
        SSH_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
    else
        create_secure_admin
        configure_ssh "$SECURE_ADMIN" "$SSH_PORT"
        configure_fail2ban "$SSH_PORT"
        mark_step_done "users_done"
    fi
    
    # =========================================================================
    # STEP 3: Project configuration
    # =========================================================================
    print_section "STEP 3/5: PROJECT PROVISIONING"
    local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
    log_info "Project directory: ${BOLD}$PROJECT_DIR${NC}"

    if is_step_done "project_done"; then
        log_info "Project already present"
        cd "$PROJECT_DIR" || exit 1
        ensure_backups_script "$PROJECT_DIR" "$SECURE_ADMIN"
    else
        # Create the directory if it does not exist
        if [ ! -d "$PROJECT_DIR" ]; then
            mkdir -p "$PROJECT_DIR"
        fi

        # Logic to populate the directory
        if [ -f "docker-compose.yml" ]; then
            log_info "Copying the local installation files..."
            rsync -av --exclude ".git" --exclude "asir-vps-defense" . "$PROJECT_DIR/" 2>/dev/null || cp -R . "$PROJECT_DIR/"
        else
            log_info "Downloading the official repository..."
            rm -rf "$PROJECT_DIR"
            git clone https://github.com/paulusgi/asir-vps-defense.git "$PROJECT_DIR"
        fi

        # Make sure the ownership is correct right away
        chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "$PROJECT_DIR"
        ensure_backups_script "$PROJECT_DIR" "$SECURE_ADMIN"
        cd "$PROJECT_DIR" || exit 1
        mark_step_done "project_done"
        log_success "Working directory: ${BOLD}$(pwd)${NC}"
    fi

    # =========================================================================
    # STEP 4: Application deployment
    # =========================================================================
    print_section "STEP 4/5: APPLICATION DEPLOYMENT"
    if is_step_done "env_done"; then
        log_info ".env file already exists"
        log_info "Not regenerated, to preserve the credentials"
        load_env_if_present
    else
        generate_env
        load_env_if_present
        mark_step_done "env_done"
    fi

    # Download GeoLite2-City from the CDN (no license key required)
    download_geolite_mmdb

    # Prepare the Cowrie log directory on the host
    # Cowrie (UID 999 in the official image) writes here
    # Promtail reads it as /var/log/host/cowrie/ (it already mounts /var/log:/var/log/host:ro)
    log_info "Preparing the Cowrie log directory on the host..."
    mkdir -p /var/log/cowrie
    chown -R 999:999 /var/log/cowrie
    chmod 755 /var/log/cowrie
    log_success "Directory /var/log/cowrie ready (UID 999, readable by Promtail)"

    if is_step_done "seed_done"; then
        log_info "Database seed already generated"
    else
        generate_db_seed
        mark_step_done "seed_done"
    fi
    
    # Fix permissions for the generated secrets
    chown "$SECURE_ADMIN:$SECURE_ADMIN" .env
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" mysql/init

    # Fix permissions for the webroot
    log_info "Adjusting web file permissions..."
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" src

    log_step "Deploying the Docker containers (this can take several minutes)"
    set +e
    run_quiet "Building and starting containers" docker compose up -d --build
    local up_status=$?
    set -e

    # Cowrie creates subdirectories on startup (cowrie.log, cowrie.json, tty/...)
    # The chown must be applied again after the up so they are writable
    chown -R 999:999 /var/log/cowrie 2>/dev/null || true

    # The tty/ directory inside the named volume is created owned by root.
    # Cowrie (UID 999) cannot create it, so it has to be created beforehand.
    local cowrie_vol
    cowrie_vol=$(docker volume inspect asir-vps-defense_cowrie_data --format '{{.Mountpoint}}' 2>/dev/null || true)
    if [ -n "$cowrie_vol" ]; then
        mkdir -p "$cowrie_vol/tty"
        chown -R 999:999 "$cowrie_vol"
        log_success "Cowrie volume tty/ directory ready (UID 999)"
    fi

    if [ $up_status -ne 0 ]; then
        log_error "docker compose up failed"
        echo ""
        echo -e "  ${CYAN}Showing diagnostic logs (MySQL):${NC}"
        docker compose logs --tail=60 mysql || true
        echo ""
        echo -e "  ${CYAN}If you see authentication/root password errors, run:${NC}"
        echo -e "    ${YELLOW}docker compose down -v${NC}"
        echo -e "    ${YELLOW}rm -f $STATE_DIR/env_done $STATE_DIR/seed_done${NC}"
        echo -e "    ${YELLOW}./deploy.sh${NC}"
        echo ""
        exit 1
    fi
    
    # =========================================================================
    # STEP 5: Backups and final actions
    # =========================================================================
    print_section "STEP 5/5: BACKUP CONFIGURATION"

    # Prepare the backup volume (but do NOT create a backup yet: that happens at the end)
    ensure_backup_volume || log_warn "Backups not configured (you can run ./deploy.sh after preparing the 'backups' VG)"
    
    # Check root and offer hardening
    check_and_harden_root
    
    if is_step_done "final_done"; then
        log_info "Final actions already applied"
    else
        mark_step_done "final_done"
    fi
    
    # =========================================================================
    # SUMMARY AND VERIFICATION
    # =========================================================================
    print_section "INSTALLATION FINISHED"
    
    echo ""
    echo -e "${YELLOW}Please review the messages above for errors (red text).${NC}"
    echo ""
    echo -n -e "Press ${BOLD}ENTER${NC} to continue with the status check..."
    read -r _ < /dev/tty
    
    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}[SERVICES] SERVICE STATUS${NC}                                  ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    
    # Make sure we are in the project directory
    local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
    cd "$PROJECT_DIR" || {
        log_error "Could not access the project directory: $PROJECT_DIR"
        exit 1
    }
    
    log_info "Waiting for the services to be ready (30-60s)..."
    
    # 1. Wait for the MySQL healthcheck
    local retries=0
    while [ $retries -lt 30 ]; do
        if [ "$(docker inspect -f '{{.State.Health.Status}}' asir_mysql 2>/dev/null)" = "healthy" ]; then
            break
        fi
        printf "\r  ${CYAN}⏳${NC} Waiting for healthchecks... [%02d/30]" "$retries"
        sleep 2
        retries=$((retries + 1))
    done
    echo ""

    # 2. Check the admin panel port (8888)
    log_info "Checking that the admin panel is available..."
    local port_ready=false
    retries=0
    while [ $retries -lt 20 ]; do
        if curl -s -I http://127.0.0.1:8888 >/dev/null; then
            port_ready=true
            log_success "Admin panel ${GREEN}ONLINE${NC} on port 8888"
            break
        fi
        printf "\r  ${CYAN}⏳${NC} Waiting for an HTTP response... [%02d/20]" "$retries"
        sleep 3
        retries=$((retries + 1))
    done
    echo ""

    if [ "$port_ready" = false ]; then
        log_error "The service on port 8888 is not responding"
        echo ""
        echo -e "  ${CYAN}The containers may still be starting.${NC}"
        echo -e "  ${CYAN}Check the logs with:${NC} ${YELLOW}docker compose logs -f${NC}"
        echo ""
    fi

    # 3. Check the Cowrie honeypot on port 22
    log_info "Checking the Cowrie honeypot on port 22..."
    sleep 3
    if ss -tlnp 2>/dev/null | grep -q ':22 ' || docker compose ps 2>/dev/null | grep -q 'asir_cowrie.*Up'; then
        log_success "Cowrie honeypot ${GREEN}ACTIVE${NC}: capturing attacks on port 22"
    else
        log_warn "Cowrie not detected on port 22 yet (it may still be starting)"
        echo -e "  ${DIM}Check with:${NC} ${YELLOW}docker compose ps cowrie${NC}"
        echo -e "  ${DIM}Logs:${NC} ${YELLOW}docker compose logs cowrie${NC}"
    fi

    echo ""
    echo -e "  ${DIM}Current container status:${NC}"
    docker compose ps 2>/dev/null || log_warn "Could not get the container status"
    
    # =========================================================================
    # CREDENTIAL MANAGEMENT
    # =========================================================================
    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}[CREDENTIALS] CREDENTIAL MANAGEMENT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    
    local CRED_PLAIN="/home/$SECURE_ADMIN/admin_credentials.txt"
    local CRED_ENC="${CRED_PLAIN}.age"
    local HOST_HINT="${DOMAIN_NAME:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

    if [ -f "$CRED_ENC" ]; then
        while true; do
            echo -e "  Encrypted file: ${BOLD}$CRED_ENC${NC}"
            echo ""
            echo -e "  ${GREEN}[1]${NC} Show the credentials on screen (temporary plain text)"
            echo -e "  ${GREEN}[2]${NC} Show the command to download the encrypted file"
            echo -e "  ${GREEN}[3]${NC} Continue without showing the credentials"
            echo ""
            echo -n -e "  ${CYAN}Option (1/2/3):${NC} "
            read -r CRED_CHOICE < /dev/tty

            case "$CRED_CHOICE" in
                1)
                    echo ""
                    echo -e "  ${YELLOW}Credentials (not saved to disk):${NC}"
                    echo -e "    • Web panel → username: ${GREEN}admin${NC} | password: ${GREEN}$WEB_ADMIN_PASS${NC}"
                    echo -e "    • DB root   → ${GREEN}$MYSQL_ROOT_PASS${NC}"
                    echo -e "    • DB app    → ${GREEN}$MYSQL_APP_PASS${NC}"
                    echo ""
                    ;;
                2)
                    echo ""
                    echo -e "  ${CYAN}Run this on your local machine to download it:${NC}"
                    echo ""
                    echo -e "    ${YELLOW}scp $SECURE_ADMIN@${HOST_HINT:-<domain_or_ip>}:$CRED_ENC ./admin_credentials.txt.age${NC}"
                    echo ""
                    echo -e "  ${CYAN}Then decrypt it with your private key:${NC}"
                    echo ""
                    echo -e "    ${YELLOW}age -d -i ~/.ssh/<your_key> -o admin_credentials.txt ./admin_credentials.txt.age${NC}"
                    echo ""
                    ;;
                3)
                    log_info "Continuing without showing the credentials"
                    break
                    ;;
                *)
                    log_warn "Invalid option. Choose 1, 2 or 3."
                    ;;
            esac
        done
    elif [ -f "$CRED_PLAIN" ]; then
        echo -e "${RED}[!] WARNING: unencrypted credentials${NC}"
        echo -e "  They will be shown ${BOLD}ONCE only${NC} and the file will be deleted."
        echo ""
        cat "$CRED_PLAIN"
        shred -u "$CRED_PLAIN"
        echo ""
        log_success "Credentials file securely deleted"
    else
        log_info "The credentials file is no longer present"
    fi

    unset WEB_ADMIN_PASS

    # =========================================================================
    # FINAL INSTRUCTIONS
    # =========================================================================
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}[OK] CONNECTION INSTRUCTIONS${NC}                                ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}1.${NC} Open a ${BOLD}NEW terminal${NC} on your local computer"
    echo ""
    echo -e "  ${CYAN}2.${NC} Run the following command to create the secure tunnel:"
    echo ""
    echo -e "     ${YELLOW}ssh -p $SSH_PORT -L 8888:127.0.0.1:8888 $SECURE_ADMIN@$DOMAIN_NAME${NC}"
    echo ""
    echo -e "  ${CYAN}3.${NC} Open your web browser and go to:"
    echo ""
    echo -e "     Admin panel: ${GREEN}http://localhost:8888${NC}"
    echo ""
    echo -e "  ${DIM}If you get 'Connection Refused', wait a few seconds for${NC}"
    echo -e "  ${DIM}the containers to finish starting.${NC}"
    echo ""

    echo -e "${DIM}Detailed log: ${LOG_FILE}${NC}"
    echo ""
    echo -n -e "Press ${BOLD}ENTER${NC} to delete the log and exit (type '${YELLOW}No${NC}' to keep it): "
    read -r CLEAN_LOG < /dev/tty
    if [[ "$CLEAN_LOG" =~ ^[Nn][Oo]$ ]]; then
        log_info "Log kept at $LOG_FILE"
    else
        rm -f "$LOG_FILE" && log_info "Log deleted"
    fi

    # =========================================================================
    # .env SANITIZATION AND INITIAL BACKUP
    # =========================================================================
    # Now that the credentials have been shown to the user, we can:
    # Create the initial backup (the secrets are in ./secrets/, not in .env)
    echo ""
    print_section "INITIAL BACKUP"
    
    # Create the initial backup if the volume is available
    prompt_initial_backup "$PROJECT_DIR"

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   [OK] INSTALLATION COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
