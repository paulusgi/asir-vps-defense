#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BACKUP_ROOT="${BACKUP_ROOT:-/srv/backups}"
BACKUP_LOOP_FILE="${BACKUP_LOOP_FILE:-/var/lib/asir-vps-defense/backups.img}"
BACKUP_VG="${BACKUP_VG:-backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"
LOG_FILE="${LOG_FILE:-/var/log/asir-vps-defense/backup.log}"
COMPOSE=(docker compose -f "$PROJECT_DIR/docker-compose.yml")
COPY_CMD=()
WARN_COPY=0
BACKUP_PROTECT_DEFAULT="${BACKUP_PROTECT_DEFAULT:-ask}"

# Style (ANSI with $'...' for printf compatibility)
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'
WHITE=$'\033[1;37m'

copy_tree() {
    local src="$1"
    local dst="$2"
    if [ ${#COPY_CMD[@]} -eq 0 ]; then
        if command -v rsync >/dev/null 2>&1; then
            COPY_CMD=(rsync -a)
        else
            COPY_CMD=(cp -a)
            if [ $WARN_COPY -eq 0 ]; then
                echo "rsync not available; using cp -a (may be slower)" >&2
                WARN_COPY=1
            fi
        fi
    fi
    "${COPY_CMD[@]}" "$src" "$dst"
}

ensure_dependencies() {
    local missing=()
    command -v rsync >/dev/null 2>&1 || missing+=(rsync)

    if [ ${#missing[@]} -eq 0 ]; then
        echo "Dependencies OK"
        return
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Missing dependencies and apt-get is not available: ${missing[*]}" >&2
        return
    fi

    echo "Installing dependencies: ${missing[*]}" >&2
    apt-get update -y >/dev/null 2>&1 || true
    if apt-get install -y "${missing[@]}" >/dev/null 2>&1; then
        echo "Dependencies installed: ${missing[*]}"
    else
        echo "Could not install: ${missing[*]}" >&2
    fi
}

detect_ssh_port() {
    local port
    port=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}')
    [ -n "$port" ] || port=22
    echo "$port"
}

detect_host_ip() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$ip" ]; then
        ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}')
    fi
    echo "$ip"
}

pause() {
    echo ""
    echo -n "  ${DIM}[Press ENTER to continue]${NC} "
    read -r _
}

render_header() {
    clear
    echo ""
    echo "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo "${CYAN}║${NC}           ${BOLD}${WHITE}🗄️  BACKUP MANAGER${NC}                        ${CYAN}║${NC}"
    echo "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    local mount_icon mount_state mount_color
    local usage="unknown"
    if mountpoint -q "$BACKUP_ROOT"; then
        mount_icon="●"
        mount_state="MOUNTED"
        mount_color="$GREEN"
        usage=$(df -h "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4" free / "$2" total"}')
    else
        mount_icon="○"
        mount_state="NOT MOUNTED"
        mount_color="$RED"
    fi

    local total protected last_entry last_name last_date
    total=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" 2>/dev/null | wc -l || echo 0)
    protected=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz.keep" 2>/dev/null | wc -l || echo 0)
    last_entry=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%T@ %f\n' 2>/dev/null | sort -nr | head -1 || true)
    last_name=""
    last_date=""
    if [ -n "$last_entry" ]; then
        last_name=$(echo "$last_entry" | awk '{print $2}')
        last_date=$(echo "$last_entry" | awk '{print $1}' | xargs -I{} date -d @{} '+%Y-%m-%d %H:%M' 2>/dev/null || echo "?")
    fi

    echo "  ${DIM}┌─ Status ─────────────────────────────────────────┐${NC}"
    echo "  ${DIM}│${NC}  ${CYAN}Target:${NC}   $BACKUP_ROOT"
    echo "  ${DIM}│${NC}  ${CYAN}Mount:${NC}    ${mount_color}${mount_icon} ${mount_state}${NC}"
    echo "  ${DIM}│${NC}  ${CYAN}Space:${NC}    ${usage}"
    echo "  ${DIM}│${NC}  ${CYAN}Backups:${NC}  ${WHITE}${total}${NC} total  ${GREEN}${protected}${NC} protected  ${YELLOW}keep=${BACKUP_RETENTION}${NC}"
    if [ -n "$last_name" ]; then
        echo "  ${DIM}│${NC}  ${CYAN}Latest:${NC}   ${last_name}"
        echo "  ${DIM}│${NC}            ${DIM}${last_date}${NC}"
    fi
    echo "  ${DIM}└──────────────────────────────────────────────────┘${NC}"
    echo ""
}

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  create [--retention N]   Create a full backup
  list                     List the available backups
  delete <file>            Delete one backup (.tar.xz)
  prune [--keep N]         Keep only the N most recent (by date)
  download-hint            Show how to download a backup with scp
  restore <file>           Restore an existing backup
  schedule <HH:MM> [N] [FREQ] [DAY]
                           Schedule an automatic backup
                           FREQ: daily (default), weekly, monthly
                           DAY:  0-6 (day of week) or 1-28 (day of month)

Contents of each backup:
  - docker-compose.yml, .env (configuration)
  - nginx/, php/, promtail/, loki/ (services)
  - mysql/init/, src/ (code and SQL)
  - db/ (full MySQL datadir)
EOF
}

log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" >/dev/null
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

load_env() {
    if [ -f "$PROJECT_DIR/.env" ]; then
        # shellcheck source=/dev/null
        . "$PROJECT_DIR/.env" 2>/dev/null || true
    fi
    # Note: MYSQL_ROOT_PASSWORD is no longer needed because we take a physical copy
    # of the datadir (stop MySQL → copy → start). If it is redacted or missing, that is fine.
    if [ -z "${MYSQL_ROOT_PASSWORD:-}" ] || [[ "${MYSQL_ROOT_PASSWORD:-}" == *REDACTED* ]]; then
        # Password unavailable or sanitized: fine for a physical backup
        MYSQL_ROOT_PASSWORD=""
    fi
}

ensure_mount() {
    if mountpoint -q "$BACKUP_ROOT"; then
        return
    fi

    # Loop-file setups: after a reboot the loop device and the LVM volume group are
    # not active, so the fstab entry (nofail) silently does not mount. Bring them up.
    if [ -f "$BACKUP_LOOP_FILE" ]; then
        losetup -j "$BACKUP_LOOP_FILE" | grep -q . || losetup -f "$BACKUP_LOOP_FILE" || true
        vgchange -ay "$BACKUP_VG" >/dev/null 2>&1 || true
    fi

    # Try to mount automatically (the loop file or dedicated disk must be in /etc/fstab)
    if mount "$BACKUP_ROOT" >/dev/null 2>&1 || mount -a >/dev/null 2>&1; then
        if mountpoint -q "$BACKUP_ROOT"; then
            return
        fi
    fi

    echo "Mount point $BACKUP_ROOT is not available" >&2
    exit 1
}

prune_backups() {
    ensure_mount
    local keep="$1"
    local files
    mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
    local candidates=()
    for f in "${files[@]}"; do
        if [ ! -f "$BACKUP_ROOT/$f.keep" ]; then
            candidates+=("$f")
        fi
    done

    local count_total=${#files[@]}
    local count_cand=${#candidates[@]}
    if [ "$count_cand" -le "$keep" ]; then
        echo "  ${GREEN}✔${NC} Prune: nothing to delete (total=$count_total, protected=$((count_total-count_cand)), keep=$keep)"
        return
    fi
    local to_delete=$((count_cand-keep))
    local deleted=0
    for fname in "${candidates[@]:0:to_delete}"; do
        rm -f "$BACKUP_ROOT/$fname"
        log "Backup deleted by rotation: $fname"
        deleted=$((deleted+1))
    done
    echo "  ${GREEN}✔${NC} Prune complete: ${YELLOW}$deleted deleted${NC} (protected backups untouched)"
}

# Name of the Docker volume mounted at <destination> in <container> (empty if none)
container_volume() {
    docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Name}}{{end}}{{end}}" "$1" 2>/dev/null || true
}

restart_mysql_quietly() {
    "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || true
}

create_backup() {
    local retention="$1"
    local protect_flag="${2:-}"
    load_env
    ensure_mount
    local existing_count
    existing_count=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" 2>/dev/null | wc -l)
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local name="backup-${ts}"
    local staging
    staging=$(mktemp -d)

    mkdir -p "$staging/files"
    for path in docker-compose.yml .env secrets nginx php promtail loki mysql/init src; do
        if [ -e "$PROJECT_DIR/$path" ]; then
            # Keep the relative path (mysql/init stays mysql/init) so restore puts it back in place
            mkdir -p "$staging/files/$(dirname "$path")"
            copy_tree "$PROJECT_DIR/$path" "$staging/files/$(dirname "$path")/"
        fi
    done

    mkdir -p "$staging/db"
    if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
        echo -e "${RED}docker compose is not available or there is no project in $PROJECT_DIR${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    echo "  ${DIM}Stopping MySQL for a physical copy of the datadir...${NC}"
    local mysql_stopped=false
    if "${COMPOSE[@]}" stop mysql >/dev/null 2>&1; then
        mysql_stopped=true
    else
        echo "  ${RED}✗ Could not stop MySQL${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    # Copy the datadir from the stopped container volume
    echo "  ${DIM}Copying the datadir...${NC}"
    if ! docker run --rm --volumes-from asir_mysql -v "$staging/db":/backup busybox:1.37 sh -c 'cd /var/lib/mysql && cp -a . /backup'; then
        echo "  ${RED}✗ Failed to copy the MySQL datadir${NC}" >&2
        rm -rf "$staging"
        if [ "$mysql_stopped" = true ]; then
            "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || true
        fi
        exit 1
    fi

    echo "  ${DIM}Starting MySQL...${NC}"
    if [ "$mysql_stopped" = true ]; then
        "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || echo "MySQL could not be started automatically" >&2
    fi

    # Honeypot data: recorded TTY sessions (Docker volume) and Cowrie logs (host)
    local cowrie_volume
    cowrie_volume=$(container_volume asir_cowrie /cowrie/var/lib/cowrie)
    if [ -n "$cowrie_volume" ]; then
        mkdir -p "$staging/cowrie/data"
        docker run --rm -v "$cowrie_volume":/data:ro -v "$staging/cowrie/data":/backup busybox:1.37 sh -c 'cp -a /data/. /backup/' \
            || echo "  ${YELLOW}⚠ Could not copy the Cowrie sessions${NC}" >&2
    fi
    if [ -d /var/log/cowrie ]; then
        mkdir -p "$staging/cowrie"
        cp -a /var/log/cowrie "$staging/cowrie/logs"
    fi

    cat > "$staging/meta.json" <<EOF
{
  "name": "$name",
  "created_at": "$(date --iso-8601=seconds)",
  "host": "$(hostname)",
  "project_dir": "$PROJECT_DIR",
  "retention": $retention
}
EOF

    local archive="$BACKUP_ROOT/${name}.tar.xz"
    tar -C "$staging" -cJf "$archive" .
    rm -rf "$staging"
    chmod 640 "$archive"
    chown root:root "$archive"
    local archive_size
    archive_size=$(du -h "$archive" | awk '{print $1}')
    log "Backup created: $archive ($archive_size)"
    echo ""
    echo "  ${GREEN}✔ Backup created:${NC} $archive"
    echo "  ${DIM}Size: ${archive_size}${NC}"
    echo ""

    if [ -z "$protect_flag" ]; then
        protect_flag="$BACKUP_PROTECT_DEFAULT"
    fi
    # The first backup is always protected
    if [ "$existing_count" -eq 0 ]; then
        protect_flag="yes"
        echo "  ${YELLOW}🔒 First backup detected: automatically marked as protected${NC}"
    fi
    if [ "$protect_flag" = "ask" ]; then
        echo -n "  Protect this backup so prune skips it? (${GREEN}Y${NC}/n): "
        read -r ans
        if [ -z "$ans" ] || [[ "$ans" =~ ^[Yy]$ ]]; then
            protect_flag="yes"
        else
            protect_flag="no"
        fi
    fi
    if [ "$protect_flag" = "yes" ]; then
        touch "$archive.keep"
        echo "  ${GREEN}🔒 Backup marked as protected${NC}"
    fi

    prune_backups "$retention"
}

list_backups() {
    ensure_mount
    local output
    output=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\t%TY-%Tm-%Td %TH:%TM\t%k\n' | sort)
    if [ -z "$output" ]; then
        echo ""
        echo "  ${YELLOW}No backups available${NC}"
        echo ""
    else
        echo ""
        echo "  ${BOLD}${CYAN}📋 Backup list${NC}"
        echo "  ${DIM}────────────────────────────────────────────────────────────────────${NC}"
        printf "  ${BOLD}%-38s  %-18s  %10s  %s${NC}\n" "Name" "Date" "Size" "Status"
        echo "  ${DIM}────────────────────────────────────────────────────────────────────${NC}"
        while IFS=$'\t' read -r name date size_kb; do
            local protected_icon="  "
            local protected_color="$NC"
            if [ -f "$BACKUP_ROOT/$name.keep" ]; then
                protected_icon="🔒 Protected"
                protected_color="$GREEN"
            fi
            local size_human
            if [ "$size_kb" -ge 1024 ]; then
                size_human="$(( size_kb / 1024 )) MB"
            else
                size_human="${size_kb} KB"
            fi
            printf "  ${protected_color}%-38s${NC}  ${DIM}%-18s${NC}  %10s  %s\n" "$name" "$date" "$size_human" "$protected_icon"
        done <<< "$output"
        echo "  ${DIM}────────────────────────────────────────────────────────────────────${NC}"
        echo ""
    fi
}

delete_backup() {
    ensure_mount
    local file="$1"
    if [ -z "$file" ]; then
        echo "  ${RED}✗ You must give the backup name (.tar.xz)${NC}" >&2
        exit 1
    fi
    echo ""
    echo -n "  ${YELLOW}⚠ Confirm deletion of '$file'${NC} (type ${WHITE}YES${NC}): "
    read -r confirm
    if [ "$confirm" != "YES" ]; then
        echo "  ${DIM}Operation cancelled${NC}"
        return
    fi
    if [ -f "$BACKUP_ROOT/$file.keep" ]; then
        echo ""
        echo -n "  ${RED}⚠⚠ WARNING: PROTECTED backup.${NC} Type ${WHITE}DELETE${NC} to delete it: "
        read -r confirm2
        if [ "$confirm2" != "DELETE" ]; then
            echo "  ${DIM}Operation cancelled${NC}"
            return
        fi
    fi
    if rm -f "$BACKUP_ROOT/$file"; then
        log "Backup deleted manually: $file"
        echo ""
        echo "  ${GREEN}✔${NC} Backup deleted: $file"
        rm -f "$BACKUP_ROOT/$file.keep"
    fi
}

download_hint() {
    ensure_mount
    local host port
    host=$(detect_host_ip)
    port=$(detect_ssh_port)

    mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort -r)
    if [ ${#files[@]} -eq 0 ]; then
        echo ""
        echo "  ${YELLOW}⚠ No backups available to download${NC}"
        return
    fi

    echo ""
    echo "  ${BOLD}${CYAN}📥 Download a backup via SCP${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  Select the backup to download:"
    echo ""
    local i=1
    for f in "${files[@]}"; do
        local prot=""
        [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protected${NC}"
        local size
        size=$(du -h "$BACKUP_ROOT/$f" 2>/dev/null | awk '{print $1}')
        echo "    ${GREEN}$i${NC})  $f  ${DIM}($size)${NC}$prot"
        i=$((i+1))
    done
    echo ""
    echo -n "  ${CYAN}➤ Number:${NC} "
    read -r sel

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#files[@]} ]; then
        echo ""
        echo "  ${RED}✗ Invalid selection${NC}"
        return
    fi

    local chosen="${files[$((sel-1))]}"
    echo ""
    echo "  ${BOLD}${YELLOW}From your local machine, run:${NC}"
    echo ""
    echo "  ${DIM}1) On the server, copy the backup to your home directory (only root can read the backups):${NC}"
    echo "  ${WHITE}sudo install -m 600 -o \"\$USER\" ${BACKUP_ROOT}/${chosen} ~/${NC}"
    echo "  ${DIM}2) On your local machine:${NC}"
    echo "  ${WHITE}scp -P ${port} <user>@${host:-<IP>}:~/${chosen} .${NC}"
    echo ""
    echo "  ${DIM}Notes:${NC}"
    echo "  ${DIM}  • Replace <user> with your SSH admin user${NC}"
    echo "  ${DIM}  • Detected SSH port: ${WHITE}${port}${NC}"
    echo "  ${DIM}  • Detected IP: ${WHITE}${host:-unknown}${NC}"
    echo ""
}

import_backup() {
    ensure_mount
    local host port
    host=$(detect_host_ip)
    port=$(detect_ssh_port)

    echo ""
    echo "  ${BOLD}${CYAN}📤 Import an external backup${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  ${WHITE}To upload a backup from your local machine:${NC}"
    echo ""
    echo "  ${WHITE}scp -P ${port} /local/path/backup-XXXXXX.tar.xz <user>@${host:-<IP>}:~/${NC}"
    echo "  ${DIM}Then, on the server:${NC} ${WHITE}sudo mv ~/backup-XXXXXX.tar.xz ${BACKUP_ROOT}/${NC}"
    echo ""
    echo "  ${DIM}Notes:${NC}"
    echo "  ${DIM}  • Replace <user> with your SSH admin user${NC}"
    echo "  ${DIM}  • The file name must end in .tar.xz${NC}"
    echo "  ${DIM}  • Detected SSH port: ${WHITE}${port}${NC}"
    echo "  ${DIM}  • Detected IP: ${WHITE}${host:-unknown}${NC}"
    echo ""
    echo "  ${YELLOW}Once it is uploaded, use option 8 to restore it.${NC}"
    echo ""
}

restore_backup() {
    ensure_mount
    local file="$1"
    local archive="$BACKUP_ROOT/$file"

    if [ ! -f "$archive" ]; then
        echo "  ${RED}✗ Backup not found: $file${NC}" >&2
        return 1
    fi

    echo ""
    echo "  ${BOLD}${YELLOW}⚠ BACKUP RESTORE${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  ${WHITE}Backup contents:${NC}"
    echo "    • docker-compose.yml, .env (configuration)"
    echo "    • nginx/, php/, promtail/, loki/ (configs)"
    echo "    • mysql/init/ (SQL scripts)"
    echo "    • src/ (panel code)"
    echo "    • db/ (full MySQL datadir)"
    echo ""
    echo "  ${RED}⚠ WARNING:${NC}"
    echo "    This will OVERWRITE the current configuration"
    echo "    and REPLACE the MySQL database."
    echo ""
    echo -n "  Type ${WHITE}RESTORE${NC} to continue: "
    read -r confirm
    if [ "$confirm" != "RESTORE" ]; then
        echo "  ${DIM}Operation cancelled${NC}"
        return
    fi

    local staging
    staging=$(mktemp -d)

    echo ""
    echo "  ${DIM}Extracting the backup...${NC}"
    if ! tar -xJf "$archive" -C "$staging"; then
        echo "  ${RED}✗ Failed to extract the backup${NC}" >&2
        rm -rf "$staging"
        return 1
    fi

    local restore_ok=true

    # Configuration files (same list and layout as create_backup)
    echo "  ${DIM}Restoring configuration files...${NC}"
    for path in docker-compose.yml .env secrets nginx php promtail loki mysql/init src; do
        local src="$staging/files/$path"
        # Backups made before v3.0.0 stored mysql/init as files/init
        if [ "$path" = "mysql/init" ] && [ ! -e "$src" ] && [ -e "$staging/files/init" ]; then
            src="$staging/files/init"
        fi
        if [ -e "$src" ]; then
            rm -rf -- "${PROJECT_DIR:?}/$path"
            mkdir -p "$PROJECT_DIR/$(dirname "$path")"
            cp -a "$src" "$PROJECT_DIR/$path"
        fi
    done

    # MySQL datadir
    if [ -d "$staging/db" ] && [ -n "$(ls -A "$staging/db" 2>/dev/null)" ]; then
        local mysql_volume
        mysql_volume=$(container_volume asir_mysql /var/lib/mysql)
        if [ -z "$mysql_volume" ]; then
            mysql_volume=$(docker volume ls -q | grep -E '_mysql_data$' | head -1 || true)
        fi
        if [ -z "$mysql_volume" ]; then
            echo "  ${RED}✗ MySQL volume not found: the database has NOT been restored${NC}" >&2
            restore_ok=false
        else
            echo "  ${DIM}Stopping MySQL...${NC}"
            "${COMPOSE[@]}" stop mysql >/dev/null 2>&1 || true
            # Whatever happens from here on, MySQL is started again and the staging copy removed
            # shellcheck disable=SC2064  # $staging is expanded now on purpose: it is a local variable
            trap "restart_mysql_quietly; rm -rf -- '$staging'" EXIT
            echo "  ${DIM}Restoring the MySQL datadir...${NC}"
            if ! docker run --rm -v "$mysql_volume":/var/lib/mysql -v "$staging/db":/backup:ro busybox:1.37 \
                    sh -c 'find /var/lib/mysql -mindepth 1 -delete && cp -a /backup/. /var/lib/mysql/'; then
                echo "  ${RED}✗ Copying the MySQL datadir failed${NC}" >&2
                restore_ok=false
            fi
            echo "  ${DIM}Starting MySQL...${NC}"
            if ! "${COMPOSE[@]}" start mysql >/dev/null 2>&1; then
                echo "  ${RED}✗ MySQL did not start; check: docker compose logs mysql${NC}" >&2
                restore_ok=false
            fi
            trap - EXIT
        fi
    fi

    # Honeypot data (backups made since v3.0.0)
    if [ -d "$staging/cowrie/data" ]; then
        local cowrie_volume
        cowrie_volume=$(container_volume asir_cowrie /cowrie/var/lib/cowrie)
        if [ -n "$cowrie_volume" ]; then
            docker run --rm -v "$cowrie_volume":/data -v "$staging/cowrie/data":/backup:ro busybox:1.37 sh -c 'cp -a /backup/. /data/' \
                || { echo "  ${YELLOW}⚠ Could not restore the Cowrie sessions${NC}" >&2; restore_ok=false; }
        fi
    fi
    if [ -d "$staging/cowrie/logs" ]; then
        mkdir -p /var/log/cowrie
        cp -a "$staging/cowrie/logs/." /var/log/cowrie/
    fi

    rm -rf -- "$staging"

    echo ""
    if [ "$restore_ok" != true ]; then
        echo "  ${YELLOW}⚠ Restore incomplete: check the messages above${NC}"
        log "Backup restored with errors: $file"
        return 1
    fi
    echo "  ${GREEN}✔ Backup restored${NC}"
    echo ""
    echo "  ${YELLOW}Note:${NC} the services may need a restart:"
    echo "    ${DIM}cd $PROJECT_DIR && docker compose down && docker compose up -d${NC}"
    echo ""
    log "Backup restored: $file"
}

schedule_backup() {
    local time="$1"
    local keep="$2"
    local freq="${3:-daily}"
    local day_param="${4:-}"

    if ! [[ "$time" =~ ^[0-9]{2}:[0-9]{2}$ ]]; then
        echo "  ${RED}✗ Invalid time. Use HH:MM${NC}" >&2
        return 1
    fi

    local minute hour
    minute=${time#*:}
    hour=${time%:*}

    local cron_schedule=""
    local freq_desc=""
    local day_names=("Sunday" "Monday" "Tuesday" "Wednesday" "Thursday" "Friday" "Saturday")

    case "$freq" in
        daily)
            cron_schedule="${minute} ${hour} * * *"
            freq_desc="Daily at ${hour}:${minute}"
            ;;
        weekly)
            if ! [[ "$day_param" =~ ^[0-6]$ ]]; then
                echo "  ${RED}✗ Invalid day of the week (0=Sun, 6=Sat)${NC}" >&2
                return 1
            fi
            cron_schedule="${minute} ${hour} * * ${day_param}"
            freq_desc="Weekly: ${day_names[$day_param]} at ${hour}:${minute}"
            ;;
        monthly)
            if ! [[ "$day_param" =~ ^[0-9]+$ ]] || [ "$day_param" -lt 1 ] || [ "$day_param" -gt 28 ]; then
                echo "  ${RED}✗ Invalid day of the month (1-28)${NC}" >&2
                return 1
            fi
            cron_schedule="${minute} ${hour} ${day_param} * *"
            freq_desc="Monthly: day ${day_param} at ${hour}:${minute}"
            ;;
        *)
            echo "  ${RED}✗ Invalid frequency${NC}" >&2
            return 1
            ;;
    esac

    local cron_file="/etc/cron.d/asir-backups"
    cat > "$cron_file" <<EOF
# ASIR VPS Defense automatic backup
# Frequency: ${freq_desc}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${cron_schedule} root BACKUP_RETENTION=${keep} BACKUP_ROOT=${BACKUP_ROOT} LOG_FILE=${LOG_FILE} bash ${PROJECT_DIR}/backups.sh create --retention ${keep} --no-protect >> ${LOG_FILE} 2>&1
EOF
    chmod 644 "$cron_file"
    log "Cron configured: ${freq_desc}, retention ${keep}"
    echo ""
    echo "  ${GREEN}✔${NC} Backup scheduled: ${WHITE}${freq_desc}${NC}"
    echo "  ${DIM}Retention: ${keep} backups${NC}"
}

show_current_schedule() {
    local cron_file="/etc/cron.d/asir-backups"
    if [ -f "$cron_file" ]; then
        local schedule_line
        schedule_line=$(grep -v '^#' "$cron_file" | grep -v '^PATH=' | grep -v '^$' | head -1)
        if [ -n "$schedule_line" ]; then
            echo "  ${CYAN}Current schedule:${NC}"
            # Extract the cron fields
            local min hour dom dow
            IFS=' ' read -r min hour dom _ dow _ <<< "$schedule_line"
            if [ "$dom" = "*" ] && [ "$dow" = "*" ]; then
                echo "    ${WHITE}Daily${NC} at ${hour}:${min}"
            elif [ "$dom" = "*" ] && [ "$dow" != "*" ]; then
                local day_names=("Sunday" "Monday" "Tuesday" "Wednesday" "Thursday" "Friday" "Saturday")
                echo "    ${WHITE}Weekly${NC}: ${day_names[$dow]} at ${hour}:${min}"
            elif [ "$dom" != "*" ]; then
                echo "    ${WHITE}Monthly${NC}: day ${dom} at ${hour}:${min}"
            fi
            echo ""
        fi
    fi
}

remove_schedule() {
    local cron_file="/etc/cron.d/asir-backups"
    if [ -f "$cron_file" ]; then
        rm -f "$cron_file"
        log "Backup schedule removed"
        echo "  ${GREEN}✔${NC} Schedule removed"
    else
        echo "  ${YELLOW}⚠ No schedule configured${NC}"
    fi
}

menu_loop() {
    while true; do
        render_header
        echo "  ${BOLD}Available actions:${NC}"
        echo ""
        echo "    ${GREEN}1${NC})  📦  Create a backup now"
        echo "    ${GREEN}2${NC})  📋  List backups"
        echo "    ${GREEN}3${NC})  🗑️   Delete a backup"
        echo "    ${GREEN}4${NC})  🔒  Protect/unprotect a backup"
        echo "    ${GREEN}5${NC})  🧹  Prune (keep the N most recent)"
        echo "    ${GREEN}6${NC})  ⏰  Schedule automatic backups"
        echo "    ${GREEN}7${NC})  📥  Download a backup (scp)"
        echo "    ${GREEN}8${NC})  🔄  Restore a backup"
        echo "    ${GREEN}9${NC})  📤  Import an external backup"
        echo "    ${GREEN}i${NC})  ℹ️   What a backup contains"
        echo "    ${RED}0${NC})  🚪  Exit"
        echo ""
        echo -n "  ${CYAN}➤ Select an option [0-9/i]:${NC} "
        read -r opt

        case "$opt" in
            1)
                echo ""
                echo "  ${BOLD}${CYAN}📦 Create a backup${NC}"
                echo ""
                echo -n "  Retention (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                echo ""
                # Manual backups: protect by default, but ask in case the user wants otherwise
                create_backup "$keep" "ask"
                pause
                ;;
            2)
                list_backups
                pause
                ;;
            3)
                ensure_mount
                local files
                mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
                if [ ${#files[@]} -eq 0 ]; then
                    echo ""
                    echo "  ${YELLOW}⚠ No backups to delete${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🗑️  Delete a backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local prot=""
                    [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protected${NC}"
                    echo "    ${GREEN}$i${NC})  $f$prot"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Number to delete:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    delete_backup "${files[$((sel-1))]}"
                else
                    echo ""
                    echo "  ${RED}✗ Invalid selection${NC}"
                fi
                pause
                ;;
            4)
                ensure_mount
                local files
                mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
                if [ ${#files[@]} -eq 0 ]; then
                    echo ""
                    echo "  ${YELLOW}⚠ No backups to manage${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🔐 Protect/unprotect a backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local tag="${DIM}(not protected)${NC}"
                    [ -f "$BACKUP_ROOT/$f.keep" ] && tag="${GREEN}🔒 PROTECTED${NC}"
                    echo "    ${GREEN}$i${NC})  $f  $tag"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Number to toggle:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    local target="${files[$((sel-1))]}"
                    if [ -f "$BACKUP_ROOT/$target.keep" ]; then
                        rm -f "$BACKUP_ROOT/$target.keep"
                        echo ""
                        echo "  ${YELLOW}🔓 Backup unprotected:${NC} $target"
                    else
                        touch "$BACKUP_ROOT/$target.keep"
                        echo ""
                        echo "  ${GREEN}🔒 Backup protected:${NC} $target"
                    fi
                else
                    echo ""
                    echo "  ${RED}✗ Invalid selection${NC}"
                fi
                pause
                ;;
            5)
                echo ""
                echo "  ${BOLD}${CYAN}🧹 Prune (clean-up)${NC}"
                echo ""
                echo -n "  How many backups to keep (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                echo ""
                prune_backups "$keep"
                pause
                ;;
            6)
                echo ""
                echo "  ${BOLD}${CYAN}⏰ Schedule automatic backups${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                show_current_schedule
                echo "  Select the frequency:"
                echo ""
                echo "    ${GREEN}1${NC})  Daily"
                echo "    ${GREEN}2${NC})  Weekly"
                echo "    ${GREEN}3${NC})  Monthly"
                echo "    ${RED}0${NC})  Remove the schedule"
                echo ""
                echo -n "  ${CYAN}➤ Option:${NC} "
                read -r freq_opt

                case "$freq_opt" in
                    1)
                        echo ""
                        echo -n "  Time (HH:MM): "
                        read -r hhmm
                        echo -n "  Retention (ENTER=${BACKUP_RETENTION}): "
                        read -r keep
                        [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                        schedule_backup "$hhmm" "$keep" "daily"
                        ;;
                    2)
                        echo ""
                        echo "  Day of the week:"
                        echo "    ${GREEN}0${NC}) Sunday     ${GREEN}1${NC}) Monday     ${GREEN}2${NC}) Tuesday"
                        echo "    ${GREEN}3${NC}) Wednesday  ${GREEN}4${NC}) Thursday   ${GREEN}5${NC}) Friday"
                        echo "    ${GREEN}6${NC}) Saturday"
                        echo ""
                        echo -n "  ${CYAN}➤ Day (0-6):${NC} "
                        read -r dow
                        echo -n "  Time (HH:MM): "
                        read -r hhmm
                        echo -n "  Retention (ENTER=${BACKUP_RETENTION}): "
                        read -r keep
                        [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                        schedule_backup "$hhmm" "$keep" "weekly" "$dow"
                        ;;
                    3)
                        echo ""
                        echo -n "  Day of the month (1-28): "
                        read -r dom
                        echo -n "  Time (HH:MM): "
                        read -r hhmm
                        echo -n "  Retention (ENTER=${BACKUP_RETENTION}): "
                        read -r keep
                        [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                        schedule_backup "$hhmm" "$keep" "monthly" "$dom"
                        ;;
                    0)
                        echo ""
                        remove_schedule
                        ;;
                    *)
                        echo ""
                        echo "  ${RED}✗ Invalid option${NC}"
                        ;;
                esac
                pause
                ;;
            7)
                download_hint
                pause
                ;;
            8)
                ensure_mount
                local files
                mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort -r)
                if [ ${#files[@]} -eq 0 ]; then
                    echo ""
                    echo "  ${YELLOW}⚠ No backups to restore${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🔄 Restore a backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local prot=""
                    [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protected${NC}"
                    local size
                    size=$(du -h "$BACKUP_ROOT/$f" 2>/dev/null | awk '{print $1}')
                    echo "    ${GREEN}$i${NC})  $f  ${DIM}($size)${NC}$prot"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Number to restore:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    restore_backup "${files[$((sel-1))]}"
                else
                    echo ""
                    echo "  ${RED}✗ Invalid selection${NC}"
                fi
                pause
                ;;
            9)
                import_backup
                pause
                ;;
            i|I)
                echo ""
                echo "  ${BOLD}${CYAN}ℹ️  Backup contents${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                echo "  Each backup (.tar.xz) includes:"
                echo ""
                echo "    ${WHITE}Configuration:${NC}"
                echo "      • docker-compose.yml  ${DIM}(service definitions)${NC}"
                echo "      • .env                ${DIM}(credentials and variables)${NC}"
                echo ""
                echo "    ${WHITE}Services:${NC}"
                echo "      • nginx/              ${DIM}(web server configuration)${NC}"
                echo "      • php/                ${DIM}(PHP-FPM configuration)${NC}"
                echo "      • promtail/           ${DIM}(log collector)${NC}"
                echo "      • loki/               ${DIM}(log store)${NC}"
                echo ""
                echo "    ${WHITE}Data:${NC}"
                echo "      • mysql/init/         ${DIM}(initial SQL scripts)${NC}"
                echo "      • src/                ${DIM}(panel source code)${NC}"
                echo "      • db/                 ${DIM}(full MySQL datadir)${NC}"
                echo ""
                echo "    ${WHITE}Metadata:${NC}"
                echo "      • meta.json           ${DIM}(date, host, retention)${NC}"
                echo ""
                echo "  ${DIM}A backup can fully restore the system,${NC}"
                echo "  ${DIM}including the panel users and configuration.${NC}"
                echo ""
                pause
                ;;
            0)
                exit 0
                ;;
            *)
                echo ""
                echo "  ${RED}✗ Invalid option${NC}"
                pause
                ;;
        esac
    done
}

main() {
    require_root

    ensure_dependencies

    if [ $# -eq 0 ]; then
        menu_loop
        exit 0
    fi

    local cmd="$1"; shift
    case "$cmd" in
        create)
            local retention="$BACKUP_RETENTION"
            local protect_cli="$BACKUP_PROTECT_DEFAULT"
            while [ $# -gt 0 ]; do
                case "$1" in
                    --retention)
                        retention="$2"; shift 2;;
                    --protect)
                        protect_cli="yes"; shift;;
                    --no-protect)
                        protect_cli="no"; shift;;
                    *) break;;
                esac
            done
            create_backup "$retention" "$protect_cli"
            ;;
        list)
            list_backups
            ;;
        delete)
            delete_backup "${1:-}"
            ;;
        prune)
            local keep="$BACKUP_RETENTION"
            while [ $# -gt 0 ]; do
                case "$1" in
                    --keep)
                        keep="$2"; shift 2;;
                    *) break;;
                esac
            done
            prune_backups "$keep"
            ;;
        download-hint)
            download_hint
            ;;
        restore)
            restore_backup "${1:-}"
            ;;
        schedule)
            schedule_backup "${1:-}" "${2:-$BACKUP_RETENTION}" "${3:-daily}" "${4:-}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
