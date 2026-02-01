#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BACKUP_ROOT="${BACKUP_ROOT:-/srv/backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"
LOG_FILE="${LOG_FILE:-/var/log/asir-vps-defense/backup.log}"
COMPOSE=(docker compose -f "$PROJECT_DIR/docker-compose.yml")

usage() {
    cat <<EOF
Uso: $0 <comando> [opciones]

Comandos:
  create [--retention N]   Crea un backup completo
  list                     Lista backups disponibles
  delete <fichero>         Elimina un backup concreto (.tar.xz)
  prune [--keep N]         Conserva solo los N últimos (por fecha)
  download-hint            Muestra cómo descargar un backup vía scp
  schedule <HH:MM> [N]     Programa backup diario a esa hora; retención N (defecto ${BACKUP_RETENTION})
EOF
}

log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" >/dev/null
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Este script debe ejecutarse como root" >&2
        exit 1
    fi
}

load_env() {
    if [ -f "$PROJECT_DIR/.env" ]; then
        # shellcheck source=/dev/null
        . "$PROJECT_DIR/.env"
    else
        echo "No se encontró .env en $PROJECT_DIR" >&2
        exit 1
    fi
    if [ -z "${MYSQL_ROOT_PASSWORD:-}" ]; then
        echo "MYSQL_ROOT_PASSWORD no definido en .env" >&2
        exit 1
    fi
}

ensure_mount() {
    if ! mountpoint -q "$BACKUP_ROOT"; then
        echo "El punto de montaje $BACKUP_ROOT no está disponible" >&2
        exit 1
    fi
}

prune_backups() {
    local keep="$1"
    local files
    mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
    local count=${#files[@]}
    if [ "$count" -le "$keep" ]; then
        return
    fi
    local to_delete=$((count-keep))
    for fname in "${files[@]:0:to_delete}"; do
        rm -f "$BACKUP_ROOT/$fname"
        log "Backup eliminado por rotación: $fname"
    done
}

create_backup() {
    local retention="$1"
    load_env
    ensure_mount
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local name="backup-${ts}"
    local staging
    staging=$(mktemp -d)

    mkdir -p "$staging/files"
    for path in docker-compose.yml .env nginx php promtail loki mysql/init src; do
        if [ -e "$PROJECT_DIR/$path" ]; then
            rsync -a "$PROJECT_DIR/$path" "$staging/files/"
        fi
    done

    mkdir -p "$staging/db"
    if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
        echo "docker compose no está disponible o no hay proyecto en $PROJECT_DIR" >&2
        rm -rf "$staging"
        exit 1
    fi
    if ! "${COMPOSE[@]}" exec -T mysql sh -c 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers asir_defense' > "$staging/db/asir_defense.sql"; then
        echo "Fallo al generar mysqldump" >&2
        rm -rf "$staging"
        exit 1
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
    log "Backup creado: $archive"
    prune_backups "$retention"
}

list_backups() {
    ensure_mount
    find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\t%TY-%Tm-%Td %TH:%TM\t%k KB\n' | sort
}

delete_backup() {
    ensure_mount
    local file="$1"
    if [ -z "$file" ]; then
        echo "Debes indicar el nombre del backup (.tar.xz)" >&2
        exit 1
    fi
    if rm -f "$BACKUP_ROOT/$file"; then
        log "Backup eliminado manualmente: $file"
    fi
}

download_hint() {
    local host
    host=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "Descarga desde tu máquina local (ejemplo):"
    echo "  scp -P <puerto_ssh> <usuario>@${host:-<host>}:$BACKUP_ROOT/<backup>.tar.xz ."
}

schedule_backup() {
    local time="$1"
    local keep="$2"
    if ! [[ "$time" =~ ^[0-9]{2}:[0-9]{2}$ ]]; then
        echo "Hora inválida. Usa HH:MM" >&2
        exit 1
    fi
    local minute hour
    minute=${time#*:}
    hour=${time%:*}
    local cron_file="/etc/cron.d/asir-backups"
    cat > "$cron_file" <<EOF
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${minute} ${hour} * * * root BACKUP_RETENTION=${keep} BACKUP_ROOT=${BACKUP_ROOT} LOG_FILE=${LOG_FILE} bash ${PROJECT_DIR}/backups.sh create --retention ${keep} >> ${LOG_FILE} 2>&1
EOF
    chmod 644 "$cron_file"
    log "Cron diario configurado a las ${hour}:${minute} con retención ${keep}"
}

main() {
    require_root
    if [ $# -lt 1 ]; then
        usage
        exit 1
    fi
    local cmd="$1"; shift
    case "$cmd" in
        create)
            local retention="$BACKUP_RETENTION"
            while [ $# -gt 0 ]; do
                case "$1" in
                    --retention)
                        retention="$2"; shift 2;;
                    *) break;;
                esac
            done
            create_backup "$retention"
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
        schedule)
            schedule_backup "${1:-}" "${2:-$BACKUP_RETENTION}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
