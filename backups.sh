#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BACKUP_ROOT="${BACKUP_ROOT:-/srv/backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"
LOG_FILE="${LOG_FILE:-/var/log/asir-vps-defense/backup.log}"
COMPOSE=(docker compose -f "$PROJECT_DIR/docker-compose.yml")
COPY_CMD=()
WARN_COPY=0

copy_tree() {
    local src="$1"
    local dst="$2"
    if [ ${#COPY_CMD[@]} -eq 0 ]; then
        if command -v rsync >/dev/null 2>&1; then
            COPY_CMD=(rsync -a)
        else
            COPY_CMD=(cp -a)
            if [ $WARN_COPY -eq 0 ]; then
                echo "rsync no disponible; usando cp -a (puede ser más lento)" >&2
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
        echo "Dependencias OK"
        return
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Faltan dependencias y no está apt-get disponible: ${missing[*]}" >&2
        return
    fi

    echo "Instalando dependencias: ${missing[*]}" >&2
    apt-get update -y >/dev/null 2>&1 || true
    if apt-get install -y "${missing[@]}" >/dev/null 2>&1; then
        echo "Dependencias instaladas: ${missing[*]}"
    else
        echo "No se pudo instalar: ${missing[*]}" >&2
    fi
}

pause() {
    echo ""
    read -r -p "Pulsa ENTER para continuar... " _
}

render_header() {
    clear
    echo "=============================="
    echo "     BACKUP MANAGER"
    echo "=============================="
    local mount_state="no montado"
    if mountpoint -q "$BACKUP_ROOT"; then
        mount_state="montado"
        local usage
        usage=$(df -h "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4" libres / "$2" tot"}')
        echo "Destino : $BACKUP_ROOT ($mount_state)"
        echo "Espacio : ${usage:-desconocido}"
    else
        echo "Destino : $BACKUP_ROOT ($mount_state)"
    fi
    local count
    count=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" 2>/dev/null | wc -l || echo 0)
    echo "Backups : $count (retención por defecto $BACKUP_RETENTION)"
    echo "=============================="
}

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
    if mountpoint -q "$BACKUP_ROOT"; then
        return
    fi

    # Intento de montaje automático (loop o disco dedicado deben estar en /etc/fstab)
    if mount "$BACKUP_ROOT" >/dev/null 2>&1 || mount -a >/dev/null 2>&1; then
        if mountpoint -q "$BACKUP_ROOT"; then
            return
        fi
    fi

    echo "El punto de montaje $BACKUP_ROOT no está disponible" >&2
    exit 1
}

prune_backups() {
    ensure_mount
    local keep="$1"
    local files
    mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
    local count=${#files[@]}
    if [ "$count" -le "$keep" ]; then
        echo "Prune: nada que borrar (total $count, keep $keep)"
        return
    fi
    local to_delete=$((count-keep))
    local deleted=0
    for fname in "${files[@]:0:to_delete}"; do
        rm -f "$BACKUP_ROOT/$fname"
        log "Backup eliminado por rotación: $fname"
        deleted=$((deleted+1))
    done
    echo "Prune completado: eliminados $deleted, quedan $keep"
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
            copy_tree "$PROJECT_DIR/$path" "$staging/files/"
        fi
    done

    mkdir -p "$staging/db"
    if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
        echo "docker compose no está disponible o no hay proyecto en $PROJECT_DIR" >&2
        rm -rf "$staging"
        exit 1
    fi
    if ! "${COMPOSE[@]}" exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql sh -c 'mysqldump -uroot --single-transaction --routines --triggers asir_defense' > "$staging/db/asir_defense.sql"; then
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
    echo "Backup creado: $archive"
    prune_backups "$retention"
}

list_backups() {
    ensure_mount
    local output
    output=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\t%TY-%Tm-%Td %TH:%TM\t%k KB\n' | sort)
    if [ -z "$output" ]; then
        echo "No hay backups disponibles"
    else
        echo -e "Nombre\tFecha\tTamaño"
        echo "$output"
    fi
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
        echo "Backup eliminado: $file"
    fi
}

download_hint() {
    ensure_mount
    local host
    host=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "Descarga desde tu máquina local (ejemplo):"
    echo "  scp -P <puerto_ssh> <usuario>@${host:-<host>}:$BACKUP_ROOT/<backup>.tar.xz ."
    echo "(Usa el puerto SSH configurado en tu VPS)"
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
    echo "Programado backup diario a las ${hour}:${minute} (keep=${keep})"
}

menu_loop() {
    while true; do
        render_header
        echo "1) Crear backup ahora"
        echo "2) Listar backups"
        echo "3) Eliminar backup"
        echo "4) Prune (mantener N últimos)"
        echo "5) Programar backup diario"
        echo "6) Cómo descargar (scp)"
        echo "7) Salir"
        echo -n "Opción: "
        read -r opt

        case "$opt" in
            1)
                echo -n "Retención (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                create_backup "$keep"
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
                    echo "No hay backups para borrar"
                    pause
                    continue
                fi
                echo "Selecciona backup a borrar:"
                local i=1
                for f in "${files[@]}"; do
                    echo "  $i) $f"; i=$((i+1))
                done
                echo -n "Número: "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    delete_backup "${files[$((sel-1))]}"
                else
                    echo "Selección inválida"
                fi
                pause
                ;;
            4)
                echo -n "Mantener cuántos backups (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                prune_backups "$keep"
                pause
                ;;
            5)
                echo -n "Hora diaria (HH:MM): "
                read -r hhmm
                echo -n "Retención (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                schedule_backup "$hhmm" "$keep"
                pause
                ;;
            6)
                download_hint
                pause
                ;;
            7)
                exit 0
                ;;
            *)
                echo "Opción inválida"
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
