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
BACKUP_PROTECT_DEFAULT="${BACKUP_PROTECT_DEFAULT:-ask}"

# Estilo mínimo (ANSI)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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
    read -r -p "${DIM}Pulsa ENTER para continuar...${NC} " _
}

render_header() {
    clear
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}        BACKUP MANAGER${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"

    local mount_state="${RED}DESMONTADO${NC}"
    local usage="desconocido"
    if mountpoint -q "$BACKUP_ROOT"; then
        mount_state="${GREEN}MONTADO${NC}"
        usage=$(df -h "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4" libres / "$2" tot"}')
    fi

    local total protected last_entry last_name last_date
    total=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" 2>/dev/null | wc -l || echo 0)
    protected=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz.keep" 2>/dev/null | wc -l || echo 0)
    last_entry=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%T@ %f\n' 2>/dev/null | sort -nr | head -1 || true)
    if [ -n "$last_entry" ]; then
        last_name=$(echo "$last_entry" | awk '{print $2}')
        last_date=$(echo "$last_entry" | awk '{print $1}' | xargs -I{} date -d @{} '+%Y-%m-%d %H:%M')
    fi

    printf "%s %-28s %s\n" "${CYAN}Destino:${NC}" "$BACKUP_ROOT" "(${mount_state})"
    printf "%s %-28s\n" "${CYAN}Espacio:${NC}" "${usage}"
    printf "%s %-28s\n" "${CYAN}Backups:${NC}" "${total} (protegidos: ${protected}, keep=${BACKUP_RETENTION})"
    if [ -n "$last_name" ]; then
        printf "%s %-28s\n" "${CYAN}Último:${NC}" "${last_name} @ ${last_date}"
    fi
    echo -e "${BOLD}──────────────────────────────────────────${NC}"
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
    local candidates=()
    for f in "${files[@]}"; do
        if [ ! -f "$BACKUP_ROOT/$f.keep" ]; then
            candidates+=("$f")
        fi
    done

    local count_total=${#files[@]}
    local count_cand=${#candidates[@]}
    if [ "$count_cand" -le "$keep" ]; then
        echo "Prune: nada que borrar (total=$count_total, protegidos=$((count_total-count_cand)), keep=$keep)"
        return
    fi
    local to_delete=$((count_cand-keep))
    local deleted=0
    for fname in "${candidates[@]:0:to_delete}"; do
        rm -f "$BACKUP_ROOT/$fname"
        log "Backup eliminado por rotación: $fname"
        deleted=$((deleted+1))
    done
    echo "Prune completado: eliminados $deleted (protegidos intactos)"
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
    for path in docker-compose.yml .env nginx php promtail loki mysql/init src; do
        if [ -e "$PROJECT_DIR/$path" ]; then
            copy_tree "$PROJECT_DIR/$path" "$staging/files/"
        fi
    done

    mkdir -p "$staging/db"
    if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
        echo -e "${RED}docker compose no está disponible o no hay proyecto en $PROJECT_DIR${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    echo "Deteniendo MySQL para copia física del datadir..."
    local mysql_stopped=false
    if "${COMPOSE[@]}" stop mysql >/dev/null 2>&1; then
        mysql_stopped=true
    else
        echo -e "${RED}No se pudo detener MySQL${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    # Copiar datadir desde el volumen del contenedor detenido
    if ! docker run --rm --volumes-from asir_mysql -v "$staging/db":/backup busybox sh -c 'cd /var/lib/mysql && cp -a . /backup'; then
        echo -e "${RED}Fallo al copiar el datadir de MySQL${NC}" >&2
        rm -rf "$staging"
        if [ "$mysql_stopped" = true ]; then
            "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || true
        fi
        exit 1
    fi

    echo "Iniciando MySQL..."
    if [ "$mysql_stopped" = true ]; then
        "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || echo "MySQL no se pudo iniciar automáticamente" >&2
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
    log "Backup creado: $archive ($archive_size)"
    echo -e "${GREEN}✔${NC} Backup creado: $archive (${archive_size})"

    if [ -z "$protect_flag" ]; then
        protect_flag="$BACKUP_PROTECT_DEFAULT"
    fi
    # Si es el primer backup, protégelo siempre
    if [ "$existing_count" -eq 0 ]; then
        protect_flag="yes"
        echo -e "${YELLOW}Primer backup detectado: marcado como protegido${NC}"
    fi
    if [ "$protect_flag" = "ask" ]; then
        echo -n "¿Proteger este backup para excluirlo de prune? (S/n): "
        read -r ans
        if [ -z "$ans" ] || [[ "$ans" =~ ^[Ss]$ ]]; then
            protect_flag="yes"
        else
            protect_flag="no"
        fi
    fi
    if [ "$protect_flag" = "yes" ]; then
        touch "$archive.keep"
        echo "Backup marcado como protegido"
    fi

    prune_backups "$retention"
}

list_backups() {
    ensure_mount
    local output
    output=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\t%TY-%Tm-%Td %TH:%TM\t%k KB\n' | sort)
    if [ -z "$output" ]; then
        echo "No hay backups disponibles"
    else
        printf "%-36s  %-16s  %-8s  %-10s\n" "Nombre" "Fecha" "Tamaño" "Protegido"
        printf "%-36s  %-16s  %-8s  %-10s\n" "------------------------------------" "----------------" "--------" "----------"
        while IFS=$'\t' read -r name date size; do
            local protected="no"
            [ -f "$BACKUP_ROOT/$name.keep" ] && protected="sí"
            printf "%-36s  %-16s  %-8s  %-10s\n" "$name" "$date" "$size" "$protected"
        done <<< "$output"
    fi
}

delete_backup() {
    ensure_mount
    local file="$1"
    if [ -z "$file" ]; then
        echo "Debes indicar el nombre del backup (.tar.xz)" >&2
        exit 1
    fi
    echo -n "Confirma eliminación de '$file' (escribe YES): "
    read -r confirm
    if [ "$confirm" != "YES" ]; then
        echo "Operación cancelada"
        return
    fi
    if [ -f "$BACKUP_ROOT/$file.keep" ]; then
        echo -n "${RED}ATENCIÓN:${NC} backup protegido. Escribe DELETE para eliminarlo igualmente: "
        read -r confirm2
        if [ "$confirm2" != "DELETE" ]; then
            echo "Operación cancelada"
            return
        fi
    fi
    if rm -f "$BACKUP_ROOT/$file"; then
        log "Backup eliminado manualmente: $file"
        echo -e "${YELLOW}Backup eliminado:${NC} $file"
        rm -f "$BACKUP_ROOT/$file.keep"
    fi
}

download_hint() {
    ensure_mount
    local host port latest
    host=$(detect_host_ip)
    port=$(detect_ssh_port)

    mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%T@ %f\n' | sort -nr)
    if [ ${#files[@]} -gt 0 ]; then
        latest=$(echo "${files[0]}" | awk '{print $2}')
    fi

    echo "${BOLD}Descarga rápida desde tu máquina local:${NC}"
    if [ -n "$latest" ]; then
        echo "  scp -P ${port} <usuario>@${host:-<host>}:$BACKUP_ROOT/${latest} ."
        echo "${DIM}(Usando el backup más reciente)${NC}"
    else
        echo "  scp -P ${port} <usuario>@${host:-<host>}:$BACKUP_ROOT/<backup>.tar.xz ."
    fi
    echo "${DIM}Sustituye <usuario> por tu admin SSH y ajusta la ruta si cambiaste BACKUP_ROOT.${NC}"
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
${minute} ${hour} * * * root BACKUP_RETENTION=${keep} BACKUP_ROOT=${BACKUP_ROOT} LOG_FILE=${LOG_FILE} bash ${PROJECT_DIR}/backups.sh create --retention ${keep} --no-protect >> ${LOG_FILE} 2>&1
EOF
    chmod 644 "$cron_file"
    log "Cron diario configurado a las ${hour}:${minute} con retención ${keep}"
    echo "Programado backup diario a las ${hour}:${minute} (keep=${keep})"
}

menu_loop() {
    while true; do
        render_header
        echo "${BOLD}Acciones:${NC}"
        echo "  1) Crear backup ahora"
        echo "  2) Listar backups"
        echo "  3) Eliminar backup"
        echo "  4) Proteger/Desproteger backup"
        echo "  5) Prune (mantener N últimos)"
        echo "  6) Programar backup diario"
        echo "  7) Cómo descargar (scp)"
        echo "  8) Salir"
        echo -n "${CYAN}Opción:${NC} "
        read -r opt

        case "$opt" in
            1)
                echo -n "Retención (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                # Manuales: proteger por defecto, pero preguntar si desea cambiar
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
                    echo "${YELLOW}No hay backups para borrar${NC}"
                    pause
                    continue
                fi
                echo "${BOLD}Selecciona backup a borrar:${NC}"
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
                ensure_mount
                local files
                mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
                if [ ${#files[@]} -eq 0 ]; then
                    echo "${YELLOW}No hay backups para gestionar${NC}"
                    pause
                    continue
                fi
                echo "${BOLD}Selecciona backup para alternar protección:${NC}"
                local i=1
                for f in "${files[@]}"; do
                    local tag=""
                    [ -f "$BACKUP_ROOT/$f.keep" ] && tag="[PROTEGIDO]"
                    echo "  $i) $f $tag"; i=$((i+1))
                done
                echo -n "Número: "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    local target="${files[$((sel-1))]}"
                    if [ -f "$BACKUP_ROOT/$target.keep" ]; then
                        rm -f "$BACKUP_ROOT/$target.keep"
                        echo "Backup desprotegido: $target"
                    else
                        touch "$BACKUP_ROOT/$target.keep"
                        echo "Backup protegido: $target"
                    fi
                else
                    echo "Selección inválida"
                fi
                pause
                ;;
            5)
                echo -n "Mantener cuántos backups (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                prune_backups "$keep"
                pause
                ;;
            6)
                echo -n "Hora diaria (HH:MM): "
                read -r hhmm
                echo -n "Retención (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                schedule_backup "$hhmm" "$keep"
                pause
                ;;
            7)
                download_hint
                pause
                ;;
            8)
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
