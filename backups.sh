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

# Estilo (ANSI con $'...' para compatibilidad con printf)
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'
BLUE=$'\033[0;34m'
MAGENTA=$'\033[0;35m'
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
    echo -n "  ${DIM}[Pulsa ENTER para continuar]${NC} "
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
    local usage="desconocido"
    if mountpoint -q "$BACKUP_ROOT"; then
        mount_icon="●"
        mount_state="MONTADO"
        mount_color="$GREEN"
        usage=$(df -h "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4" libres / "$2" total"}')
    else
        mount_icon="○"
        mount_state="DESMONTADO"
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

    echo "  ${DIM}┌─ Estado ─────────────────────────────────────────┐${NC}"
    echo "  ${DIM}│${NC}  ${CYAN}Destino:${NC}  $BACKUP_ROOT"
    echo "  ${DIM}│${NC}  ${CYAN}Estado:${NC}   ${mount_color}${mount_icon} ${mount_state}${NC}"
    echo "  ${DIM}│${NC}  ${CYAN}Espacio:${NC}  ${usage}"
    echo "  ${DIM}│${NC}  ${CYAN}Backups:${NC}  ${WHITE}${total}${NC} total  ${GREEN}${protected}${NC} protegidos  ${YELLOW}keep=${BACKUP_RETENTION}${NC}"
    if [ -n "$last_name" ]; then
        echo "  ${DIM}│${NC}  ${CYAN}Último:${NC}   ${last_name}"
        echo "  ${DIM}│${NC}            ${DIM}${last_date}${NC}"
    fi
    echo "  ${DIM}└──────────────────────────────────────────────────┘${NC}"
    echo ""
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
  restore <fichero>        Restaura un backup existente
  schedule <HH:MM> [N] [FREQ] [DAY]
                           Programa backup automático
                           FREQ: daily (defecto), weekly, monthly
                           DAY:  0-6 (día semana) o 1-28 (día mes)

Contenido de cada backup:
  - docker-compose.yml, .env (configuración)
  - nginx/, php/, promtail/, loki/ (servicios)
  - mysql/init/, src/ (código y SQL)
  - db/ (datadir MySQL completo)
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
        . "$PROJECT_DIR/.env" 2>/dev/null || true
    fi
    # Nota: MYSQL_ROOT_PASSWORD ya no es necesario porque usamos copia física
    # del datadir (stop MySQL → copy → start). Si está redactado o no existe, es correcto.
    if [ -z "${MYSQL_ROOT_PASSWORD:-}" ] || [[ "${MYSQL_ROOT_PASSWORD:-}" == *REDACTED* ]]; then
        # Password no disponible o sanitizada - OK para backup físico
        MYSQL_ROOT_PASSWORD=""
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
        echo "  ${GREEN}✔${NC} Prune: nada que borrar (total=$count_total, protegidos=$((count_total-count_cand)), keep=$keep)"
        return
    fi
    local to_delete=$((count_cand-keep))
    local deleted=0
    for fname in "${candidates[@]:0:to_delete}"; do
        rm -f "$BACKUP_ROOT/$fname"
        log "Backup eliminado por rotación: $fname"
        deleted=$((deleted+1))
    done
    echo "  ${GREEN}✔${NC} Prune completado: ${YELLOW}$deleted eliminados${NC} (protegidos intactos)"
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
            copy_tree "$PROJECT_DIR/$path" "$staging/files/"
        fi
    done

    mkdir -p "$staging/db"
    if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
        echo -e "${RED}docker compose no está disponible o no hay proyecto en $PROJECT_DIR${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    echo "  ${DIM}Deteniendo MySQL para copia física del datadir...${NC}"
    local mysql_stopped=false
    if "${COMPOSE[@]}" stop mysql >/dev/null 2>&1; then
        mysql_stopped=true
    else
        echo "  ${RED}✗ No se pudo detener MySQL${NC}" >&2
        rm -rf "$staging"
        exit 1
    fi

    # Copiar datadir desde el volumen del contenedor detenido
    echo "  ${DIM}Copiando datadir...${NC}"
    if ! docker run --rm --volumes-from asir_mysql -v "$staging/db":/backup busybox:1.37 sh -c 'cd /var/lib/mysql && cp -a . /backup'; then
        echo "  ${RED}✗ Fallo al copiar el datadir de MySQL${NC}" >&2
        rm -rf "$staging"
        if [ "$mysql_stopped" = true ]; then
            "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || true
        fi
        exit 1
    fi

    echo "  ${DIM}Iniciando MySQL...${NC}"
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
    echo ""
    echo "  ${GREEN}✔ Backup creado:${NC} $archive"
    echo "  ${DIM}Tamaño: ${archive_size}${NC}"
    echo ""

    if [ -z "$protect_flag" ]; then
        protect_flag="$BACKUP_PROTECT_DEFAULT"
    fi
    # Si es el primer backup, protégelo siempre
    if [ "$existing_count" -eq 0 ]; then
        protect_flag="yes"
        echo "  ${YELLOW}🔒 Primer backup detectado: marcado como protegido automáticamente${NC}"
    fi
    if [ "$protect_flag" = "ask" ]; then
        echo -n "  ¿Proteger este backup para excluirlo de prune? (${GREEN}S${NC}/n): "
        read -r ans
        if [ -z "$ans" ] || [[ "$ans" =~ ^[Ss]$ ]]; then
            protect_flag="yes"
        else
            protect_flag="no"
        fi
    fi
    if [ "$protect_flag" = "yes" ]; then
        touch "$archive.keep"
        echo "  ${GREEN}🔒 Backup marcado como protegido${NC}"
    fi

    prune_backups "$retention"
}

list_backups() {
    ensure_mount
    local output
    output=$(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\t%TY-%Tm-%Td %TH:%TM\t%k\n' | sort)
    if [ -z "$output" ]; then
        echo ""
        echo "  ${YELLOW}No hay backups disponibles${NC}"
        echo ""
    else
        echo ""
        echo "  ${BOLD}${CYAN}📋 Lista de backups${NC}"
        echo "  ${DIM}────────────────────────────────────────────────────────────────────${NC}"
        printf "  ${BOLD}%-38s  %-18s  %10s  %s${NC}\n" "Nombre" "Fecha" "Tamaño" "Estado"
        echo "  ${DIM}────────────────────────────────────────────────────────────────────${NC}"
        while IFS=$'\t' read -r name date size_kb; do
            local protected_icon="  "
            local protected_color="$NC"
            if [ -f "$BACKUP_ROOT/$name.keep" ]; then
                protected_icon="🔒 Protegido"
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
        echo "  ${RED}✗ Debes indicar el nombre del backup (.tar.xz)${NC}" >&2
        exit 1
    fi
    echo ""
    echo -n "  ${YELLOW}⚠ Confirma eliminación de '$file'${NC} (escribe ${WHITE}YES${NC}): "
    read -r confirm
    if [ "$confirm" != "YES" ]; then
        echo "  ${DIM}Operación cancelada${NC}"
        return
    fi
    if [ -f "$BACKUP_ROOT/$file.keep" ]; then
        echo ""
        echo -n "  ${RED}⚠⚠ ATENCIÓN: backup PROTEGIDO.${NC} Escribe ${WHITE}DELETE${NC} para eliminar: "
        read -r confirm2
        if [ "$confirm2" != "DELETE" ]; then
            echo "  ${DIM}Operación cancelada${NC}"
            return
        fi
    fi
    if rm -f "$BACKUP_ROOT/$file"; then
        log "Backup eliminado manualmente: $file"
        echo ""
        echo "  ${GREEN}✔${NC} Backup eliminado: $file"
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
        echo "  ${YELLOW}⚠ No hay backups disponibles para descargar${NC}"
        return
    fi

    echo ""
    echo "  ${BOLD}${CYAN}📥 Descargar backup via SCP${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  Selecciona el backup a descargar:"
    echo ""
    local i=1
    for f in "${files[@]}"; do
        local prot=""
        [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protegido${NC}"
        local size
        size=$(du -h "$BACKUP_ROOT/$f" 2>/dev/null | awk '{print $1}')
        echo "    ${GREEN}$i${NC})  $f  ${DIM}($size)${NC}$prot"
        i=$((i+1))
    done
    echo ""
    echo -n "  ${CYAN}➤ Número:${NC} "
    read -r sel

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#files[@]} ]; then
        echo ""
        echo "  ${RED}✗ Selección inválida${NC}"
        return
    fi

    local chosen="${files[$((sel-1))]}"
    echo ""
    echo "  ${BOLD}${YELLOW}Desde tu máquina local, ejecuta:${NC}"
    echo ""
    echo "  ${WHITE}scp -P ${port} <usuario>@${host:-<IP>}:${BACKUP_ROOT}/${chosen} .${NC}"
    echo ""
    echo "  ${DIM}Notas:${NC}"
    echo "  ${DIM}  • Sustituye <usuario> por tu usuario admin SSH${NC}"
    echo "  ${DIM}  • Puerto SSH detectado: ${WHITE}${port}${NC}"
    echo "  ${DIM}  • IP detectada: ${WHITE}${host:-desconocida}${NC}"
    echo ""
}

import_backup() {
    ensure_mount
    local host port
    host=$(detect_host_ip)
    port=$(detect_ssh_port)

    echo ""
    echo "  ${BOLD}${CYAN}📤 Importar backup externo${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  ${WHITE}Para subir un backup desde tu máquina local:${NC}"
    echo ""
    echo "  ${WHITE}scp -P ${port} /ruta/local/backup-XXXXXX.tar.xz <usuario>@${host:-<IP>}:${BACKUP_ROOT}/${NC}"
    echo ""
    echo "  ${DIM}Notas:${NC}"
    echo "  ${DIM}  • Sustituye <usuario> por tu usuario admin SSH${NC}"
    echo "  ${DIM}  • El archivo debe terminar en .tar.xz${NC}"
    echo "  ${DIM}  • Puerto SSH detectado: ${WHITE}${port}${NC}"
    echo "  ${DIM}  • IP detectada: ${WHITE}${host:-desconocida}${NC}"
    echo ""
    echo "  ${YELLOW}Una vez subido, usa la opción 8 para restaurarlo.${NC}"
    echo ""
}

restore_backup() {
    ensure_mount
    local file="$1"
    local archive="$BACKUP_ROOT/$file"

    if [ ! -f "$archive" ]; then
        echo "  ${RED}✗ Backup no encontrado: $file${NC}" >&2
        return 1
    fi

    echo ""
    echo "  ${BOLD}${YELLOW}⚠ RESTAURACIÓN DE BACKUP${NC}"
    echo "  ${DIM}────────────────────────────────────────${NC}"
    echo ""
    echo "  ${WHITE}Contenido del backup:${NC}"
    echo "    • docker-compose.yml, .env (configuración)"
    echo "    • nginx/, php/, promtail/, loki/ (configs)"
    echo "    • mysql/init/ (scripts SQL)"
    echo "    • src/ (código del panel)"
    echo "    • db/ (datadir MySQL completo)"
    echo ""
    echo "  ${RED}⚠ ADVERTENCIA:${NC}"
    echo "    Esto SOBRESCRIBIRÁ la configuración actual"
    echo "    y REEMPLAZARÁ la base de datos MySQL."
    echo ""
    echo -n "  Escribe ${WHITE}RESTORE${NC} para continuar: "
    read -r confirm
    if [ "$confirm" != "RESTORE" ]; then
        echo "  ${DIM}Operación cancelada${NC}"
        return
    fi

    local staging
    staging=$(mktemp -d)

    echo ""
    echo "  ${DIM}Extrayendo backup...${NC}"
    if ! tar -xJf "$archive" -C "$staging"; then
        echo "  ${RED}✗ Fallo al extraer el backup${NC}" >&2
        rm -rf "$staging"
        return 1
    fi

    # Restaurar archivos de configuración
    echo "  ${DIM}Restaurando archivos de configuración...${NC}"
    for path in docker-compose.yml .env secrets nginx php promtail loki mysql src; do
        if [ -e "$staging/files/$path" ]; then
            rm -rf "$PROJECT_DIR/$path"
            cp -a "$staging/files/$path" "$PROJECT_DIR/"
        fi
    done

    # Restaurar MySQL datadir
    if [ -d "$staging/db" ] && [ "$(ls -A "$staging/db" 2>/dev/null)" ]; then
        echo "  ${DIM}Deteniendo MySQL...${NC}"
        "${COMPOSE[@]}" stop mysql >/dev/null 2>&1 || true

        echo "  ${DIM}Restaurando datadir de MySQL...${NC}"
        # Obtener el volumen de MySQL
        local mysql_volume
        mysql_volume=$(docker volume ls -q | grep -E 'mysql_data$' | head -1)
        if [ -n "$mysql_volume" ]; then
            # Limpiar y restaurar
            docker run --rm -v "$mysql_volume":/var/lib/mysql -v "$staging/db":/backup busybox:1.37 sh -c 'rm -rf /var/lib/mysql/* && cp -a /backup/. /var/lib/mysql/'
        fi

        echo "  ${DIM}Iniciando MySQL...${NC}"
        "${COMPOSE[@]}" start mysql >/dev/null 2>&1 || true
    fi

    rm -rf "$staging"

    echo ""
    echo "  ${GREEN}✔ Backup restaurado correctamente${NC}"
    echo ""
    echo "  ${YELLOW}Nota:${NC} Puede ser necesario reiniciar los servicios:"
    echo "    ${DIM}cd $PROJECT_DIR && docker compose down && docker compose up -d${NC}"
    echo ""
    log "Backup restaurado: $file"
}

schedule_backup() {
    local time="$1"
    local keep="$2"
    local freq="${3:-daily}"
    local day_param="${4:-}"

    if ! [[ "$time" =~ ^[0-9]{2}:[0-9]{2}$ ]]; then
        echo "  ${RED}✗ Hora inválida. Usa HH:MM${NC}" >&2
        return 1
    fi

    local minute hour
    minute=${time#*:}
    hour=${time%:*}

    local cron_schedule=""
    local freq_desc=""
    local day_names=("Domingo" "Lunes" "Martes" "Miércoles" "Jueves" "Viernes" "Sábado")

    case "$freq" in
        daily)
            cron_schedule="${minute} ${hour} * * *"
            freq_desc="Diario a las ${hour}:${minute}"
            ;;
        weekly)
            if ! [[ "$day_param" =~ ^[0-6]$ ]]; then
                echo "  ${RED}✗ Día de semana inválido (0=Dom, 6=Sáb)${NC}" >&2
                return 1
            fi
            cron_schedule="${minute} ${hour} * * ${day_param}"
            freq_desc="Semanal: ${day_names[$day_param]} a las ${hour}:${minute}"
            ;;
        monthly)
            if ! [[ "$day_param" =~ ^[0-9]+$ ]] || [ "$day_param" -lt 1 ] || [ "$day_param" -gt 28 ]; then
                echo "  ${RED}✗ Día del mes inválido (1-28)${NC}" >&2
                return 1
            fi
            cron_schedule="${minute} ${hour} ${day_param} * *"
            freq_desc="Mensual: día ${day_param} a las ${hour}:${minute}"
            ;;
        *)
            echo "  ${RED}✗ Frecuencia inválida${NC}" >&2
            return 1
            ;;
    esac

    local cron_file="/etc/cron.d/asir-backups"
    cat > "$cron_file" <<EOF
# Backup automático ASIR VPS Defense
# Frecuencia: ${freq_desc}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${cron_schedule} root BACKUP_RETENTION=${keep} BACKUP_ROOT=${BACKUP_ROOT} LOG_FILE=${LOG_FILE} bash ${PROJECT_DIR}/backups.sh create --retention ${keep} --no-protect >> ${LOG_FILE} 2>&1
EOF
    chmod 644 "$cron_file"
    log "Cron configurado: ${freq_desc} con retención ${keep}"
    echo ""
    echo "  ${GREEN}✔${NC} Backup programado: ${WHITE}${freq_desc}${NC}"
    echo "  ${DIM}Retención: ${keep} backups${NC}"
}

show_current_schedule() {
    local cron_file="/etc/cron.d/asir-backups"
    if [ -f "$cron_file" ]; then
        local schedule_line
        schedule_line=$(grep -v '^#' "$cron_file" | grep -v '^PATH=' | grep -v '^$' | head -1)
        if [ -n "$schedule_line" ]; then
            echo "  ${CYAN}Programación actual:${NC}"
            # Extraer campos del cron
            local min hour dom mon dow
            read -r min hour dom mon dow _ <<< "$schedule_line"
            if [ "$dom" = "*" ] && [ "$dow" = "*" ]; then
                echo "    ${WHITE}Diario${NC} a las ${hour}:${min}"
            elif [ "$dom" = "*" ] && [ "$dow" != "*" ]; then
                local day_names=("Domingo" "Lunes" "Martes" "Miércoles" "Jueves" "Viernes" "Sábado")
                echo "    ${WHITE}Semanal${NC}: ${day_names[$dow]} a las ${hour}:${min}"
            elif [ "$dom" != "*" ]; then
                echo "    ${WHITE}Mensual${NC}: día ${dom} a las ${hour}:${min}"
            fi
            echo ""
        fi
    fi
}

remove_schedule() {
    local cron_file="/etc/cron.d/asir-backups"
    if [ -f "$cron_file" ]; then
        rm -f "$cron_file"
        log "Programación de backup eliminada"
        echo "  ${GREEN}✔${NC} Programación eliminada"
    else
        echo "  ${YELLOW}⚠ No hay programación configurada${NC}"
    fi
}

menu_loop() {
    while true; do
        render_header
        echo "  ${BOLD}Acciones disponibles:${NC}"
        echo ""
        echo "    ${GREEN}1${NC})  📦  Crear backup ahora"
        echo "    ${GREEN}2${NC})  📋  Listar backups"
        echo "    ${GREEN}3${NC})  🗑️   Eliminar backup"
        echo "    ${GREEN}4${NC})  🔒  Proteger/Desproteger backup"
        echo "    ${GREEN}5${NC})  🧹  Prune (mantener N últimos)"
        echo "    ${GREEN}6${NC})  ⏰  Programar backups automáticos"
        echo "    ${GREEN}7${NC})  📥  Descargar backup (scp)"
        echo "    ${GREEN}8${NC})  🔄  Restaurar backup"
        echo "    ${GREEN}9${NC})  📤  Importar backup externo"
        echo "    ${GREEN}i${NC})  ℹ️   Qué contiene un backup"
        echo "    ${RED}0${NC})  🚪  Salir"
        echo ""
        echo -n "  ${CYAN}➤ Selecciona opción [0-9/i]:${NC} "
        read -r opt

        case "$opt" in
            1)
                echo ""
                echo "  ${BOLD}${CYAN}📦 Crear backup${NC}"
                echo ""
                echo -n "  Retención (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                echo ""
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
                    echo ""
                    echo "  ${YELLOW}⚠ No hay backups para borrar${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🗑️  Eliminar backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local prot=""
                    [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protegido${NC}"
                    echo "    ${GREEN}$i${NC})  $f$prot"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Número a eliminar:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    delete_backup "${files[$((sel-1))]}"
                else
                    echo ""
                    echo "  ${RED}✗ Selección inválida${NC}"
                fi
                pause
                ;;
            4)
                ensure_mount
                local files
                mapfile -t files < <(find "$BACKUP_ROOT" -maxdepth 1 -type f -name "*.tar.xz" -printf '%f\n' | sort)
                if [ ${#files[@]} -eq 0 ]; then
                    echo ""
                    echo "  ${YELLOW}⚠ No hay backups para gestionar${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🔐 Proteger/Desproteger backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local tag="${DIM}(sin protección)${NC}"
                    [ -f "$BACKUP_ROOT/$f.keep" ] && tag="${GREEN}🔒 PROTEGIDO${NC}"
                    echo "    ${GREEN}$i${NC})  $f  $tag"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Número para alternar:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    local target="${files[$((sel-1))]}"
                    if [ -f "$BACKUP_ROOT/$target.keep" ]; then
                        rm -f "$BACKUP_ROOT/$target.keep"
                        echo ""
                        echo "  ${YELLOW}🔓 Backup desprotegido:${NC} $target"
                    else
                        touch "$BACKUP_ROOT/$target.keep"
                        echo ""
                        echo "  ${GREEN}🔒 Backup protegido:${NC} $target"
                    fi
                else
                    echo ""
                    echo "  ${RED}✗ Selección inválida${NC}"
                fi
                pause
                ;;
            5)
                echo ""
                echo "  ${BOLD}${CYAN}🧹 Prune (limpieza)${NC}"
                echo ""
                echo -n "  Mantener cuántos backups (ENTER=${BACKUP_RETENTION}): "
                read -r keep
                [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                echo ""
                prune_backups "$keep"
                pause
                ;;
            6)
                echo ""
                echo "  ${BOLD}${CYAN}⏰ Programar backups automáticos${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                show_current_schedule
                echo "  Selecciona frecuencia:"
                echo ""
                echo "    ${GREEN}1${NC})  Diario"
                echo "    ${GREEN}2${NC})  Semanal"
                echo "    ${GREEN}3${NC})  Mensual"
                echo "    ${RED}0${NC})  Eliminar programación"
                echo ""
                echo -n "  ${CYAN}➤ Opción:${NC} "
                read -r freq_opt

                case "$freq_opt" in
                    1)
                        echo ""
                        echo -n "  Hora (HH:MM): "
                        read -r hhmm
                        echo -n "  Retención (ENTER=${BACKUP_RETENTION}): "
                        read -r keep
                        [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                        schedule_backup "$hhmm" "$keep" "daily"
                        ;;
                    2)
                        echo ""
                        echo "  Día de la semana:"
                        echo "    ${GREEN}0${NC}) Domingo    ${GREEN}1${NC}) Lunes      ${GREEN}2${NC}) Martes"
                        echo "    ${GREEN}3${NC}) Miércoles  ${GREEN}4${NC}) Jueves     ${GREEN}5${NC}) Viernes"
                        echo "    ${GREEN}6${NC}) Sábado"
                        echo ""
                        echo -n "  ${CYAN}➤ Día (0-6):${NC} "
                        read -r dow
                        echo -n "  Hora (HH:MM): "
                        read -r hhmm
                        echo -n "  Retención (ENTER=${BACKUP_RETENTION}): "
                        read -r keep
                        [ -z "$keep" ] && keep="$BACKUP_RETENTION"
                        schedule_backup "$hhmm" "$keep" "weekly" "$dow"
                        ;;
                    3)
                        echo ""
                        echo -n "  Día del mes (1-28): "
                        read -r dom
                        echo -n "  Hora (HH:MM): "
                        read -r hhmm
                        echo -n "  Retención (ENTER=${BACKUP_RETENTION}): "
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
                        echo "  ${RED}✗ Opción inválida${NC}"
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
                    echo "  ${YELLOW}⚠ No hay backups para restaurar${NC}"
                    pause
                    continue
                fi
                echo ""
                echo "  ${BOLD}${CYAN}🔄 Restaurar backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                local i=1
                for f in "${files[@]}"; do
                    local prot=""
                    [ -f "$BACKUP_ROOT/$f.keep" ] && prot=" ${GREEN}🔒 Protegido${NC}"
                    local size
                    size=$(du -h "$BACKUP_ROOT/$f" 2>/dev/null | awk '{print $1}')
                    echo "    ${GREEN}$i${NC})  $f  ${DIM}($size)${NC}$prot"
                    i=$((i+1))
                done
                echo ""
                echo -n "  ${CYAN}➤ Número a restaurar:${NC} "
                read -r sel
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#files[@]} ]; then
                    restore_backup "${files[$((sel-1))]}"
                else
                    echo ""
                    echo "  ${RED}✗ Selección inválida${NC}"
                fi
                pause
                ;;
            9)
                import_backup
                pause
                ;;
            i|I)
                echo ""
                echo "  ${BOLD}${CYAN}ℹ️  Contenido de un backup${NC}"
                echo "  ${DIM}────────────────────────────────────────${NC}"
                echo ""
                echo "  Cada backup (.tar.xz) incluye:"
                echo ""
                echo "    ${WHITE}Configuración:${NC}"
                echo "      • docker-compose.yml  ${DIM}(definición de servicios)${NC}"
                echo "      • .env                ${DIM}(credenciales y variables)${NC}"
                echo ""
                echo "    ${WHITE}Servicios:${NC}"
                echo "      • nginx/              ${DIM}(configuración web server)${NC}"
                echo "      • php/                ${DIM}(configuración PHP-FPM)${NC}"
                echo "      • promtail/           ${DIM}(recolector de logs)${NC}"
                echo "      • loki/               ${DIM}(almacén de logs)${NC}"
                echo ""
                echo "    ${WHITE}Datos:${NC}"
                echo "      • mysql/init/         ${DIM}(scripts SQL iniciales)${NC}"
                echo "      • src/                ${DIM}(código fuente del panel)${NC}"
                echo "      • db/                 ${DIM}(datadir MySQL completo)${NC}"
                echo ""
                echo "    ${WHITE}Metadatos:${NC}"
                echo "      • meta.json           ${DIM}(fecha, host, retención)${NC}"
                echo ""
                echo "  ${DIM}El backup permite restaurar completamente el sistema${NC}"
                echo "  ${DIM}incluyendo usuarios del panel y configuración.${NC}"
                echo ""
                pause
                ;;
            0)
                exit 0
                ;;
            *)
                echo ""
                echo "  ${RED}✗ Opción inválida${NC}"
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
