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
# NOMBRE:       deploy.sh
# VERSIÓN:      2.1.0
# AUTOR:        Equipo ASIR
# LICENCIA:     MIT
#
# DESCRIPCIÓN:
#   Orquesta el despliegue de una infraestructura VPS segura (honeypot)
#   con observabilidad integrada y hardening de seguridad:
#
#   • Instalación de Docker y Docker Compose
#   • Hardening del Firewall (UFW)
#   • Configuración SSH segura (Split Auth: Admin=clave, Honeypot=contraseña)
#   • Configuración WAF (Nginx + ModSecurity)
#   • Pila de Observabilidad (Loki + Promtail)
#   • Fail2Ban con políticas estrictas (35d ban, 2 intentos)
#
# USO:
#   sudo ./deploy.sh
#
# REQUISITOS:
#   • Sistema Operativo: Debian 11+ / Ubuntu 20.04+
#   • Ejecutar como root (sudo)
#   • Conexión a Internet
#
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONSTANTES Y CONFIGURACIÓN
# =============================================================================

readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="ASIR VPS Defense"

# Rutas de estado y logs
readonly ENV_FILE=".env"
readonly STATE_DIR="/var/lib/asir-vps-defense"
readonly LOG_FILE="/var/log/asir-vps-defense/install.log"

# Crear directorios necesarios
mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")"
>"$LOG_FILE"

# =============================================================================
# PALETA DE COLORES ANSI
# =============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'  # Reset / Sin Color

# Símbolos Unicode para mejor UX visual
readonly ICON_OK="✓"
readonly ICON_FAIL="✗"
readonly ICON_WARN="⚠"
readonly ICON_INFO="ℹ"
readonly ICON_ARROW="→"
readonly ICON_LOCK="🔒"
readonly ICON_KEY="🔑"
readonly ICON_FIRE="🔥"
readonly ICON_GEAR="⚙"

# =============================================================================
# MANEJO DE ERRORES
# =============================================================================

trap 'handle_error $LINENO' ERR

handle_error() {
    local line_num="$1"
    echo -e "\n${RED}${ICON_FAIL} [ERROR FATAL]${NC} Fallo inesperado en línea ${BOLD}$line_num${NC}" >&2
    echo -e "${DIM}Últimas 25 líneas del log:${NC}" >&2
    tail -n 25 "$LOG_FILE" >&2
    echo -e "\n${YELLOW}Log completo disponible en:${NC} $LOG_FILE" >&2
    exit 1
}

# =============================================================================
# VARIABLES GLOBALES DE ESTADO
# =============================================================================

# Bandera para conversión diferida del usuario actual a honeypot
CONVERT_CURRENT_USER_TO_HONEYPOT=false
HONEYPOT_TARGET_USER=""
HONEYPOT_TARGET_PASS=""
SECURE_ADMIN=""
CURRENT_REAL_USER=""
CREDENTIALS_MODE="unknown"

# =============================================================================
# FUNCIONES DE LOGGING (UX mejorada)
# =============================================================================

log_info() {
    echo -e "${BLUE}${ICON_INFO}${NC} ${BLUE}[INFO]${NC}    $1"
}

log_success() {
    echo -e "${GREEN}${ICON_OK}${NC} ${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}${ICON_WARN}${NC} ${YELLOW}[WARN]${NC}    $1"
}

log_error() {
    echo -e "${RED}${ICON_FAIL}${NC} ${RED}[ERROR]${NC}   $1"
}

log_step() {
    # Para pasos principales del proceso
    echo -e "\n${CYAN}${ICON_ARROW}${NC} ${BOLD}$1${NC}"
}

# =============================================================================
# SPINNER Y EJECUCIÓN SILENCIOSA
# =============================================================================

run_quiet() {
    local msg="$1"; shift
    local frames=('|' '/' '-' '\')
    local i=0

    "$@" >>"$LOG_FILE" 2>&1 &
    local pid=$!

    # Si el comando no pudo lanzarse, marcamos fallo temprano
    if [ -z "$pid" ]; then
        printf "\r  ${RED}${ICON_FAIL}${NC} %-50s ${RED}[FAIL]${NC}\n" "$msg"
        log_error "No se pudo lanzar el comando: $*"
        return 1
    fi

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}[%s]${NC} %-50s" "${frames[i%4]}" "$msg"
        sleep 0.2
        ((i++))
    done

    # Capturar el status sin que errexit aborte antes de imprimir
    set +e
    wait "$pid"
    local status=$?
    set -e

    if [ $status -eq 0 ]; then
        printf "\r  ${GREEN}${ICON_OK}${NC} %-50s ${GREEN}[OK]${NC}  \n" "$msg"
    else
        printf "\r  ${RED}${ICON_FAIL}${NC} %-50s ${RED}[FAIL]${NC}\n" "$msg"
        echo -e "\n${DIM}Últimas líneas del log:${NC}" >&2
        tail -n 25 "$LOG_FILE" >&2
        return $status
    fi
}

# =============================================================================
# VALIDACIÓN DE PERMISOS
# =============================================================================

check_mode() {
    # Verifica que un archivo/directorio tenga los permisos esperados
    # Uso: check_mode "/ruta/archivo" "600" "descripción opcional"
    local path="$1"
    local expected="$2"
    local label="${3:-$path}"
    
    if [ -e "$path" ]; then
        local mode
        mode=$(stat -c "%a" "$path")
        if [ "$mode" != "$expected" ]; then
            log_warn "Permisos incorrectos en ${label}: modo ${RED}$mode${NC}, esperado ${GREEN}$expected${NC}"
            return 1
        fi
    fi
    return 0
}

# =============================================================================
# GESTIÓN DE CLAVES SSH
# =============================================================================

collect_public_keys_for_user() {
    # Recolecta todas las claves públicas SSH disponibles en el sistema
    local user="$1"
    declare -A seen
    declare -A file_seen
    PUBLIC_KEY_CANDIDATES=()
    local files=()

    log_info "Buscando claves SSH públicas en el sistema..."
    
    # Preferir find para cubrir claves inyectadas por el proveedor; fallback si falta find
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

    # Rutas explícitas clave para asegurar cobertura aunque find estuviera filtrado
    files+=(
        "/home/$user/.ssh/authorized_keys"
        "/home/$CURRENT_REAL_USER/.ssh/authorized_keys"
        "/root/.ssh/authorized_keys"
    )

    # Deduplicar lista de ficheros
    local unique_files=()
    for f in "${files[@]}"; do
        [ -n "$f" ] || continue
        if [ -z "${file_seen[$f]:-}" ]; then
            unique_files+=("$f")
            file_seen[$f]=1
        fi
    done

    # Extraer claves de cada fichero candidato (authorized_keys o *.pub)
    for file in "${unique_files[@]}"; do
        [ -s "$file" ] || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^ssh-(rsa|ed25519|ecdsa) ]] || continue
            if [ -z "${seen[$line]:-}" ]; then
                PUBLIC_KEY_CANDIDATES+=("$line")
                seen[$line]=1
            fi
        done < <(grep -hE '^ssh-(rsa|ed25519|ecdsa)' "$file" 2>/dev/null || cat "$file")
    done
}

choose_public_key_for_user() {
    # Interfaz interactiva para seleccionar una clave pública SSH
    local user="$1"
    local purpose="$2"
    collect_public_keys_for_user "$user"
    local candidates=("${PUBLIC_KEY_CANDIDATES[@]}")

    if [ ${#candidates[@]} -gt 0 ]; then
        echo "" >&2
        echo -e "${CYAN}${ICON_KEY} Se encontraron ${BOLD}${#candidates[@]}${NC}${CYAN} clave(s) SSH para ${BOLD}$user${NC}${CYAN} (${purpose}):${NC}" >&2
        echo "" >&2
        local i=1
        for key in "${candidates[@]}"; do
            # Mostrar tipo de clave y fingerprint parcial para identificación
            local key_type="${key%% *}"
            local key_short="${key:0:50}..."
            echo -e "  ${GREEN}[$i]${NC} ${DIM}${key_type}${NC} ${key_short}" >&2
            ((i++))
        done
        echo "" >&2
        echo -e "  ${YELLOW}[M]${NC} Introducir clave manualmente" >&2
        echo -e "  ${RED}[S]${NC} Salir sin elegir" >&2
        echo "" >&2
        echo -n -e "${CYAN}Selecciona opción: ${NC}" >&2
        read -r choice < /dev/tty

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#candidates[@]} ]; then
            printf '%s' "${candidates[$((choice-1))]}"
            return 0
        elif [[ "$choice" =~ ^[Mm]$ ]]; then
            candidates=()
        elif [[ "$choice" =~ ^[Ss]$ ]]; then
            return 1
        else
            return 1
        fi
    fi

    # Entrada manual (cuando no hay detecciones o se elige M)
    echo "" >&2
    echo -n -e "${CYAN}Pega una clave pública SSH (ssh-rsa/ssh-ed25519) o ENTER para omitir: ${NC}" >&2
    read -r manual < /dev/tty
    if [[ "$manual" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
        printf '%s' "$manual"
        return 0
    fi
    return 1
}

# =============================================================================
# CIFRADO DE CREDENCIALES (age)
# =============================================================================

install_age_if_missing() {
    if command -v age >/dev/null 2>&1; then
        return 0
    fi
    log_info "Instalando 'age' para cifrado de credenciales..."
    if ! run_quiet "Instalando age (cifrado moderno)" apt-get install -y age; then
        log_warn "No se pudo instalar age. Las credenciales se mostrarán en texto plano."
        return 1
    fi
    return 0
}

# =============================================================================
# AUDITORÍA DE PERMISOS
# =============================================================================

audit_permissions() {
    local base="$1"
    local issues=0

    log_info "Ejecutando auditoría de permisos en ${BOLD}$base${NC}"
    echo ""

    # Ficheros de secretos
    echo -e "  ${CYAN}Verificando secretos...${NC}"
    check_mode "$base/.env" 600 ".env" || issues=1
    check_mode "$base/mysql/init" 755 "mysql/init (directorio)" || issues=1
    if find "$base/mysql/init" -type d ! -perm 755 -print -quit | grep -q .; then 
        issues=1
        log_warn "Directorio(s) en mysql/init sin modo 755"
    fi
    if find "$base/mysql/init" -type f ! -perm 644 -print -quit | grep -q .; then 
        issues=1
        log_warn "Ficheros en mysql/init sin modo 644"
    fi

    # Configs PHP y Loki
    echo -e "  ${CYAN}Verificando configuraciones...${NC}"
    check_mode "$base/php/conf.d/custom.ini" 644 "php/conf.d/custom.ini" || issues=1
    check_mode "$base/php/pool.d/www.conf" 644 "php/pool.d/www.conf" || issues=1
    check_mode "$base/loki/config.yml" 644 "loki/config.yml" || issues=1

    # Webroot
    echo -e "  ${CYAN}Verificando webroot...${NC}"
    if find "$base/src" -type d ! -perm 755 -print -quit | grep -q .; then 
        issues=1
        log_warn "Directorios en src sin modo 755"
    fi
    if find "$base/src" -type f ! -perm 644 -print -quit | grep -q .; then 
        issues=1
        log_warn "Ficheros en src sin modo 644"
    fi

    # Credenciales del admin
    echo -e "  ${CYAN}Verificando archivos sensibles...${NC}"
    if [ -f "/home/$SECURE_ADMIN/admin_credentials.txt" ]; then
        check_mode "/home/$SECURE_ADMIN/admin_credentials.txt" 600 "admin_credentials.txt" || issues=1
        log_warn "admin_credentials.txt presente; guarda su contenido y elimínalo del servidor"
    else
        log_info "admin_credentials.txt no encontrado (ya eliminado correctamente)"
    fi

    # SSH del admin
    if [ -d "/home/$SECURE_ADMIN/.ssh" ]; then
        check_mode "/home/$SECURE_ADMIN/.ssh" 700 ".ssh" || issues=1
        check_mode "/home/$SECURE_ADMIN/.ssh/authorized_keys" 600 "authorized_keys" || issues=1
    fi

    echo ""
    if [ $issues -eq 0 ]; then
        log_success "Auditoría completada: ${GREEN}Sin problemas detectados${NC}"
    else
        log_warn "Auditoría completada: ${YELLOW}Se detectaron permisos incorrectos${NC}"
    fi

    return $issues
}

# =============================================================================
# GESTIÓN DE ESTADO (idempotencia)
# =============================================================================

load_env_if_present() {
    # Carga las variables de .env en el entorno actual
    if [ -f .env ]; then
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
# INTERFAZ DE USUARIO
# =============================================================================

print_section() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    printf "${GREEN}║${NC}%*s${BOLD}%s${NC}%*s${GREEN}║${NC}\n" $padding "" "$title" $((width - padding - ${#title})) ""
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
    echo -e "                    ${DIM}Versión ${SCRIPT_VERSION}${NC}"
    echo ""
}

# =============================================================================
# DETECCIÓN DE CONTEXTO
# =============================================================================

detect_context() {
    # Identificar el usuario humano real que ejecuta el script (incluso detrás de sudo)
    if [ -n "$SUDO_USER" ]; then
        CURRENT_REAL_USER="$SUDO_USER"
    else
        CURRENT_REAL_USER=$(whoami)
    fi
    log_info "Usuario real detectado: ${BOLD}$CURRENT_REAL_USER${NC}"
}

# =============================================================================
# VALIDACIONES DEL SISTEMA
# =============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo ""
        log_error "Este script debe ejecutarse como ${BOLD}root${NC}"
        echo ""
        echo -e "  ${CYAN}Uso correcto:${NC}"
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
            log_info "Sistema Operativo: ${BOLD}$OS $VER${NC} ${GREEN}${ICON_OK}${NC}"
        else
            log_error "Sistema Operativo no soportado: ${BOLD}$OS${NC}"
            echo ""
            echo -e "  ${CYAN}Sistemas soportados:${NC}"
            echo -e "    • Debian 11+"
            echo -e "    • Ubuntu 20.04+"
            echo ""
            exit 1
        fi
    else
        log_error "No se puede detectar el Sistema Operativo (/etc/os-release no existe)"
        exit 1
    fi
}

# =============================================================================
# GESTIÓN DE PAQUETES APT
# =============================================================================

wait_for_apt_locks() {
    log_info "Verificando disponibilidad del gestor de paquetes..."
    
    local wait_count=0
    local max_wait=30  # Máximo 5 minutos (30 * 10s)
    
    # Bucle hasta que no haya procesos apt/dpkg ejecutándose
    while pgrep -a apt > /dev/null || pgrep -a apt-get > /dev/null || pgrep -a dpkg > /dev/null; do
        if [ $wait_count -eq 0 ]; then
            log_warn "El sistema está ejecutando actualizaciones automáticas..."
        fi
        printf "\r  ${YELLOW}${ICON_WARN}${NC} Esperando liberación de apt/dpkg... [%02d/%02d]" "$wait_count" "$max_wait"
        sleep 10
        ((wait_count++))
        if [ $wait_count -ge $max_wait ]; then
            echo ""
            log_error "Tiempo de espera excedido. Revisa procesos apt/dpkg manualmente."
            exit 1
        fi
    done
    
    # Doble comprobación de archivos de bloqueo
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        log_warn "Bloqueo de base de datos dpkg detectado. Esperando..."
        sleep 5
    done
    
    if [ $wait_count -gt 0 ]; then
        echo ""
        log_success "Gestor de paquetes disponible"
    fi
}

# =============================================================================
# INSTALACIÓN DE DEPENDENCIAS
# =============================================================================

install_dependencies() {
    wait_for_apt_locks
    
    log_step "Instalando dependencias del sistema"
    
    run_quiet "Actualizando repositorios" apt-get update -y

    # Instalar con reintento y verificación
    if ! run_quiet "Instalando paquetes base (psmisc, curl, git, ufw, fail2ban, rsyslog)" apt-get install -y psmisc curl git ufw fail2ban rsyslog; then
        log_warn "Fallo en la instalación. Reintentando tras espera..."
        wait_for_apt_locks
        run_quiet "Instalando paquetes base (reintento)" apt-get install -y psmisc curl git ufw fail2ban rsyslog
    fi

    # Comprobación crítica: Fail2Ban debe estar presente
    if ! command -v fail2ban-client &> /dev/null; then
        log_error "CRÍTICO: Fail2Ban no se instaló correctamente"
        echo ""
        echo -e "  ${CYAN}Intenta instalarlo manualmente:${NC}"
        echo -e "    ${YELLOW}apt-get install -y fail2ban${NC}"
        echo ""
        exit 1
    fi

    # Asegurar que rsyslog se está ejecutando para que se genere /var/log/auth.log
    if systemctl list-unit-files | grep -q rsyslog.service; then
        systemctl enable --now rsyslog >/dev/null 2>&1 || log_warn "No se pudo iniciar rsyslog automáticamente"
    fi

    # Instalar Docker si no está presente
    if ! command -v docker &> /dev/null; then
        log_step "Instalando Docker (esto puede tardar unos minutos)"
        run_quiet "Descargando e instalando Docker" bash -c 'curl -fsSL https://get.docker.com | sh'
        log_success "Docker instalado correctamente"
    else
        log_info "Docker ya está instalado ${GREEN}${ICON_OK}${NC}"
    fi
}

# =============================================================================
# CIFRADO DE CREDENCIALES
# =============================================================================

encrypt_credentials_file() {
    local cred_file="$1"

    if [ ! -f "$cred_file" ]; then
        log_warn "Archivo de credenciales no encontrado: ${BOLD}$cred_file${NC}"
        CREDENTIALS_MODE="missing"
        return 1
    fi

    echo ""
    echo -e "${CYAN}${ICON_LOCK} Cifrado de credenciales${NC}"
    echo -e "${DIM}Selecciona una clave SSH pública para cifrar las credenciales.${NC}"
    echo -e "${DIM}Solo podrás descifrarlas con la clave privada correspondiente.${NC}"
    echo ""
    
    local selected_key=""
    selected_key=$(choose_public_key_for_user "$SECURE_ADMIN" "cifrar credenciales") || selected_key=""

    if [ -z "$selected_key" ]; then
        log_warn "No se seleccionó clave SSH para cifrado"
        log_info "Las credenciales se mostrarán al final y luego se eliminarán"
        CREDENTIALS_MODE="plain"
        return 1
    fi

    if ! install_age_if_missing; then
        log_warn "Sin herramienta 'age' disponible"
        log_info "Las credenciales se mostrarán al final y luego se eliminarán"
        CREDENTIALS_MODE="plain"
        return 1
    fi

    if age -r "$selected_key" -o "${cred_file}.age" "$cred_file"; then
        chmod 600 "${cred_file}.age"
        chown "$SECURE_ADMIN:$SECURE_ADMIN" "${cred_file}.age"
        shred -u "$cred_file"
        log_success "Credenciales cifradas en ${BOLD}${cred_file}.age${NC}"
        log_info "Archivo de texto plano eliminado de forma segura"
        CREDENTIALS_MODE="encrypted"
        return 0
    else
        log_warn "Falló el cifrado con age"
        CREDENTIALS_MODE="plain"
        return 1
    fi
}

# =============================================================================
# CONFIGURACIÓN DE FIREWALL (UFW)
# =============================================================================

setup_firewall() {
    log_step "Configurando Firewall (UFW)"
    
    ufw default deny incoming
    ufw default allow outgoing
    
    # Solo permitir SSH inicialmente (el puerto se puede cambiar al final del deploy)
    # Los puertos 80/443 no se abren porque el panel solo es accesible por túnel SSH
    ufw allow 22/tcp comment 'SSH'
    
    # Habilitar UFW de forma no interactiva y verificar
    ufw --force enable
    if ufw status | grep -q "Status: active"; then
        log_success "Firewall configurado y activo"
        echo -e "  ${DIM}Política: DENY incoming / ALLOW outgoing${NC}"
        echo -e "  ${DIM}Puerto abierto: 22/tcp (SSH)${NC}"
    else
        log_warn "UFW no quedó activo; revisa configuración"
    fi
}

# =============================================================================
# CONFIGURACIÓN SSH (Split Authentication)
# =============================================================================

configure_ssh() {
    local REAL_USER=$1
    local HONEYPOT_USER=$2

    log_step "Configurando SSH Hardening (Split Authentication)"
    
    # Copia de seguridad de la configuración
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    log_info "Backup de sshd_config creado"

    # Configuración base (segura por defecto)
cat > /etc/ssh/sshd_config <<EOF
# ==============================================================================
# ASIR VPS Defense - SSH Configuration
# Generado el $(date)
# ==============================================================================

# Configuración base
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Hardening extra
MaxAuthTries 1
MaxStartups 5:30:10
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512,hmac-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
LogLevel VERBOSE
UseDNS no

# ==============================================================================
# SPLIT AUTHENTICATION
# Admin real ($REAL_USER): solo clave pública (sin password)
# Resto de usuarios (incluido honeypot): password habilitado para capturar ataques
# ==============================================================================
Match User $REAL_USER
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
EOF

    # Validar sintaxis y reiniciar de forma comprobada
    sshd -t
    systemctl restart sshd
    systemctl is-active --quiet sshd
    
    log_success "SSH configurado con Split Authentication"
    echo -e "  ${DIM}Admin (${BOLD}$REAL_USER${NC}${DIM}): Solo clave pública${NC}"
    echo -e "  ${DIM}Honeypot: Contraseña habilitada (captura ataques)${NC}"
}

# =============================================================================
# CONFIGURACIÓN FAIL2BAN
# =============================================================================

configure_fail2ban() {
    log_step "Configurando Fail2Ban (Protección Activa)"

    systemctl stop fail2ban 2>/dev/null || true

    # Asegurar que auth log existe para que Fail2Ban pueda leerlo
    if [ ! -f /var/log/auth.log ]; then
        touch /var/log/auth.log
        chown syslog:adm /var/log/auth.log 2>/dev/null || true
        chmod 640 /var/log/auth.log
    fi

    # Crear configuración de jaula personalizada
    cat > /etc/fail2ban/jail.local <<EOF
# ==============================================================================
# ASIR VPS Defense - Fail2Ban Configuration
# Generado el $(date)
# ==============================================================================

[DEFAULT]
# Banear hosts por 35 días (política estricta)
bantime = 35d

# Una IP es baneada si ha generado "maxretry" durante el último "findtime"
findtime = 10m

# Número de fallos permitidos antes del ban
maxretry = 2

# Ignorar localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
filter  = sshd
maxretry = 2
EOF

    systemctl restart fail2ban
    systemctl is-active --quiet fail2ban
    systemctl enable fail2ban
    
    log_success "Fail2Ban configurado"
    echo -e "  ${DIM}Política: ${BOLD}35 días${NC}${DIM} de ban tras ${BOLD}2${NC}${DIM} intentos fallidos${NC}"
    echo -e "  ${DIM}Ventana de detección: 10 minutos${NC}"
}

# =============================================================================
# CREACIÓN DEL ADMINISTRADOR SEGURO
# =============================================================================

create_secure_admin() {
    log_step "Creando Administrador Seguro"

    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}${ICON_KEY} CONFIGURACIÓN DEL ADMIN REAL (Tú)${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    echo -n -e "  ${CYAN}Nombre de usuario administrador (ej: sys_ops):${NC} "
    read -r SECURE_ADMIN < /dev/tty

    if [ -z "$SECURE_ADMIN" ]; then
        log_error "El nombre de usuario no puede estar vacío"
        exit 1
    fi

    if id "$SECURE_ADMIN" &>/dev/null; then
        log_warn "El usuario ${BOLD}$SECURE_ADMIN${NC} ya existe. Se reutilizará."
    else
        useradd -m -s /bin/bash "$SECURE_ADMIN"
        usermod -aG sudo,docker "$SECURE_ADMIN"
        log_success "Usuario ${BOLD}$SECURE_ADMIN${NC} creado"
    fi

    # Establecer contraseña para uso de sudo
    echo ""
    echo -e "  ${CYAN}${ICON_LOCK} Configuración de contraseña para SUDO${NC}"
    echo -e "  ${DIM}Aunque el acceso SSH sea por clave, necesitas una contraseña para elevar privilegios.${NC}"
    echo ""
    
    while true; do
        echo -n -e "  ${CYAN}Contraseña sudo:${NC} "
        read -r -s ADMIN_PASS < /dev/tty
        echo ""
        echo -n -e "  ${CYAN}Confirmar contraseña:${NC} "
        read -r -s ADMIN_PASS_CONFIRM < /dev/tty
        echo ""
        
        if [ -n "$ADMIN_PASS" ] && [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]; then
            echo "$SECURE_ADMIN:$ADMIN_PASS" | chpasswd
            log_success "Contraseña establecida para ${BOLD}$SECURE_ADMIN${NC}"
            break
        else
            log_error "Las contraseñas no coinciden o están vacías"
            echo ""
        fi
    done

    # Configurar Clave SSH para Admin Real (obligatorio)
    echo ""
    echo -e "  ${CYAN}${ICON_KEY} Clave SSH del administrador (obligatorio)${NC}"
    echo -e "  ${DIM}Tu cuenta solo podrá acceder mediante clave pública SSH.${NC}"
    echo ""
    
    local SSH_KEY=""
    while true; do
        echo -e "  ${GREEN}[1]${NC} Detectar claves existentes y elegir"
        echo -e "  ${GREEN}[2]${NC} Introducir clave pública manualmente"
        echo ""
        echo -n -e "  ${CYAN}Opción:${NC} "
        read -r key_opt < /dev/tty

        if [ "$key_opt" = "1" ]; then
            SSH_KEY=$(choose_public_key_for_user "$SECURE_ADMIN" "acceso SSH") || SSH_KEY=""
            if [ -n "$SSH_KEY" ]; then
                log_info "Clave seleccionada mediante detección"
                break
            else
                log_warn "No se detectaron claves. Usa la opción 2."
            fi
        elif [ "$key_opt" = "2" ]; then
            echo ""
            echo -n -e "  ${CYAN}Pega tu clave pública (ssh-ed25519/ssh-rsa):${NC} "
            read -r manual_key < /dev/tty
            if [[ "$manual_key" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
                SSH_KEY="$manual_key"
                break
            else
                log_warn "Formato no válido. Debe comenzar con ssh-rsa, ssh-ed25519 o ssh-ecdsa"
            fi
        else
            log_warn "Opción no válida. Elige 1 o 2."
        fi
    done

    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    if grep -qF "$SSH_KEY" "/home/$SECURE_ADMIN/.ssh/authorized_keys" 2>/dev/null; then
        log_info "La clave SSH ya estaba autorizada"
    else
        echo "$SSH_KEY" >> "/home/$SECURE_ADMIN/.ssh/authorized_keys"
        log_success "Clave SSH añadida correctamente"
    fi

    # Asegurar que los permisos son correctos (Paso crítico)
    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    chmod 700 "/home/$SECURE_ADMIN/.ssh"
    if [ -f "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        chmod 600 "/home/$SECURE_ADMIN/.ssh/authorized_keys"
    fi
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "/home/$SECURE_ADMIN/.ssh"
    
    log_success "Configuración SSH verificada para ${BOLD}$SECURE_ADMIN${NC}"

    echo "$SECURE_ADMIN" > "$STATE_DIR/secure_admin"
}

# =============================================================================
# CONFIGURACIÓN DEL HONEYPOT
# =============================================================================

handle_honeypot_logic() {
    log_step "Configurando Usuario Honeypot (Cebo)"

    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}${ICON_FIRE} CONFIGURACIÓN DEL USUARIO CEBO (Honeypot)${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    echo -e "  ${DIM}El honeypot simula un usuario vulnerable para capturar ataques.${NC}"
    echo -e "  ${DIM}Usa nombres comunes como 'admin', 'support', 'user', etc.${NC}"
    echo ""
    echo -n -e "  ${CYAN}Nombre del usuario cebo (ej: admin, support):${NC} "
    read -r HONEYPOT_TARGET_USER < /dev/tty

    if [ -z "$HONEYPOT_TARGET_USER" ]; then
        HONEYPOT_TARGET_USER="admin"
        log_info "Usando nombre por defecto: ${BOLD}admin${NC}"
    fi

    # Comprobar conflicto: ¿Es el usuario real actual el mismo que el usuario honeypot deseado?
    if [ "$CURRENT_REAL_USER" == "$HONEYPOT_TARGET_USER" ]; then
        echo ""
        echo -e "${RED}╭─────────────────────────────────────────────────────────────╮${NC}"
        echo -e "${RED}│${NC}  ${BOLD}${ICON_WARN} ¡CONFLICTO DETECTADO!${NC}                                    ${RED}│${NC}"
        echo -e "${RED}╰─────────────────────────────────────────────────────────────╯${NC}"
        echo ""
        echo -e "  Estás logueado como '${BOLD}$CURRENT_REAL_USER${NC}', pero quieres usar"
        echo -e "  ese mismo nombre como Honeypot."
        echo ""
        echo -e "  ${CYAN}Solución segura:${NC}"
        echo -e "    1. Tu nuevo usuario seguro (${GREEN}$SECURE_ADMIN${NC}) - YA CREADO"
        echo -e "    2. Convertir '${YELLOW}$CURRENT_REAL_USER${NC}' en Honeypot AL FINAL del script"
        echo -e "       (Esto evita cortar tu sesión actual)"
        echo ""
        echo -n -e "  ${CYAN}¿Proceder con conversión diferida? (S/n):${NC} "
        read -r CONFIRM_CONVERSION < /dev/tty
        
        if [[ "$CONFIRM_CONVERSION" =~ ^[Ss]$ ]] || [[ -z "$CONFIRM_CONVERSION" ]]; then
            CONVERT_CURRENT_USER_TO_HONEYPOT=true
            log_warn "Conversión diferida ACTIVADA"
            log_info "'$CURRENT_REAL_USER' se convertirá en Honeypot al finalizar"
        else
            log_error "Operación cancelada. Elige otro nombre para el Honeypot."
            exit 1
        fi
    else
        # Sin conflicto, crear honeypot normalmente si no existe
        if id "$HONEYPOT_TARGET_USER" &>/dev/null; then
            log_warn "El usuario ${BOLD}$HONEYPOT_TARGET_USER${NC} ya existe. Se configurará como Honeypot."
        else
            useradd -m -s /bin/bash "$HONEYPOT_TARGET_USER"
            log_success "Usuario cebo ${BOLD}$HONEYPOT_TARGET_USER${NC} creado"
        fi
    fi

    # Establecer Contraseña del Honeypot
    echo ""
    echo -n -e "  ${CYAN}Contraseña para el Honeypot (ENTER para generar aleatoria):${NC} "
    read -r HONEYPOT_TARGET_PASS < /dev/tty
    
    if [ -z "$HONEYPOT_TARGET_PASS" ]; then
        HONEYPOT_TARGET_PASS=$(openssl rand -base64 12)
        log_info "Contraseña generada para Honeypot: ${BOLD}$HONEYPOT_TARGET_PASS${NC}"
    fi

    # Si NO convertimos el usuario actual, establecer contraseña ahora. 
    # Si convertimos, esperamos hasta el final.
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = false ]; then
        echo "$HONEYPOT_TARGET_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        log_success "Contraseña establecida para ${BOLD}$HONEYPOT_TARGET_USER${NC}"
    fi
}

# =============================================================================
# CONVERSIÓN DIFERIDA DE USUARIO A HONEYPOT
# =============================================================================

finalize_deferred_conversion() {
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = true ]; then
        echo ""
        echo -e "${YELLOW}╭─────────────────────────────────────────────────────────────╮${NC}"
        echo -e "${YELLOW}│${NC}  ${BOLD}${ICON_WARN} EJECUTANDO CONVERSIÓN DIFERIDA${NC}                          ${YELLOW}│${NC}"
        echo -e "${YELLOW}╰─────────────────────────────────────────────────────────────╯${NC}"
        echo ""
        log_info "Convirtiendo '${BOLD}$CURRENT_REAL_USER${NC}' en Honeypot..."

        # 1. Eliminar privilegios sudo del usuario antiguo
        deluser "$CURRENT_REAL_USER" sudo 2>/dev/null || true
        deluser "$CURRENT_REAL_USER" docker 2>/dev/null || true
        
        # 2. Establecer la contraseña del honeypot
        echo "$CURRENT_REAL_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        
        # 3. Desactivar claves SSH para forzar uso de contraseña
        if [ -f "/home/$CURRENT_REAL_USER/.ssh/authorized_keys" ]; then
            mv "/home/$CURRENT_REAL_USER/.ssh/authorized_keys" "/home/$CURRENT_REAL_USER/.ssh/authorized_keys.bak_conversion"
            log_info "Claves SSH de '$CURRENT_REAL_USER' desactivadas (backup creado)"
        fi

        log_success "Conversión completada"
        echo ""
        echo -e "${RED}╭─────────────────────────────────────────────────────────────╮${NC}"
        echo -e "${RED}│${NC}  ${BOLD}⚠ ATENCIÓN${NC}                                                 ${RED}│${NC}"
        echo -e "${RED}╰─────────────────────────────────────────────────────────────╯${NC}"
        echo ""
        echo -e "  Tu sesión actual sigue activa, pero si te desconectas,"
        echo -e "  ${RED}NO podrás volver a entrar como '$CURRENT_REAL_USER'${NC}"
        echo ""
        echo -e "  Debes usar el nuevo usuario seguro: ${GREEN}${BOLD}$SECURE_ADMIN${NC}"
        echo ""
    fi
}

# =============================================================================
# GENERACIÓN DE ARCHIVO .ENV
# =============================================================================

generate_env() {
    log_step "Generando secretos y configuración (.env)"
    
    echo ""
    echo -n -e "  ${CYAN}Dominio del VPS (o IP pública si no tienes dominio):${NC} "
    read -r DOMAIN_NAME < /dev/tty

    if [ -z "${DOMAIN_NAME}" ]; then
        log_error "El dominio/IP no puede estar vacío"
        exit 1
    fi
    if echo "${DOMAIN_NAME}" | grep -q ' '; then
        log_error "El dominio/IP no debe contener espacios"
        exit 1
    fi
    
    # Generar contraseñas aleatorias
    MYSQL_ROOT_PASS=$(openssl rand -base64 24)
    MYSQL_APP_PASS=$(openssl rand -base64 24)
    
    cat > .env <<EOF
# ==============================================================================
# ASIR VPS Defense - Variables de Entorno
# Generado el $(date)
# ==============================================================================

# Dominio/IP del servidor
DOMAIN_NAME=$DOMAIN_NAME

# Credenciales MySQL (generadas automáticamente)
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASS
MYSQL_DATABASE=asir_defense
MYSQL_USER=app_user
MYSQL_PASSWORD=$MYSQL_APP_PASS

# Configuración de Red Docker
FRONTEND_SUBNET=172.20.0.0/16
BACKEND_SUBNET=172.21.0.0/16

# GeoIP (opcional)
GEOIP_LICENSE_KEY=
EOF

    chmod 600 .env
    log_success "Archivo .env generado con credenciales seguras"
}

# =============================================================================
# DESCARGA DE BASE DE DATOS GEOLITE2
# =============================================================================

download_geolite_mmdb() {
    # Descarga la base GeoLite2-City desde el CDN libre (jsDelivr)
    local url="https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p geoip

    log_step "Descargando base de datos GeoLite2-City"
    log_info "Fuente: jsDelivr CDN (sin API key necesaria)"
    
    if ! curl -fsSL "$url" -o "$tmpdir/GeoLite2-City.mmdb.gz"; then
        log_warn "No se pudo descargar GeoLite2 desde el CDN"
        log_info "Se usará fallback de país (funcionalidad reducida)"
        rm -rf "$tmpdir"
        return 0
    fi

    if ! gunzip -c "$tmpdir/GeoLite2-City.mmdb.gz" > geoip/GeoLite2-City.mmdb; then
        log_warn "No se pudo descomprimir GeoLite2"
        log_info "Se usará fallback de país"
        rm -rf "$tmpdir"
        return 0
    fi

    chmod 644 geoip/GeoLite2-City.mmdb
    log_success "Base GeoLite2-City descargada: ${BOLD}geoip/GeoLite2-City.mmdb${NC}"
    rm -rf "$tmpdir"
}

# =============================================================================
# GENERACIÓN DE SEMILLA DE BASE DE DATOS
# =============================================================================

generate_db_seed() {
    log_step "Generando credenciales para el Panel de Administración"
    
    WEB_ADMIN_PASS=$(openssl rand -base64 12)
    
    # Usar un contenedor PHP temporal para generar el hash Bcrypt
    log_info "Calculando hash de contraseña seguro (bcrypt)..."
    set +e
    WEB_ADMIN_HASH=$(docker run --rm php:8.2-cli php -r "echo password_hash('$WEB_ADMIN_PASS', PASSWORD_DEFAULT);" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local hash_status=$?
    set -e
    if [ $hash_status -ne 0 ] || [ -z "$WEB_ADMIN_HASH" ]; then
        log_error "No se pudo generar el hash de la contraseña"
        echo ""
        echo -e "  ${CYAN}Revisa el log para más detalles:${NC}"
        echo -e "    ${YELLOW}tail -n 25 $LOG_FILE${NC}"
        echo ""
        tail -n 25 "$LOG_FILE" >&2
        exit 1
    fi
    
    cat > mysql/init/02-seed.sql <<EOF
-- ==============================================================================
-- ASIR VPS Defense - Archivo semilla
-- Generado por deploy.sh el $(date)
-- ==============================================================================

INSERT INTO users (username, password_hash, role) VALUES 
('admin', '$WEB_ADMIN_HASH', 'admin');
EOF
    
    # Guardar credenciales en un archivo seguro para el usuario
    local CRED_FILE="/home/$SECURE_ADMIN/admin_credentials.txt"
    
    cat > "$CRED_FILE" <<EOF
╔══════════════════════════════════════════════════════════════╗
║         ASIR VPS DEFENSE - CREDENCIALES DE ACCESO            ║
╚══════════════════════════════════════════════════════════════╝

Generado el: $(date)

┌──────────────────────────────────────────────────────────────┐
│ PANEL DE ADMINISTRACIÓN                                      │
├──────────────────────────────────────────────────────────────┤
│ URL:        http://localhost:8888 (Requiere Túnel SSH)       │
│ Usuario:    admin                                            │
│ Contraseña: $WEB_ADMIN_PASS
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ BASE DE DATOS                                                │
├──────────────────────────────────────────────────────────────┤
│ Root Password:     $MYSQL_ROOT_PASS
│ App User Password: $MYSQL_APP_PASS
└──────────────────────────────────────────────────────────────┘

NOTA: Este archivo es propiedad de $SECURE_ADMIN (modo 600).
      Guarda estas credenciales y elimina este archivo.
EOF
    
    # Asegurar el archivo
    chown "$SECURE_ADMIN:$SECURE_ADMIN" "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    log_success "Semilla de base de datos generada: ${BOLD}mysql/init/02-seed.sql${NC}"
    log_success "Credenciales guardadas en: ${BOLD}$CRED_FILE${NC}"
    
    if encrypt_credentials_file "$CRED_FILE"; then
        log_info "Credenciales cifradas. Podrás verlas o descargarlas al final."
    else
        CREDENTIALS_MODE="plain"
        log_warn "Credenciales sin cifrar; se mostrarán al final y se eliminarán"
    fi
}

# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================

main() {
    clear
    print_banner
    print_section "INSTALADOR v${SCRIPT_VERSION}"
    
    check_root
    detect_context
    detect_os

    # Recuperar usuario admin seguro de ejecuciones previas (si existe)
    if [ -z "$SECURE_ADMIN" ] && [ -f "$STATE_DIR/secure_admin" ]; then
        SECURE_ADMIN=$(cat "$STATE_DIR/secure_admin")
        log_info "Usuario admin recuperado de sesión anterior: ${BOLD}$SECURE_ADMIN${NC}"
    fi

    # Si todo ya estuvo completado, permitir una ejecución de auditoría rápida y salir
    if is_step_done "prep_done" && is_step_done "users_done" && is_step_done "project_done" \
       && is_step_done "env_done" && is_step_done "seed_done" && is_step_done "final_done"; then
        local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
        if [ -d "$PROJECT_DIR" ]; then
            cd "$PROJECT_DIR" || exit 1
            load_env_if_present
            print_section "AUDITORÍA DE PERMISOS"
            log_info "Instalación completa detectada. Ejecutando solo auditoría..."
            audit_permissions "$PROJECT_DIR"
            exit 0
        fi
    fi
    
    # =========================================================================
    # PASO 1: Preparación del Sistema
    # =========================================================================
    print_section "PASO 1/5: PREPARACIÓN DEL SISTEMA"
    if is_step_done "prep_done"; then
        log_info "Preparación previa detectada ${GREEN}${ICON_OK}${NC}"
        log_info "Saltando reinstalación de dependencias y firewall"
    else
        install_dependencies
        setup_firewall
        mark_step_done "prep_done"
    fi
    
    # =========================================================================
    # PASO 2: Configuración de Usuario y Seguridad
    # =========================================================================
    print_section "PASO 2/5: USUARIOS Y SEGURIDAD"
    if is_step_done "users_done"; then
        log_info "Usuarios y seguridad ya configurados ${GREEN}${ICON_OK}${NC}"
        if [ -z "$SECURE_ADMIN" ]; then
            log_error "No se pudo recuperar SECURE_ADMIN del estado previo"
            echo ""
            echo -e "  ${CYAN}Para rehacer este paso, elimina el archivo de estado:${NC}"
            echo -e "    ${YELLOW}rm -f $STATE_DIR/users_done${NC}"
            echo ""
            exit 1
        fi
    else
        create_secure_admin
        handle_honeypot_logic
        configure_ssh "$SECURE_ADMIN" "$HONEYPOT_TARGET_USER"
        configure_fail2ban
        mark_step_done "users_done"
    fi
    
    # =========================================================================
    # PASO 3: Configuración del Proyecto
    # =========================================================================
    print_section "PASO 3/5: PROVISIONADO DEL PROYECTO"
    local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
    log_info "Directorio del proyecto: ${BOLD}$PROJECT_DIR${NC}"

    if is_step_done "project_done"; then
        log_info "Proyecto ya presente ${GREEN}${ICON_OK}${NC}"
        cd "$PROJECT_DIR" || exit 1
    else
        # Crear directorio si no existe
        if [ ! -d "$PROJECT_DIR" ]; then
            mkdir -p "$PROJECT_DIR"
        fi

        # Lógica para poblar el directorio
        if [ -f "docker-compose.yml" ]; then
            log_info "Copiando archivos de instalación locales..."
            rsync -av --exclude ".git" --exclude "asir-vps-defense" . "$PROJECT_DIR/" 2>/dev/null || cp -R . "$PROJECT_DIR/"
        else
            log_info "Descargando repositorio oficial..."
            rm -rf "$PROJECT_DIR"
            git clone https://github.com/paulusgi/asir-vps-defense.git "$PROJECT_DIR"
        fi

        # Asegurar que la propiedad es correcta inmediatamente
        chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "$PROJECT_DIR"
        cd "$PROJECT_DIR" || exit 1
        mark_step_done "project_done"
        log_success "Directorio de trabajo: ${BOLD}$(pwd)${NC}"
    fi

    # =========================================================================
    # PASO 4: Despliegue de la Aplicación
    # =========================================================================
    print_section "PASO 4/5: DESPLIEGUE DE LA APLICACIÓN"
    if is_step_done "env_done"; then
        log_info "Archivo .env ya existe ${GREEN}${ICON_OK}${NC}"
        log_info "No se regenera para preservar credenciales"
        load_env_if_present
    else
        generate_env
        load_env_if_present
        mark_step_done "env_done"
    fi

    # Descarga GeoLite2-City desde CDN (sin requerir License Key)
    download_geolite_mmdb

    # Asegurar que el directorio de posiciones de Promtail existe y es escribible
    log_info "Preparando directorio de posiciones de Promtail..."
    mkdir -p "$PROJECT_DIR/promtail/positions"
    # Promtail corre como nobody (65534) en la imagen oficial
    chown -R 65534:65534 "$PROJECT_DIR/promtail/positions" 2>/dev/null || chmod 777 "$PROJECT_DIR/promtail/positions"
    touch "$PROJECT_DIR/promtail/positions/positions.yaml"
    chown 65534:65534 "$PROJECT_DIR/promtail/positions/positions.yaml" 2>/dev/null || chmod 666 "$PROJECT_DIR/promtail/positions/positions.yaml"

    if is_step_done "seed_done"; then
        log_info "Semilla de base de datos ya generada ${GREEN}${ICON_OK}${NC}"
    else
        generate_db_seed
        mark_step_done "seed_done"
    fi
    
    # Corregir permisos para secretos generados
    chown "$SECURE_ADMIN:$SECURE_ADMIN" .env
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" mysql/init

    # Corregir permisos para webroot
    log_info "Ajustando permisos de archivos web..."
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" src

    log_step "Desplegando contenedores Docker (esto puede tardar varios minutos)"
    set +e
    run_quiet "Construyendo y levantando contenedores" docker compose up -d --build
    local up_status=$?
    set -e

    if [ $up_status -ne 0 ]; then
        log_error "docker compose up falló"
        echo ""
        echo -e "  ${CYAN}Mostrando logs de diagnóstico (MySQL):${NC}"
        docker compose logs --tail=60 mysql || true
        echo ""
        echo -e "  ${CYAN}Si ves errores de autenticación/root password, ejecuta:${NC}"
        echo -e "    ${YELLOW}docker compose down -v${NC}"
        echo -e "    ${YELLOW}rm -f $STATE_DIR/env_done $STATE_DIR/seed_done${NC}"
        echo -e "    ${YELLOW}./deploy.sh${NC}"
        echo ""
        exit 1
    fi
    
    # =========================================================================
    # PASO 5: Limpieza Final y Acciones Diferidas
    # =========================================================================
    print_section "PASO 5/5: AJUSTES FINALES"
    if is_step_done "final_done"; then
        log_info "Acciones finales ya aplicadas ${GREEN}${ICON_OK}${NC}"
    else
        finalize_deferred_conversion
        mark_step_done "final_done"
    fi
    history -c
    
    # =========================================================================
    # RESUMEN Y VERIFICACIÓN
    # =========================================================================
    print_section "INSTALACIÓN FINALIZADA"
    
    echo ""
    echo -e "${YELLOW}Por favor, revisa los mensajes anteriores en busca de errores (texto rojo).${NC}"
    echo ""
    echo -n -e "Presiona ${BOLD}ENTER${NC} para continuar con la verificación de estado..."
    read -r _ < /dev/tty
    
    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}${ICON_GEAR} ESTADO DE LOS SERVICIOS${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    
    log_info "Esperando a que los servicios estén listos (30-60s)..."
    
    # 1. Esperar al Healthcheck de MySQL
    local retries=0
    while [ $retries -lt 30 ]; do
        if docker compose ps | grep -q "healthy"; then
             break
        fi
        printf "\r  ${CYAN}⏳${NC} Esperando healthchecks... [%02d/30]" "$retries"
        sleep 2
        ((retries++))
    done
    echo ""

    # 2. Verificar Puerto del Panel de Administración (8888)
    log_info "Verificando disponibilidad del Panel de Administración..."
    local port_ready=false
    retries=0
    while [ $retries -lt 20 ]; do
        if curl -s -I http://127.0.0.1:8888 >/dev/null; then
            port_ready=true
            log_success "Panel de Administración ${GREEN}ONLINE${NC} en puerto 8888"
            break
        fi
        printf "\r  ${CYAN}⏳${NC} Esperando respuesta HTTP... [%02d/20]" "$retries"
        sleep 3
        ((retries++))
    done
    echo ""

    if [ "$port_ready" = false ]; then
        log_error "El servicio en el puerto 8888 no responde"
        echo ""
        echo -e "  ${CYAN}Puede que los contenedores sigan iniciándose.${NC}"
        echo -e "  ${CYAN}Revisa los logs con:${NC} ${YELLOW}docker compose logs -f${NC}"
        echo ""
    fi

    echo ""
    echo -e "  ${DIM}Estado actual de los contenedores:${NC}"
    docker compose ps
    
    # =========================================================================
    # GESTIÓN DE CREDENCIALES
    # =========================================================================
    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}${ICON_LOCK} GESTIÓN DE CREDENCIALES${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    
    local CRED_PLAIN="/home/$SECURE_ADMIN/admin_credentials.txt"
    local CRED_ENC="${CRED_PLAIN}.age"
    local HOST_HINT="${DOMAIN_NAME:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

    if [ -f "$CRED_ENC" ]; then
        while true; do
            echo -e "  Archivo cifrado: ${BOLD}$CRED_ENC${NC}"
            echo ""
            echo -e "  ${GREEN}[1]${NC} Mostrar credenciales en pantalla (texto plano temporal)"
            echo -e "  ${GREEN}[2]${NC} Ver comando para descargar el archivo cifrado"
            echo -e "  ${GREEN}[3]${NC} Continuar sin mostrar credenciales"
            echo ""
            echo -n -e "  ${CYAN}Opción (1/2/3):${NC} "
            read -r CRED_CHOICE < /dev/tty

            case "$CRED_CHOICE" in
                1)
                    echo ""
                    echo -e "  ${YELLOW}Credenciales (no se guardan en disco):${NC}"
                    echo -e "    • Panel Web → usuario: ${GREEN}admin${NC} | contraseña: ${GREEN}$WEB_ADMIN_PASS${NC}"
                    echo -e "    • DB root   → ${GREEN}$MYSQL_ROOT_PASS${NC}"
                    echo -e "    • DB app    → ${GREEN}$MYSQL_APP_PASS${NC}"
                    echo ""
                    ;;
                2)
                    echo ""
                    echo -e "  ${CYAN}Ejecuta en tu máquina local para descargar:${NC}"
                    echo ""
                    echo -e "    ${YELLOW}scp $SECURE_ADMIN@${HOST_HINT:-<dominio_o_ip>}:$CRED_ENC ./admin_credentials.txt.age${NC}"
                    echo ""
                    echo -e "  ${CYAN}Luego descifra con tu clave privada:${NC}"
                    echo ""
                    echo -e "    ${YELLOW}age -d -i ~/.ssh/<tu_clave> -o admin_credentials.txt ./admin_credentials.txt.age${NC}"
                    echo ""
                    ;;
                3)
                    log_info "Continuando sin mostrar credenciales"
                    break
                    ;;
                *)
                    log_warn "Opción no válida. Elige 1, 2 o 3."
                    ;;
            esac
        done
    elif [ -f "$CRED_PLAIN" ]; then
        echo -e "${RED}${ICON_WARN} ATENCIÓN: Credenciales sin cifrar${NC}"
        echo -e "  Se mostrarán ${BOLD}UNA sola vez${NC} y el archivo se eliminará."
        echo ""
        cat "$CRED_PLAIN"
        shred -u "$CRED_PLAIN"
        echo ""
        log_success "Archivo de credenciales eliminado de forma segura"
    else
        log_info "El archivo de credenciales ya no está presente"
    fi

    unset WEB_ADMIN_PASS

    # =========================================================================
    # CAMBIO DE PUERTO SSH
    # =========================================================================
    echo ""
    echo -e "${CYAN}╭─────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}${ICON_LOCK} CAMBIO DE PUERTO SSH (PASO FINAL)${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}╰─────────────────────────────────────────────────────────────╯${NC}"
    echo ""
    
    local NEW_SSH_PORT=""
    local EFFECTIVE_SSH_PORT="22"
    echo -n -e "  ${CYAN}Nuevo puerto SSH (ENTER para usar 2929):${NC} "
    read -r NEW_SSH_PORT < /dev/tty
    if [ -z "$NEW_SSH_PORT" ]; then
        NEW_SSH_PORT="2929"
    fi
    if ! [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_SSH_PORT" -lt 1 ] || [ "$NEW_SSH_PORT" -gt 65535 ]; then
        log_error "Puerto no válido. Se mantiene el puerto 22."
        EFFECTIVE_SSH_PORT="22"
    else
        log_info "Aplicando puerto SSH ${BOLD}$NEW_SSH_PORT${NC}..."
        sed -i "s/^Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
        ufw allow "$NEW_SSH_PORT"/tcp comment 'SSH custom' || log_warn "No se pudo abrir el puerto $NEW_SSH_PORT en UFW"
        ufw delete allow 22/tcp >/dev/null 2>&1 || true
        if sshd -t && systemctl restart sshd; then
            log_success "sshd reiniciado en puerto ${BOLD}$NEW_SSH_PORT${NC}"
            EFFECTIVE_SSH_PORT="$NEW_SSH_PORT"
        else
            log_error "No se pudo reiniciar sshd; se mantiene puerto 22"
            EFFECTIVE_SSH_PORT="22"
        fi
    fi

    # =========================================================================
    # INSTRUCCIONES FINALES
    # =========================================================================
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}${ICON_OK} INSTRUCCIONES DE CONEXIÓN${NC}                                 ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}1.${NC} Abre una ${BOLD}NUEVA terminal${NC} en tu ordenador local"
    echo ""
    echo -e "  ${CYAN}2.${NC} Ejecuta el siguiente comando para crear el túnel seguro:"
    echo ""
    echo -e "     ${YELLOW}ssh -p $EFFECTIVE_SSH_PORT -L 8888:127.0.0.1:8888 $SECURE_ADMIN@$DOMAIN_NAME${NC}"
    echo ""
    echo -e "  ${CYAN}3.${NC} Abre tu navegador web y accede a:"
    echo ""
    echo -e "     Panel de Administración: ${GREEN}http://localhost:8888${NC}"
    echo ""
    echo -e "  ${DIM}Si recibes 'Connection Refused', espera unos segundos a que${NC}"
    echo -e "  ${DIM}los contenedores terminen de arrancar.${NC}"
    echo ""

    echo -e "${DIM}Log detallado: ${LOG_FILE}${NC}"
    echo ""
    echo -n -e "Pulsa ${BOLD}ENTER${NC} para borrar el log y salir (escribe '${YELLOW}No${NC}' para conservarlo): "
    read -r CLEAN_LOG < /dev/tty
    if [[ "$CLEAN_LOG" =~ ^[Nn][Oo]$ ]]; then
        log_info "Log conservado en $LOG_FILE"
    else
        rm -f "$LOG_FILE" && log_info "Log eliminado"
    fi

    # =========================================================================
    # LIMPIEZA DE VARIABLES SENSIBLES
    # =========================================================================
    echo ""
    log_info "Limpiando variables sensibles del entorno..."
    unset MYSQL_ROOT_PASS MYSQL_APP_PASS WEB_ADMIN_PASS WEB_ADMIN_HASH ADMIN_PASS ADMIN_PASS_CONFIRM \
        HONEYPOT_TARGET_PASS SSH_KEY CREDENTIALS_MODE DOMAIN_NAME HOST_HINT EFFECTIVE_SSH_PORT NEW_SSH_PORT

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   ${ICON_OK} INSTALACIÓN COMPLETADA EXITOSAMENTE${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
