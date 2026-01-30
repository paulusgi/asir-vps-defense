#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
# ============================================================================== 
# ASIR VPS Defense - Script de Despliegue Automatizado
# ==============================================================================
# Autor: Equipo ASIR
# Descripción:
#   Orquesta el despliegue de una infraestructura VPS segura incluyendo:
#   - Instalación de Docker y Docker Compose
#   - Hardening del Firewall (UFW)
#   - Configuración SSH segura (Split Auth: Admin solo clave vs Honeypot contraseña)
#   - Configuración WAF (Nginx + ModSecurity)
#   - Pila de Observabilidad (Loki + Promtail)
#   sudo ./deploy.sh
# ==============================================================================

ENV_FILE=".env"
STATE_DIR="/var/lib/asir-vps-defense"
LOG_FILE="/var/log/asir-vps-defense/install.log"
mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")"
>"$LOG_FILE"

# Colores para la salida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin Color

trap 'echo "[ERROR] Fallo en línea $LINENO" >&2; tail -n 25 "$LOG_FILE" >&2' ERR

# Bandera global para rastrear si necesitamos convertir el usuario actual más tarde
CONVERT_CURRENT_USER_TO_HONEYPOT=false
HONEYPOT_TARGET_USER=""
HONEYPOT_TARGET_PASS=""
SECURE_ADMIN=""
CURRENT_REAL_USER=""
CREDENTIALS_MODE="unknown"

# ==============================================================================
# Funciones Auxiliares
# ==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_quiet() {
    local msg="$1"; shift
    local frames='|/-\\'
    local i=0

    "$@" >>"$LOG_FILE" 2>&1 &
    local pid=$!

    # Si el comando no pudo lanzarse, marcamos fallo temprano
    if [ -z "$pid" ]; then
        printf "\r%-55s [FAIL]\n" "$msg"
        log_error "No se pudo lanzar el comando: $*"
        return 1
    fi

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r%-55s [%c]" "$msg" "${frames:i++%4:1}"
        sleep 0.2
    done

    # Capturar el status aunque falle sin que errexit aborte antes de imprimir el log
    set +e
    wait "$pid"
    local status=$?
    set -e

    if [ $status -eq 0 ]; then
        printf "\r%-55s [OK ]\n" "$msg"
    else
        printf "\r%-55s [FAIL]\n" "$msg"
        tail -n 25 "$LOG_FILE" >&2
        return $status
    fi
}

check_mode() {
    # $1 path, $2 expected mode
    local path="$1"; local expected="$2"; local label="$3"
    if [ -e "$path" ]; then
        local mode
        mode=$(stat -c "%a" "$path")
        if [ "$mode" != "$expected" ]; then
            log_warn "Permisos inesperados en ${label:-$path} (modo $mode, esperado $expected)."
            return 1
        fi
    fi
    return 0
}

collect_public_keys_for_user() {
    local user="$1"
    declare -A seen
    declare -A file_seen
    PUBLIC_KEY_CANDIDATES=()
    local files=()

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
    local user="$1"
    local purpose="$2"
    collect_public_keys_for_user "$user"
    local candidates=("${PUBLIC_KEY_CANDIDATES[@]}")

    if [ ${#candidates[@]} -gt 0 ]; then
        echo "Se detectaron ${#candidates[@]} claves públicas para $user ($purpose). Elige una o introduce otra:" >&2
        local i=1
        for key in "${candidates[@]}"; do
            echo "  [$i] ${key:0:60}..." >&2
            ((i++))
        done
        echo "  [M] Introducir manualmente" >&2
        echo "  [S] Volver sin elegir" >&2
        echo -n "Selecciona opción: " >&2
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
    echo -n "Pega una clave pública SSH (ssh-rsa/ssh-ed25519) o deja vacío para omitir: " >&2
    read -r manual < /dev/tty
    if [[ "$manual" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
        printf '%s' "$manual"
        return 0
    fi
    return 1
}

install_age_if_missing() {
    if command -v age >/dev/null 2>&1; then
        return 0
    fi
    log_info "Instalando age para cifrar credenciales..."
    if ! run_quiet "Instalando age" apt-get install -y age; then
        log_warn "No se pudo instalar age. Se omite el cifrado y se mostrarán credenciales para que las guardes manualmente."
        return 1
    fi
    return 0
}

audit_permissions() {
    local base="$1"
    local issues=0

    log_info "Auditando permisos en $base"

    # Ficheros de secretos
    check_mode "$base/.env" 600 ".env" || issues=1
    check_mode "$base/mysql/init" 755 "mysql/init (directorio)" || issues=1
    if find "$base/mysql/init" -type d ! -perm 755 -print -quit | grep -q .; then issues=1; log_warn "Directorio(s) en mysql/init sin modo 755"; fi
    if find "$base/mysql/init" -type f ! -perm 644 -print -quit | grep -q .; then issues=1; log_warn "Ficheros en mysql/init sin modo 644"; fi

    # Configs PHP y Loki
    check_mode "$base/php/conf.d/custom.ini" 644 "php/conf.d/custom.ini" || issues=1
    check_mode "$base/php/pool.d/www.conf" 644 "php/pool.d/www.conf" || issues=1
    check_mode "$base/loki/config.yml" 644 "loki/config.yml" || issues=1

    # Webroot
    if find "$base/src" -type d ! -perm 755 -print -quit | grep -q .; then issues=1; log_warn "Directorios en src sin modo 755"; fi
    if find "$base/src" -type f ! -perm 644 -print -quit | grep -q .; then issues=1; log_warn "Ficheros en src sin modo 644"; fi

    # Credenciales del admin
    if [ -f "/home/$SECURE_ADMIN/admin_credentials.txt" ]; then
        check_mode "/home/$SECURE_ADMIN/admin_credentials.txt" 600 "admin_credentials.txt" || issues=1
        log_warn "admin_credentials.txt presente; guarda su contenido en un lugar seguro y bórralo del servidor si ya no lo necesitas."
    else
        log_info "admin_credentials.txt no encontrado (posiblemente ya retirado)."
    fi

    # SSH del admin
    if [ -d "/home/$SECURE_ADMIN/.ssh" ]; then
        check_mode "/home/$SECURE_ADMIN/.ssh" 700 ".ssh" || issues=1
        check_mode "/home/$SECURE_ADMIN/.ssh/authorized_keys" 600 "authorized_keys" || issues=1
    fi

    if [ $issues -eq 0 ]; then
        log_success "Permisos verificados: OK."
    else
        log_warn "Se detectaron permisos distintos a lo esperado; revisa y corrige según corresponda."
    fi

    return $issues
}

load_env_if_present() {
    # Carga las variables de .env en el entorno actual
    if [ -f .env ]; then
        set -a
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

print_section() {
    local title="$1"
    local line="=================================================="
    echo -e "${GREEN}${line}${NC}"
    printf "${GREEN}   %-46s${NC}\n" "$title"
    echo -e "${GREEN}${line}${NC}"
}

detect_context() {
    # Identificar el usuario humano real que ejecuta el script (incluso detrás de sudo)
    if [ -n "$SUDO_USER" ]; then
        CURRENT_REAL_USER="$SUDO_USER"
    else
        CURRENT_REAL_USER=$(whoami)
    fi
    log_info "Contexto de ejecución: Usuario real detectado -> $CURRENT_REAL_USER"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script debe ejecutarse como root (sudo)."
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        if [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
            log_info "Sistema Operativo detectado: $OS $VER"
        else
            log_error "Sistema Operativo no soportado. Se requiere Debian o Ubuntu."
            exit 1
        fi
    else
        log_error "No se puede detectar el Sistema Operativo."
        exit 1
    fi
}

wait_for_apt_locks() {
    log_info "Verificando si el gestor de paquetes está ocupado..."
    
    # Bucle hasta que no haya procesos apt/dpkg ejecutándose
    while pgrep -a apt > /dev/null || pgrep -a apt-get > /dev/null || pgrep -a dpkg > /dev/null; do
        log_warn "El sistema está instalando actualizaciones automáticas en segundo plano. Esperando..."
        sleep 10
    done
    
    # Doble comprobación de archivos de bloqueo
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        log_warn "Bloqueo de base de datos dpkg detectado. Esperando..."
        sleep 5
    done
}

install_dependencies() {
    wait_for_apt_locks
    run_quiet "Actualizando repositorios" apt-get update -y

    # Instalar con reintento y verificación
    if ! run_quiet "Instalando paquetes base" apt-get install -y psmisc curl git ufw fail2ban rsyslog; then
        log_warn "Fallo en la instalación de paquetes. Reintentando tras espera..."
        wait_for_apt_locks
        run_quiet "Instalando paquetes base (reintento)" apt-get install -y psmisc curl git ufw fail2ban rsyslog
    fi

    # Comprobación crítica: Fail2Ban debe estar presente
    if ! command -v fail2ban-client &> /dev/null; then
        log_error "CRÍTICO: Fail2Ban no se instaló correctamente. Abortando para seguridad."
        log_info "Intenta ejecutar manualmente: apt-get install -y fail2ban"
        exit 1
    fi

    # Asegurar que rsyslog se está ejecutando para que se genere /var/log/auth.log
    if systemctl list-unit-files | grep -q rsyslog.service; then
        systemctl enable --now rsyslog >/dev/null 2>&1 || log_warn "No se pudo iniciar rsyslog automáticamente."
    fi

    # Instalar Docker si no está presente
    if ! command -v docker &> /dev/null; then
        run_quiet "Instalando Docker" bash -c 'curl -fsSL https://get.docker.com | sh'
        log_success "Docker instalado correctamente."
    else
        log_info "Docker ya está instalado."
    fi
}

encrypt_credentials_file() {
    local cred_file="$1"

    if [ ! -f "$cred_file" ]; then
        log_warn "Archivo de credenciales no encontrado para cifrar ($cred_file)."
        CREDENTIALS_MODE="missing"
        return 1
    fi

    local selected_key=""
    selected_key=$(choose_public_key_for_user "$SECURE_ADMIN" "cifrar credenciales") || selected_key=""

    if [ -z "$selected_key" ]; then
        log_warn "No se seleccionó clave SSH para cifrado. Se mantendrá el archivo plano para mostrarlo al final y luego se borrará."
        CREDENTIALS_MODE="plain"
        return 1
    fi

    if ! install_age_if_missing; then
        log_warn "Sin age disponible. Se mantendrá el archivo plano para mostrarlo al final y luego se borrará."
        CREDENTIALS_MODE="plain"
        return 1
    fi

    if age -r "$selected_key" -o "${cred_file}.age" "$cred_file"; then
        chmod 600 "${cred_file}.age"
        chown "$SECURE_ADMIN:$SECURE_ADMIN" "${cred_file}.age"
        shred -u "$cred_file"
        log_success "Credenciales cifradas en ${cred_file}.age. Sólo la clave privada asociada puede descifrarlas."
        CREDENTIALS_MODE="encrypted"
        return 0
    else
        log_warn "Falló el cifrado con age. Se mantendrá el archivo plano para mostrarlo al final y luego se borrará."
        CREDENTIALS_MODE="plain"
        return 1
    fi
}

setup_firewall() {
    log_info "Configurando Firewall (UFW)..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Permitir puertos críticos
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Habilitar UFW de forma no interactiva y verificar
    ufw --force enable
    if ufw status | grep -q "Status: active"; then
        log_success "Firewall configurado y activo."
    else
        log_warn "UFW no quedó activo; revisa configuración."
    fi
}

configure_ssh() {
    local REAL_USER=$1
    local HONEYPOT_USER=$2

    log_info "Configurando SSH Hardening (Split Authentication)..."
    
    # Copia de seguridad de la configuración
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Configuración base (segura por defecto)
cat > /etc/ssh/sshd_config <<EOF
# ASIR VPS Defense - SSH Config
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

# Admin real: solo clave pública (sin password)
Match User $REAL_USER
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
EOF

    # Validar sintaxis y reiniciar de forma comprobada
    sshd -t
    systemctl restart sshd
    systemctl is-active --quiet sshd
    log_success "SSH configurado. Admin real solo clave pública; resto acepta contraseña."
}

configure_fail2ban() {
    log_info "Configurando Fail2Ban (Protección Activa)..."

    systemctl stop fail2ban 2>/dev/null || true

    # Asegurar que auth log existe para que Fail2Ban pueda leerlo
    if [ ! -f /var/log/auth.log ]; then
        touch /var/log/auth.log
        chown syslog:adm /var/log/auth.log 2>/dev/null || true
        chmod 640 /var/log/auth.log
    fi

    # Crear configuración de jaula personalizada
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Banear hosts por 35 días (se puede subir a 365d si se desea un año completo)
bantime = 35d

# Una IP es baneada si ha generado "maxretry" durante el último "findtime"
findtime = 10m

# "maxretry" es el numero de fallos permitidos antes del ban global
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
    log_success "Fail2Ban configurado con política estricta (Bantime: 35d, MaxRetry: 2)."
}

create_secure_admin() {
    log_info "Iniciando creación del Administrador Seguro..."

    echo -e "${YELLOW}>>> Configuración del ADMIN REAL (Tú)${NC}"
    echo -n "Introduce el nombre para tu usuario administrador (ej: sys_ops): "
    read -r SECURE_ADMIN < /dev/tty

    if [ -z "$SECURE_ADMIN" ]; then
        log_error "El nombre de usuario no puede estar vacío."
        exit 1
    fi

    if id "$SECURE_ADMIN" &>/dev/null; then
        log_warn "El usuario $SECURE_ADMIN ya existe. Se asumirá que es correcto."
    else
        useradd -m -s /bin/bash "$SECURE_ADMIN"
        usermod -aG sudo,docker "$SECURE_ADMIN"
        log_success "Usuario $SECURE_ADMIN creado."
    fi

    # Establecer contraseña para uso de sudo
    echo -e "${YELLOW}>>> Configuración de contraseña para SUDO${NC}"
    echo -e "Aunque el acceso SSH sea por clave, necesitas una contraseña para elevar privilegios (sudo)."
    echo -e "Por favor, establece una contraseña segura para el usuario '$SECURE_ADMIN'."
    
    while true; do
        echo -n "Contraseña sudo: "
        read -r -s ADMIN_PASS < /dev/tty
        echo ""
        echo -n "Confirmar contraseña: "
        read -r -s ADMIN_PASS_CONFIRM < /dev/tty
        echo ""
        
        if [ -n "$ADMIN_PASS" ] && [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]; then
            echo "$SECURE_ADMIN:$ADMIN_PASS" | chpasswd
            log_success "Contraseña establecida para $SECURE_ADMIN."
            break
        else
            log_error "Las contraseñas no coinciden o están vacías. Inténtalo de nuevo."
        fi
    done

    # Configurar Clave SSH para Admin Real (obligatorio). Admin queda con PasswordAuthentication no (Match User), resto de usuarios sí permiten password para capturar ataques.
    local SSH_KEY=""
    while true; do
        echo -e "${YELLOW}Selecciona cómo añadir la clave pública SSH del admin (obligatorio):${NC}"
        echo "  [1] Detectar claves existentes y elegir"
        echo "  [2] Introducir clave pública manualmente"
        echo -n "Opción: "
        read -r key_opt < /dev/tty

        if [ "$key_opt" = "1" ]; then
            SSH_KEY=$(choose_public_key_for_user "$SECURE_ADMIN" "acceso SSH") || SSH_KEY=""
            if [ -n "$SSH_KEY" ]; then
                log_info "Clave seleccionada mediante detección."
                break
            else
                log_warn "No se detectaron claves. Usa la opción 2 para pegar una clave manualmente."
            fi
        elif [ "$key_opt" = "2" ]; then
            echo -n "Pega tu clave pública (ssh-ed25519/ssh-rsa): "
            read -r manual_key < /dev/tty
            if [[ "$manual_key" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
                SSH_KEY="$manual_key"
                break
            else
                log_warn "Formato no válido. Intenta de nuevo."
            fi
        else
            log_warn "Debes proporcionar una clave para el admin."
        fi
    done

    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    if grep -qF "$SSH_KEY" "/home/$SECURE_ADMIN/.ssh/authorized_keys" 2>/dev/null; then
        log_info "La clave SSH ya estaba autorizada."
    else
        echo "$SSH_KEY" >> "/home/$SECURE_ADMIN/.ssh/authorized_keys"
        log_success "Clave SSH añadida correctamente."
    fi

    # Asegurar que los permisos son correctos (Paso crítico)
    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    chmod 700 "/home/$SECURE_ADMIN/.ssh"
    if [ -f "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        chmod 600 "/home/$SECURE_ADMIN/.ssh/authorized_keys"
    fi
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "/home/$SECURE_ADMIN/.ssh"
    
    # Permitir al nuevo admin iniciar sesión vía SSH inmediatamente (incluso antes del hardening completo)
    # Esta es una medida de seguridad en caso de que el script falle más tarde
    log_success "Configuración SSH y permisos verificados para $SECURE_ADMIN."

    echo "$SECURE_ADMIN" > "$STATE_DIR/secure_admin"
}

handle_honeypot_logic() {
    log_info "Configurando lógica del Honeypot..."

    echo -e "${YELLOW}>>> Configuración del USUARIO CEBO (Honeypot)${NC}"
    echo -n "Introduce el nombre para el usuario cebo (ej: admin, support): "
    read -r HONEYPOT_TARGET_USER < /dev/tty

    if [ -z "$HONEYPOT_TARGET_USER" ]; then
        HONEYPOT_TARGET_USER="admin"
        log_info "Usando nombre por defecto: admin"
    fi

    # Comprobar conflicto: ¿Es el usuario real actual el mismo que el usuario honeypot deseado?
    if [ "$CURRENT_REAL_USER" == "$HONEYPOT_TARGET_USER" ]; then
        echo -e "${RED}¡CONFLICTO DETECTADO!${NC}"
        echo -e "Estás logueado como '$CURRENT_REAL_USER', pero quieres usar ese nombre como Honeypot."
        echo -e "Para hacer esto de forma segura, debemos:"
        echo -e "1. Crear tu nuevo usuario seguro ($SECURE_ADMIN) - YA REALIZADO"
        echo -e "2. Convertir tu usuario actual ($CURRENT_REAL_USER) en el Honeypot AL FINAL del script."
        echo -e "   (Esto evitará que tu sesión se corte ahora mismo)"
        
        echo -n "¿Deseas proceder con esta conversión diferida? (S/n): "
        read -r CONFIRM_CONVERSION < /dev/tty
        
        if [[ "$CONFIRM_CONVERSION" =~ ^[Ss]$ ]] || [[ -z "$CONFIRM_CONVERSION" ]]; then
            CONVERT_CURRENT_USER_TO_HONEYPOT=true
            log_warn "Conversión diferida ACTIVADA. '$CURRENT_REAL_USER' se convertirá en Honeypot al finalizar."
        else
            log_error "Operación cancelada por el usuario. Elige otro nombre para el Honeypot."
            exit 1
        fi
    else
        # Sin conflicto, crear honeypot normalmente si no existe
        if id "$HONEYPOT_TARGET_USER" &>/dev/null; then
            log_warn "El usuario $HONEYPOT_TARGET_USER ya existe. Se configurará como Honeypot."
        else
            useradd -m -s /bin/bash "$HONEYPOT_TARGET_USER"
            log_success "Usuario cebo $HONEYPOT_TARGET_USER creado."
        fi
    fi

    # Establecer Contraseña del Honeypot
    echo -n "Introduce una contraseña para el Honeypot (o ENTER para generar una aleatoria): "
    read -r HONEYPOT_TARGET_PASS < /dev/tty
    
    if [ -z "$HONEYPOT_TARGET_PASS" ]; then
        HONEYPOT_TARGET_PASS=$(openssl rand -base64 12)
        log_info "Contraseña generada para Honeypot: $HONEYPOT_TARGET_PASS"
    fi

    # Si NO convertimos el usuario actual, establecer contraseña ahora. 
    # Si convertimos, esperamos hasta el final.
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = false ]; then
        echo "$HONEYPOT_TARGET_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        log_success "Contraseña establecida para $HONEYPOT_TARGET_USER."
    fi
}

finalize_deferred_conversion() {
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = true ]; then
        log_warn ">>> EJECUTANDO CONVERSIÓN DIFERIDA DE USUARIO <<<"
        log_info "Convirtiendo '$CURRENT_REAL_USER' en Honeypot..."

        # 1. Eliminar privilegios sudo del usuario antiguo
        deluser "$CURRENT_REAL_USER" sudo 2>/dev/null || true
        deluser "$CURRENT_REAL_USER" docker 2>/dev/null || true
        
        # 2. Establecer la contraseña del honeypot
        echo "$CURRENT_REAL_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        
        # 3. Asegurar que la config SSH permite contraseña para este usuario (ya hecho en configure_ssh)
        # Pero podríamos querer limpiar authorized_keys para forzar el uso de contraseña?
        # Idealmente sí, para simular un usuario vulnerable real.
        if [ -f "/home/$CURRENT_REAL_USER/.ssh/authorized_keys" ]; then
            mv "/home/$CURRENT_REAL_USER/.ssh/authorized_keys" "/home/$CURRENT_REAL_USER/.ssh/authorized_keys.bak_conversion"
            log_info "Claves SSH de '$CURRENT_REAL_USER' desactivadas (backup creado)."
        fi

        log_success "Conversión completada. '$CURRENT_REAL_USER' es ahora un usuario restringido (Honeypot)."
        echo -e "${RED}ATENCIÓN: Tu sesión actual sigue activa, pero si te desconectas, no podrás volver a entrar como '$CURRENT_REAL_USER' sin contraseña.${NC}"
        echo -e "Debes usar el nuevo usuario seguro: ${GREEN}$SECURE_ADMIN${NC}"
    fi
}

generate_env() {
    log_info "Generando secretos y configuración (.env)..."
    
    echo -n "Introduce el DOMINIO del VPS (o la IP Pública si no tienes dominio): "
    read -r DOMAIN_NAME < /dev/tty

    if [ -z "${DOMAIN_NAME}" ]; then
        log_error "El dominio/IP no puede estar vacío."
        exit 1
    fi
    if echo "${DOMAIN_NAME}" | grep -q ' '; then
        log_error "El dominio/IP no debe contener espacios."
        exit 1
    fi
    
    # Generar contraseñas aleatorias
    MYSQL_ROOT_PASS=$(openssl rand -base64 24)
    MYSQL_APP_PASS=$(openssl rand -base64 24)
    
    cat > .env <<EOF
# ASIR VPS Defense - Variables de Entorno
# Generado el $(date)

DOMAIN_NAME=$DOMAIN_NAME
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASS
MYSQL_DATABASE=asir_defense
MYSQL_USER=app_user
MYSQL_PASSWORD=$MYSQL_APP_PASS

# Configuración de Red
FRONTEND_SUBNET=172.20.0.0/16
BACKEND_SUBNET=172.21.0.0/16
GEOIP_LICENSE_KEY=
EOF

    chmod 600 .env
    log_success "Archivo .env generado con credenciales seguras."
}

download_geolite_mmdb() {
    # Descarga la base GeoLite2-City desde el CDN libre (jsDelivr)
    local url="https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p geoip

    log_info "Descargando base GeoLite2-City (jsDelivr, sin API key)..."
    if ! curl -fsSL "$url" -o "$tmpdir/GeoLite2-City.mmdb.gz"; then
        log_warn "No se pudo descargar GeoLite2 desde el CDN. Se usará fallback de país."
        rm -rf "$tmpdir"
        return 0
    fi

    if ! gunzip -c "$tmpdir/GeoLite2-City.mmdb.gz" > geoip/GeoLite2-City.mmdb; then
        log_warn "No se pudo descomprimir GeoLite2. Se usará fallback de país."
        rm -rf "$tmpdir"
        return 0
    fi

    chmod 644 geoip/GeoLite2-City.mmdb
    log_success "Base GeoLite2-City descargada localmente (geoip/GeoLite2-City.mmdb)."
    rm -rf "$tmpdir"
}

generate_db_seed() {
    log_info "Generando credenciales para el Panel de Administración..."
    
    WEB_ADMIN_PASS=$(openssl rand -base64 12)
    
    # Usar un contenedor PHP temporal para generar el hash Bcrypt
    # Usamos la imagen php:8.2-cli que es pequeña y estándar
    log_info "Calculando hash de contraseña seguro..."
    set +e
    WEB_ADMIN_HASH=$(docker run --rm php:8.2-cli php -r "echo password_hash('$WEB_ADMIN_PASS', PASSWORD_DEFAULT);" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local hash_status=$?
    set -e
    if [ $hash_status -ne 0 ] || [ -z "$WEB_ADMIN_HASH" ]; then
        log_error "No se pudo generar el hash de la contraseña (docker run). Revisa $LOG_FILE."
        tail -n 25 "$LOG_FILE" >&2
        exit 1
    fi
    
    cat > mysql/init/02-seed.sql <<EOF
-- Archivo semilla auto-generado
-- Creado por deploy.sh el $(date)

INSERT INTO users (username, password_hash, role) VALUES 
('admin', '$WEB_ADMIN_HASH', 'admin');
EOF
    
    # Guardar credenciales en un archivo seguro para el usuario
    # Lo guardamos en el directorio home del admin seguro para asegurar propiedad y persistencia
    local CRED_FILE="/home/$SECURE_ADMIN/admin_credentials.txt"
    
    cat > "$CRED_FILE" <<EOF
==================================================
ASIR VPS DEFENSE - CREDENCIALES DE ACCESO
==================================================
Generado el: $(date)

[PANEL DE ADMINISTRACIÓN]
URL: http://localhost:8888 (Requiere Túnel SSH)
Usuario: admin
Contraseña: $WEB_ADMIN_PASS

[BASE DE DATOS]
Root Password: $MYSQL_ROOT_PASS
App User Password: $MYSQL_APP_PASS

NOTA: Este archivo es propiedad de $SECURE_ADMIN y tiene permisos restrictivos (600).
EOF
    
    # Asegurar el archivo
    chown "$SECURE_ADMIN:$SECURE_ADMIN" "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    log_success "Semilla de base de datos generada (mysql/init/02-seed.sql)."
    log_success "Credenciales guardadas temporalmente en '$CRED_FILE'."
    if encrypt_credentials_file "$CRED_FILE"; then
        log_info "Credenciales cifradas. Podrás decidir si verlas o descargar el archivo al final."
    else
        # Mantener el archivo plano para mostrar y destruir al final
        CREDENTIALS_MODE="plain"
        log_warn "Credenciales sin cifrar; se mostrarán al final con advertencia y luego se borrarán."
    fi
}

# ==============================================================================
# Ejecución Principal
# ==============================================================================


main() {
    clear
    print_section "ASIR VPS DEFENSE - INSTALADOR v1.1"
    
    check_root
    detect_context
    detect_os

    # Recuperar usuario admin seguro de ejecuciones previas (si existe)
    if [ -z "$SECURE_ADMIN" ] && [ -f "$STATE_DIR/secure_admin" ]; then
        SECURE_ADMIN=$(cat "$STATE_DIR/secure_admin")
    fi

    # Si todo ya estuvo completado, permitir una ejecución de auditoría rápida y salir
    if is_step_done "prep_done" && is_step_done "users_done" && is_step_done "project_done" \
       && is_step_done "env_done" && is_step_done "seed_done" && is_step_done "final_done"; then
        local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
        if [ -d "$PROJECT_DIR" ]; then
            cd "$PROJECT_DIR" || exit 1
            load_env_if_present
            print_section "AUDITORÍA DE PERMISOS"
            audit_permissions "$PROJECT_DIR"
            exit 0
        fi
    fi
    
    # Paso 1: Preparación del Sistema
    print_section "PREPARACIÓN DEL SISTEMA"
    if is_step_done "prep_done"; then
        log_info "Preparación previa detectada; saltando reinstalación de dependencias y firewall."
    else
        install_dependencies
        setup_firewall
        mark_step_done "prep_done"
    fi
    
    # Paso 2: Configuración de Usuario y Seguridad
    print_section "USUARIOS Y SEGURIDAD"
    # Creamos el usuario PRIMERO para poder desplegar en su directorio home
    if is_step_done "users_done"; then
        log_info "Usuarios y seguridad ya configurados previamente; saltando creación y hardening."
        if [ -z "$SECURE_ADMIN" ]; then
            log_error "No se pudo recuperar SECURE_ADMIN de estado previo. Elimina $STATE_DIR/users_done para rehacer este paso."
            exit 1
        fi
    else
        create_secure_admin
        handle_honeypot_logic
        configure_ssh "$SECURE_ADMIN" "$HONEYPOT_TARGET_USER"
        configure_fail2ban
        mark_step_done "users_done"
    fi
    
    # Paso 3: Configuración del Proyecto en el Home del Usuario Seguro
    print_section "PROVISIONADO DEL PROYECTO"
    local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
    log_info "Estableciendo directorio del proyecto en: $PROJECT_DIR"

    if is_step_done "project_done"; then
        log_info "Proyecto ya presente; reutilizando $PROJECT_DIR"
        cd "$PROJECT_DIR" || exit 1
    else
        # Crear directorio si no existe
        if [ ! -d "$PROJECT_DIR" ]; then
            mkdir -p "$PROJECT_DIR"
        fi

        # Lógica para poblar el directorio
        if [ -f "docker-compose.yml" ]; then
            log_info "Copiando archivos de instalación locales (incluyendo parches)..."
            # Copiar contenido al home del nuevo usuario
            rsync -av --exclude ".git" --exclude "asir-vps-defense" . "$PROJECT_DIR/" 2>/dev/null || cp -R . "$PROJECT_DIR/"
        else
            log_info "Descargando repositorio oficial..."
            # Limpiar dir por si acaso
            rm -rf "$PROJECT_DIR"
            git clone https://github.com/paulusgi/asir-vps-defense.git "$PROJECT_DIR"
        fi

        # Asegurar que la propiedad es correcta inmediatamente
        chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "$PROJECT_DIR"
        cd "$PROJECT_DIR" || exit 1
        mark_step_done "project_done"
        log_success "Directorio de trabajo establecido: $(pwd)"
    fi

    # Paso 4: Despliegue de la Aplicación
    print_section "DESPLIEGUE DE LA APLICACIÓN"
    if is_step_done "env_done"; then
        log_info "Archivo .env ya existe; no se regenera para evitar cambiar credenciales."
        load_env_if_present
    else
        generate_env
        load_env_if_present
        mark_step_done "env_done"
    fi

    # Descarga GeoLite2-City desde CDN (sin requerir License Key)
    download_geolite_mmdb

    if is_step_done "seed_done"; then
        log_info "Semilla de base de datos ya generada; saltando."
    else
        generate_db_seed
        mark_step_done "seed_done"
    fi
    
    # Corregir permisos para secretos generados
    chown "$SECURE_ADMIN:$SECURE_ADMIN" .env
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" mysql/init

    # Corregir permisos para webroot (usuario contenedor 101/1000 necesita acceso)
    log_info "Ajustando permisos de archivos web..."
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" src

    set +e
    run_quiet "Desplegando contenedores Docker" docker compose up -d --build
    local up_status=$?
    set -e

    if [ $up_status -ne 0 ]; then
        log_error "docker compose up falló. Mostrando logs breves para diagnóstico..."
        # Mostrar los últimos logs de MySQL, que suele ser el culpable cuando hay volumen previo con otra contraseña
        docker compose logs --tail=60 mysql || true
        log_warn "Si ves errores de autenticación/root password, borra el volumen persistente y reintenta:"
        log_warn "   docker compose down -v"
        log_warn "   sudo rm -f $STATE_DIR/env_done $STATE_DIR/seed_done  # si necesitas regenerar .env/seed"
        log_warn "   ./deploy.sh"
        exit 1
    fi
    
    # Paso 5: Limpieza Final y Acciones Diferidas
    print_section "AJUSTES FINALES"
    if is_step_done "final_done"; then
        log_info "Acciones finales ya aplicadas anteriormente."
    else
        finalize_deferred_conversion
        mark_step_done "final_done"
    fi
    history -c
    
    print_section "INSTALACIÓN FINALIZADA"
    
    echo -e "\n${YELLOW}Por favor, revisa los mensajes anteriores en busca de errores (texto rojo).${NC}"
    echo -n "Presiona ENTER para continuar con la verificación de estado y credenciales..."
    read -r _ < /dev/tty
    
    echo -e "\n${YELLOW}>>> ESTADO DE LOS SERVICIOS <<<${NC}"
    
    log_info "Esperando a que la base de datos y los servicios estén listos (puede tardar 30-60s)..."
    
    # 1. Esperar al Healthcheck de MySQL
    local retries=0
    while [ $retries -lt 30 ]; do
        if docker compose ps | grep -q "healthy"; then
             break
        fi
        echo -n "."
        sleep 2
        ((retries++))
    done
    echo ""

    # 2. Verificar Puerto del Panel de Administración (8888)
    log_info "Verificando disponibilidad real del Panel de Administración..."
    local port_ready=false
    retries=0
    while [ $retries -lt 20 ]; do
        # Intentar obtener cabeceras de localhost:8888
        if curl -s -I http://127.0.0.1:8888 >/dev/null; then
            port_ready=true
            log_success "¡Panel de Administración ONLINE en puerto 8888!"
            break
        fi
        echo -n "."
        sleep 3
        ((retries++))
    done
    echo ""

    if [ "$port_ready" = false ]; then
        log_error "El servicio en el puerto 8888 no responde aún."
        log_warn "Es posible que los contenedores sigan iniciándose o haya un error."
        log_warn "Revisa los logs con: docker compose logs -f"
    fi

    docker compose ps
    
    echo -e "\n${YELLOW}>>> GESTIÓN DE CREDENCIALES <<<${NC}"
    local CRED_PLAIN="/home/$SECURE_ADMIN/admin_credentials.txt"
    local CRED_ENC="${CRED_PLAIN}.age"
    local HOST_HINT="${DOMAIN_NAME:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

    if [ -f "$CRED_ENC" ]; then
        echo -e "Archivo cifrado con tu clave pública SSH: ${BLUE}$CRED_ENC${NC}"
        echo -e "Elige una opción:"
        echo "  [1] Mostrar credenciales en pantalla (texto plano temporal)"
        echo "  [2] Ver comando para descargar el archivo cifrado en tu máquina local"
        echo "  [3] No hacer nada"
        echo -n "Opción (1/2/3): "
        read -r CRED_CHOICE < /dev/tty

        case "$CRED_CHOICE" in
            1)
                echo -e "${YELLOW}Credenciales (no se guardan en disco):${NC}"
                echo "- Panel Web -> usuario: admin | contraseña: $WEB_ADMIN_PASS"
                echo "- DB root   -> $MYSQL_ROOT_PASS"
                echo "- DB app    -> $MYSQL_APP_PASS"
                ;;
            2)
                echo -e "Ejecuta en tu máquina local para descargar el archivo cifrado:"
                echo -e "   scp $SECURE_ADMIN@${HOST_HINT:-<dominio_o_ip>}:$CRED_ENC ./admin_credentials.txt.age"
                echo -e "Luego descifra con tu clave privada:"
                echo -e "   age -d -i ~/.ssh/<tu_clave> -o admin_credentials.txt ./admin_credentials.txt.age"
                ;;
            *)
                log_info "Continuando sin mostrar ni descargar credenciales."
                ;;
        esac
    elif [ -f "$CRED_PLAIN" ]; then
        echo -e "${RED}ATENCIÓN: Credenciales sin cifrar. Se mostrarán UNA sola vez y el archivo se borrará ahora.${NC}"
        cat "$CRED_PLAIN"
        shred -u "$CRED_PLAIN"
    else
        echo -e "El archivo de credenciales ya no está presente."
    fi

    unset WEB_ADMIN_PASS

    echo -e "\n${BLUE}>>> INSTRUCCIONES DE CONEXIÓN <<<${NC}"
    echo -e "1. Abre una NUEVA terminal en tu ordenador local (no en este servidor)."
    echo -e "2. Ejecuta el siguiente comando para crear el túnel seguro:"
    echo -e "   ${YELLOW}ssh -L 8888:127.0.0.1:8888 $SECURE_ADMIN@$DOMAIN_NAME${NC}"
    echo -e ""
    echo -e "3. Abre tu navegador web y accede a:"
    echo -e "   - Panel de Administración + Métricas Loki: ${GREEN}http://localhost:8888${NC}"
    echo -e ""
    echo -e "Si recibes 'Connection Refused', espera unos segundos a que los contenedores terminen de arrancar."
    echo -e "\n${YELLOW}Log detallado: ${LOG_FILE}${NC}"
    echo -n "Pulsa ENTER para borrar el log y salir (escribe 'No' para conservarlo): "
    read -r CLEAN_LOG < /dev/tty
    if [[ "$CLEAN_LOG" =~ ^[Nn][Oo]$ ]]; then
        log_info "Log conservado en $LOG_FILE"
    else
        rm -f "$LOG_FILE" && log_info "Log eliminado."
    fi

    echo -e "${GREEN}==================================================${NC}"
}

main "$@"
