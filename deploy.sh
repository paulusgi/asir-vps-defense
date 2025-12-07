#!/bin/bash

# ==============================================================================
# ASIR VPS Defense - Automated Deployment Script
# ==============================================================================
# Author: ASIR Team
# Description:
#   Orchestrates the deployment of a secure VPS infrastructure including:
#   - Docker & Docker Compose installation
#   - Firewall (UFW) hardening
#   - Secure SSH configuration (Split Auth: Key-only Admin vs Password Honeypot)
#   - WAF (Nginx + ModSecurity) setup
#   - Observability Stack (Loki + Promtail + Grafana)
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
# ==============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global Variables
INSTALL_DIR="/opt/asir-vps-defense"
ENV_FILE=".env"

# Global flag to track if we need to convert the current user later
CONVERT_CURRENT_USER_TO_HONEYPOT=false
HONEYPOT_TARGET_USER=""
HONEYPOT_TARGET_PASS=""
SECURE_ADMIN=""
CURRENT_REAL_USER=""

# ==============================================================================
# Helper Functions
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

detect_context() {
    # Identify the real human user running the script (even behind sudo)
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
    
    # Loop until no apt/dpkg processes are running
    while pgrep -a apt > /dev/null || pgrep -a apt-get > /dev/null || pgrep -a dpkg > /dev/null; do
        log_warn "El sistema está instalando actualizaciones automáticas en segundo plano. Esperando..."
        sleep 10
    done
    
    # Double check lock files
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        log_warn "Bloqueo de base de datos dpkg detectado. Esperando..."
        sleep 5
    done
}

install_dependencies() {
    wait_for_apt_locks
    log_info "Actualizando repositorios e instalando dependencias base..."
    
    # Update with retry logic
    if ! apt-get update; then
        log_warn "Fallo al actualizar repositorios. Reintentando en 5s..."
        sleep 5
        apt-get update || log_error "No se pudieron actualizar los repositorios. Continuando bajo riesgo..."
    fi

    # Install with retry and verification
    log_info "Instalando paquetes (curl, git, ufw, fail2ban)..."
    if ! apt-get install -y psmisc curl git ufw fail2ban; then
        log_warn "Fallo en la instalación de paquetes. Reintentando tras espera..."
        wait_for_apt_locks
        apt-get install -y psmisc curl git ufw fail2ban
    fi

    # Critical check: Fail2Ban must be present
    if ! command -v fail2ban-client &> /dev/null; then
        log_error "CRÍTICO: Fail2Ban no se instaló correctamente. Abortando para seguridad."
        log_info "Intenta ejecutar manualmente: apt-get install -y fail2ban"
        exit 1
    fi

    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        log_info "Instalando Docker..."
        curl -fsSL https://get.docker.com | sh
        log_success "Docker instalado correctamente."
    else
        log_info "Docker ya está instalado."
    fi
}

setup_firewall() {
    log_info "Configurando Firewall (UFW)..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow critical ports
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable UFW without prompt
    echo "y" | ufw enable
    log_success "Firewall configurado y activo."
}

configure_ssh() {
    local REAL_USER=$1
    local HONEYPOT_USER=$2

    log_info "Configurando SSH Hardening (Split Authentication)..."
    
    # Backup config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Base configuration (Secure by default)
    cat > /etc/ssh/sshd_config <<EOF
# ASIR VPS Defense - Hardened SSH Config
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Honeypot User Configuration (Allow Password)
Match User $HONEYPOT_USER
    PasswordAuthentication yes
    PermitEmptyPasswords no
    MaxAuthTries 5
    AllowTcpForwarding no
EOF

    systemctl restart sshd
    log_success "SSH configurado. Admin: Key-only | Honeypot: Password-allowed."
}

configure_fail2ban() {
    log_info "Configurando Fail2Ban (Protección Activa)..."

    # Create custom jail configuration
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban hosts for 1 hour:
bantime = 1h

# An ip is banned if it has generated "maxretry" during the last "findtime"
findtime = 10m

# "maxretry" is the number of failures before a ban is imposed
maxretry = 5

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    log_success "Fail2Ban configurado con política estricta (Bantime: 1h, MaxRetry: 3)."
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

    # Setup SSH Key for Real Admin
    local ASK_FOR_KEY=true
    
    # Check if user already has keys (e.g. from Cloud-Init)
    if [ -s "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        echo -e "${YELLOW}¡Atención! Se han detectado claves SSH existentes para el usuario $SECURE_ADMIN.${NC}"
        echo -n "¿Quieres usar las claves existentes y saltar el paso de añadir una nueva? (S/n): "
        read -r USE_EXISTING < /dev/tty
        # Default to Yes
        if [[ "$USE_EXISTING" =~ ^[Ss]$ ]] || [[ -z "$USE_EXISTING" ]]; then
            ASK_FOR_KEY=false
            log_info "Manteniendo claves existentes..."
        fi
    fi

    if [ "$ASK_FOR_KEY" = true ]; then
        echo -e "Pega tu CLAVE PÚBLICA SSH (comienza por ssh-rsa o ssh-ed25519):"
        read -r SSH_KEY < /dev/tty
        
        if [ -n "$SSH_KEY" ]; then
            mkdir -p "/home/$SECURE_ADMIN/.ssh"
            
            # Append key instead of overwrite
            if grep -qF "$SSH_KEY" "/home/$SECURE_ADMIN/.ssh/authorized_keys" 2>/dev/null; then
                log_info "La clave SSH ya estaba autorizada."
            else
                echo "$SSH_KEY" >> "/home/$SECURE_ADMIN/.ssh/authorized_keys"
                log_success "Clave SSH añadida correctamente."
            fi
        else
            log_warn "No has introducido ninguna clave. Asegúrate de poder acceder."
        fi
    fi

    # Ensure permissions are correct (Critical step)
    mkdir -p "/home/$SECURE_ADMIN/.ssh"
    chmod 700 "/home/$SECURE_ADMIN/.ssh"
    if [ -f "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        chmod 600 "/home/$SECURE_ADMIN/.ssh/authorized_keys"
    fi
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "/home/$SECURE_ADMIN/.ssh"
    
    # Allow the new admin to log in via SSH immediately (even before full hardening)
    # This is a safety measure in case the script fails later
    log_success "Configuración SSH y permisos verificados para $SECURE_ADMIN."
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

    # Check for conflict: Is the current real user the same as the desired honeypot user?
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
        # No conflict, create honeypot normally if it doesn't exist
        if id "$HONEYPOT_TARGET_USER" &>/dev/null; then
            log_warn "El usuario $HONEYPOT_TARGET_USER ya existe. Se configurará como Honeypot."
        else
            useradd -m -s /bin/bash "$HONEYPOT_TARGET_USER"
            log_success "Usuario cebo $HONEYPOT_TARGET_USER creado."
        fi
    fi

    # Set Honeypot Password
    echo -n "Introduce una contraseña para el Honeypot (o ENTER para generar una aleatoria): "
    read -r HONEYPOT_TARGET_PASS < /dev/tty
    
    if [ -z "$HONEYPOT_TARGET_PASS" ]; then
        HONEYPOT_TARGET_PASS=$(openssl rand -base64 12)
        log_info "Contraseña generada para Honeypot: $HONEYPOT_TARGET_PASS"
    fi

    # If NOT converting current user, set password now. 
    # If converting, we wait until the end.
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = false ]; then
        echo "$HONEYPOT_TARGET_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        log_success "Contraseña establecida para $HONEYPOT_TARGET_USER."
    fi
}

finalize_deferred_conversion() {
    if [ "$CONVERT_CURRENT_USER_TO_HONEYPOT" = true ]; then
        log_warn ">>> EJECUTANDO CONVERSIÓN DIFERIDA DE USUARIO <<<"
        log_info "Convirtiendo '$CURRENT_REAL_USER' en Honeypot..."

        # 1. Remove sudo privileges from the old user
        deluser "$CURRENT_REAL_USER" sudo 2>/dev/null || true
        deluser "$CURRENT_REAL_USER" docker 2>/dev/null || true
        
        # 2. Set the honeypot password
        echo "$CURRENT_REAL_USER:$HONEYPOT_TARGET_PASS" | chpasswd
        
        # 3. Ensure SSH config allows password for this user (already done in configure_ssh)
        # But we might want to clear authorized_keys to force password usage?
        # Ideally yes, to simulate a real vulnerable user.
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
    
    # Generate random passwords
    MYSQL_ROOT_PASS=$(openssl rand -base64 24)
    MYSQL_APP_PASS=$(openssl rand -base64 24)
    GRAFANA_PASS=$(openssl rand -base64 12)
    
    cat > .env <<EOF
# ASIR VPS Defense - Environment Variables
# Generated on $(date)

DOMAIN_NAME=$DOMAIN_NAME
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASS
MYSQL_DATABASE=asir_defense
MYSQL_USER=app_user
MYSQL_PASSWORD=$MYSQL_APP_PASS
GRAFANA_ADMIN_PASSWORD=$GRAFANA_PASS

# Network Configuration
FRONTEND_SUBNET=172.20.0.0/16
BACKEND_SUBNET=172.21.0.0/16
EOF

    chmod 600 .env
    log_success "Archivo .env generado con credenciales seguras."
}

generate_db_seed() {
    log_info "Generando credenciales para el Panel de Administración..."
    
    WEB_ADMIN_PASS=$(openssl rand -base64 12)
    
    # Use a temporary PHP container to generate the Bcrypt hash
    # We use the php:8.2-cli image which is small and standard
    log_info "Calculando hash de contraseña seguro..."
    # Ensure docker is running or wait for it? It should be installed.
    # We might need to pull the image first to avoid timeout in the run command, but run does pull.
    WEB_ADMIN_HASH=$(docker run --rm php:8.2-cli php -r "echo password_hash('$WEB_ADMIN_PASS', PASSWORD_DEFAULT);")
    
    cat > mysql/init/02-seed.sql <<EOF
-- Auto-generated seed file
-- Created by deploy.sh on $(date)

INSERT INTO users (username, password_hash, role) VALUES 
('admin', '$WEB_ADMIN_HASH', 'admin');
EOF
    
    # Save credentials to a secure file for the user
    # We save it to the secure admin's home directory to ensure ownership and persistence
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

[GRAFANA]
URL: http://localhost:3000 (Requiere Túnel SSH)
Usuario: admin
Contraseña: $GRAFANA_PASS

[BASE DE DATOS]
Root Password: $MYSQL_ROOT_PASS
App User Password: $MYSQL_APP_PASS

NOTA: Este archivo es propiedad de $SECURE_ADMIN y tiene permisos restrictivos (600).
EOF
    
    # Secure the file
    chown "$SECURE_ADMIN:$SECURE_ADMIN" "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    log_success "Semilla de base de datos generada (mysql/init/02-seed.sql)."
    log_success "Credenciales guardadas de forma segura en '$CRED_FILE'."
    export WEB_ADMIN_PASS
}

# ==============================================================================
# Main Execution
# ==============================================================================

main() {
    clear
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}   ASIR VPS DEFENSE - INSTALLER v1.0              ${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    check_root
    detect_context
    detect_os
    
    # Step 1: System Prep
    install_dependencies

    # Ensure we are in the correct directory with all files
    if [ ! -f "docker-compose.yml" ]; then
        log_info "Archivos de configuración no encontrados. Clonando repositorio..."
        # Remove dir if exists to avoid conflicts
        rm -rf "$INSTALL_DIR"
        git clone https://github.com/paulusgi/asir-vps-defense.git "$INSTALL_DIR"
        cd "$INSTALL_DIR" || exit 1
        log_success "Repositorio clonado en $INSTALL_DIR"
    fi

    setup_firewall
    
    # Step 2: User & Security Config
    create_secure_admin
    handle_honeypot_logic
    
    configure_ssh "$SECURE_ADMIN" "$HONEYPOT_TARGET_USER"
    configure_fail2ban
    
    # Step 3: Application Deployment
    generate_env
    generate_db_seed
    
    # Fix permissions for webroot before starting containers
    # This ensures the container user (1000) can read the files
    log_info "Ajustando permisos de archivos web..."
    chown -R 1000:1000 src
    chmod -R 755 src

    log_info "Desplegando contenedores Docker..."
    docker compose up -d --build
    
    # Step 4: Final Cleanup & Deferred Actions
    finalize_deferred_conversion
    history -c
    
    # Removed clear to allow user to see previous errors
    # clear
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}   INSTALACIÓN FINALIZADA                         ${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    echo -e "\n${YELLOW}Por favor, revisa los mensajes anteriores en busca de errores (texto rojo).${NC}"
    echo -n "Presiona ENTER para continuar con la verificación de estado y credenciales..."
    read -r _ < /dev/tty
    
    echo -e "\n${YELLOW}>>> ESTADO DE LOS SERVICIOS <<<${NC}"
    
    log_info "Esperando a que la base de datos y los servicios estén listos (puede tardar 30-60s)..."
    # Simple wait loop for ports
    local retries=0
    while [ $retries -lt 20 ]; do
        if docker compose ps | grep -q "healthy" && docker compose ps | grep -q "Up"; then
             # Check if ports are actually listening inside the container logic? 
             # Docker ps showing healthy is good enough for now.
             break
        fi
        echo -n "."
        sleep 3
        ((retries++))
    done
    echo ""
    
    docker compose ps
    
    echo -e "\n${YELLOW}>>> GESTIÓN DE CREDENCIALES <<<${NC}"
    echo -e "Por seguridad, las contraseñas NO se muestran en pantalla."
    echo -e "Se han guardado en un archivo protegido en el home de tu usuario:"
    echo -e "${BLUE}/home/$SECURE_ADMIN/admin_credentials.txt${NC}"
    echo -e ""
    echo -e "Para verlas, conéctate por SSH con tu nuevo usuario y ejecuta:"
    echo -e "   ${YELLOW}cat ~/admin_credentials.txt${NC}"
    
    echo -e "\n--------------------------------------------------"
    echo -n "¿Deseas ver SOLO la contraseña temporal del Panel Web para acceder ahora? (S/n): "
    read -r SHOW_WEB_PASS < /dev/tty
    if [[ "$SHOW_WEB_PASS" =~ ^[Ss]$ ]] || [[ -z "$SHOW_WEB_PASS" ]]; then
        echo -e "Contraseña Panel Web: ${GREEN}$WEB_ADMIN_PASS${NC}"
    else
        echo -e "Entendido. Recuerda consultar el archivo de credenciales."
    fi
    echo -e "--------------------------------------------------"

    echo -e "\n${BLUE}>>> INSTRUCCIONES DE CONEXIÓN <<<${NC}"
    echo -e "1. Abre una NUEVA terminal en tu ordenador local (no en este servidor)."
    echo -e "2. Ejecuta el siguiente comando para crear el túnel seguro:"
    echo -e "   ${YELLOW}ssh -L 8888:127.0.0.1:8888 -L 3000:127.0.0.1:3000 $SECURE_ADMIN@$DOMAIN_NAME${NC}"
    echo -e ""
    echo -e "3. Abre tu navegador web y accede a:"
    echo -e "   - Panel de Administración: ${GREEN}http://localhost:8888${NC}"
    echo -e "   - Monitorización Grafana:  ${GREEN}http://localhost:3000${NC}"
    echo -e ""
    echo -e "Si recibes 'Connection Refused', espera unos segundos a que los contenedores terminen de arrancar."
    echo -e "${GREEN}==================================================${NC}"
}

main
