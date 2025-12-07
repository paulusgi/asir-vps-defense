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

install_dependencies() {
    log_info "Actualizando repositorios e instalando dependencias base..."
    apt-get update -qq
    apt-get install -y -qq curl git ufw fail2ban software-properties-common

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
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Honeypot User Configuration (Allow Password)
Match User $HONEYPOT_USER
    PasswordAuthentication yes
    PermitEmptyPasswords no
    MaxAuthTries 5
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

create_users() {
    log_info "Iniciando Wizard de Usuarios..."

    # 1. Real Admin User
    echo -e "${YELLOW}>>> Configuración del ADMIN REAL (Tú)${NC}"
    # Force read from TTY to support curl | bash piping
    echo -n "Introduce el nombre para tu usuario administrador (ej: sys_ops): "
    read -r REAL_USER < /dev/tty
    
    if id "$REAL_USER" &>/dev/null; then
        log_warn "El usuario $REAL_USER ya existe."
    else
        useradd -m -s /bin/bash "$REAL_USER"
        usermod -aG sudo,docker "$REAL_USER"
        log_success "Usuario $REAL_USER creado."
    fi

    # Setup SSH Key for Real Admin
    local ASK_FOR_KEY=true
    
    # Check if user already has keys (e.g. from Cloud-Init)
    if [ -s "/home/$REAL_USER/.ssh/authorized_keys" ]; then
        echo -e "${YELLOW}¡Atención! Se han detectado claves SSH existentes para el usuario $REAL_USER.${NC}"
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
            mkdir -p "/home/$REAL_USER/.ssh"
            
            # Append key instead of overwrite
            if grep -qF "$SSH_KEY" "/home/$REAL_USER/.ssh/authorized_keys" 2>/dev/null; then
                log_info "La clave SSH ya estaba autorizada."
            else
                echo "$SSH_KEY" >> "/home/$REAL_USER/.ssh/authorized_keys"
                log_success "Clave SSH añadida correctamente."
            fi
        else
            log_warn "No has introducido ninguna clave. Asegúrate de poder acceder."
        fi
    fi

    # Ensure permissions are correct (Critical step)
    mkdir -p "/home/$REAL_USER/.ssh"
    chmod 700 "/home/$REAL_USER/.ssh"
    if [ -f "/home/$REAL_USER/.ssh/authorized_keys" ]; then
        chmod 600 "/home/$REAL_USER/.ssh/authorized_keys"
    fi
    chown -R "$REAL_USER:$REAL_USER" "/home/$REAL_USER/.ssh"
    log_success "Configuración SSH y permisos verificados para $REAL_USER."

    # 2. Honeypot User
    echo -e "${YELLOW}>>> Configuración del USUARIO CEBO (Honeypot)${NC}"
    echo -n "Introduce el nombre para el usuario cebo (ej: admin, support): "
    read -r HONEYPOT_USER < /dev/tty
    
    if id "$HONEYPOT_USER" &>/dev/null; then
        log_warn "El usuario $HONEYPOT_USER ya existe."
    else
        useradd -m -s /bin/bash "$HONEYPOT_USER"
        # Set a complex password for the honeypot user so bots can't actually login easily
        # but Fail2ban will catch the attempts
        echo "$HONEYPOT_USER:AsirVpsDefense2025!Secure" | chpasswd
        log_success "Usuario cebo $HONEYPOT_USER creado."
    fi

    # Return users for next steps
    export REAL_USER
    export HONEYPOT_USER
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
    cat > admin_credentials.txt <<EOF
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

NOTA: Guarda este archivo en un lugar seguro y bórralo del servidor si es necesario.
EOF
    chmod 600 admin_credentials.txt

    log_success "Semilla de base de datos generada (mysql/init/02-seed.sql)."
    log_success "Credenciales guardadas en 'admin_credentials.txt'."
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
    create_users
    configure_ssh "$REAL_USER" "$HONEYPOT_USER"
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
    
    # Step 4: Final Cleanup
    history -c
    
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}   DESPLIEGUE COMPLETADO CON ÉXITO                ${NC}"
    echo -e "${GREEN}==================================================${NC}"
    echo -e "IMPORTANTE: Se ha generado un archivo 'admin_credentials.txt' con todas las contraseñas."
    echo -e ""
    echo -e "INSTRUCCIONES DE ACCESO:"
    echo -e "1. Establece el Túnel SSH desde tu máquina local:"
    echo -e "   ${YELLOW}ssh -L 8888:127.0.0.1:8888 -L 3000:127.0.0.1:3000 <USUARIO>@<IP_O_DOMINIO>${NC}"
    echo -e "   (Ejemplo: ssh -L 8888:127.0.0.1:8888 -L 3000:127.0.0.1:3000 $REAL_USER@$DOMAIN_NAME)"
    echo -e ""
    echo -e "2. Abre el Panel Unificado en tu navegador:"
    echo -e "   URL: http://localhost:8888"
    echo -e "   Credenciales: admin / (Ver archivo admin_credentials.txt)"
    echo -e ""
    echo -e "NOTA: El WAF público escucha en los puertos 8000 (HTTP) y 8443 (HTTPS)"
    echo -e "      para no interferir con otros servicios web en el puerto 80/443."
    echo -e "${GREEN}==================================================${NC}"
}

main
