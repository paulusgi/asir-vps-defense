#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
umask 027
trap 'echo "[ERROR] Fallo en línea $LINENO" >&2' ERR

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
#
# Uso:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
# ==============================================================================

# Colores para la salida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin Color

# Variables Globales
ENV_FILE=".env"

# Bandera global para rastrear si necesitamos convertir el usuario actual más tarde
CONVERT_CURRENT_USER_TO_HONEYPOT=false
HONEYPOT_TARGET_USER=""
HONEYPOT_TARGET_PASS=""
SECURE_ADMIN=""
CURRENT_REAL_USER=""

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
    log_info "Actualizando repositorios e instalando dependencias base..."
    
    # Actualizar con lógica de reintento
    if ! apt-get update; then
        log_warn "Fallo al actualizar repositorios. Reintentando en 5s..."
        sleep 5
        apt-get update || log_error "No se pudieron actualizar los repositorios. Continuando bajo riesgo..."
    fi

    # Instalar con reintento y verificación
    log_info "Instalando paquetes (curl, git, ufw, fail2ban, rsyslog)..."
    if ! apt-get install -y psmisc curl git ufw fail2ban rsyslog; then
        log_warn "Fallo en la instalación de paquetes. Reintentando tras espera..."
        wait_for_apt_locks
        apt-get install -y psmisc curl git ufw fail2ban rsyslog
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
maxretry = 1

# Ignorar localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
filter  = sshd
maxretry = 1
EOF

    systemctl restart fail2ban
    systemctl is-active --quiet fail2ban
    systemctl enable fail2ban
    log_success "Fail2Ban configurado con política estricta (Bantime: 35d, MaxRetry: 1)."
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

    # Configurar Clave SSH para Admin Real
    local ASK_FOR_KEY=true
    
    # Comprobar si el usuario ya tiene claves (ej. desde Cloud-Init)
    if [ -s "/home/$SECURE_ADMIN/.ssh/authorized_keys" ]; then
        echo -e "${YELLOW}¡Atención! Se han detectado claves SSH existentes para el usuario $SECURE_ADMIN.${NC}"
        echo -n "¿Quieres usar las claves existentes y saltar el paso de añadir una nueva? (S/n): "
        read -r USE_EXISTING < /dev/tty
        # Por defecto Sí
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
            
            # Añadir clave en lugar de sobrescribir
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
EOF

    chmod 600 .env
    log_success "Archivo .env generado con credenciales seguras."
}

generate_db_seed() {
    log_info "Generando credenciales para el Panel de Administración..."
    
    WEB_ADMIN_PASS=$(openssl rand -base64 12)
    
    # Usar un contenedor PHP temporal para generar el hash Bcrypt
    # Usamos la imagen php:8.2-cli que es pequeña y estándar
    log_info "Calculando hash de contraseña seguro..."
    # ¿Asegurar que docker está corriendo o esperar? Debería estar instalado.
    # Podríamos necesitar hacer pull de la imagen primero para evitar timeout en el comando run, pero run hace pull.
    WEB_ADMIN_HASH=$(docker run --rm php:8.2-cli php -r "echo password_hash('$WEB_ADMIN_PASS', PASSWORD_DEFAULT);")
    
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
    log_success "Credenciales guardadas de forma segura en '$CRED_FILE'."
    export WEB_ADMIN_PASS
}

# ==============================================================================
# Ejecución Principal
# ==============================================================================


main() {
    clear
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}   ASIR VPS DEFENSE - INSTALADOR v1.1             ${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    check_root
    detect_context
    detect_os
    
    # Paso 1: Preparación del Sistema
    install_dependencies
    setup_firewall
    
    # Paso 2: Configuración de Usuario y Seguridad
    # Creamos el usuario PRIMERO para poder desplegar en su directorio home
    create_secure_admin
    handle_honeypot_logic
    
    configure_ssh "$SECURE_ADMIN" "$HONEYPOT_TARGET_USER"
    configure_fail2ban
    
    # Paso 3: Configuración del Proyecto en el Home del Usuario Seguro
    local PROJECT_DIR="/home/$SECURE_ADMIN/asir-vps-defense"
    log_info "Estableciendo directorio del proyecto en: $PROJECT_DIR"

    # Crear directorio si no existe
    if [ ! -d "$PROJECT_DIR" ]; then
        mkdir -p "$PROJECT_DIR"
    fi

    # Lógica para poblar el directorio
    if [ -f "docker-compose.yml" ]; then
        log_info "Copiando archivos de instalación locales (incluyendo parches)..."
        # Copiar contenido al home del nuevo usuario
        # Excluimos el directorio destino en sí mismo para evitar recursión si se ejecuta desde root
        rsync -av --exclude ".git" --exclude "asir-vps-defense" . "$PROJECT_DIR/" 2>/dev/null || cp -R . "$PROJECT_DIR/"
    else
        log_info "Descargando repositorio oficial..."
        # Limpiar dir por si acaso
        rm -rf "$PROJECT_DIR"
        git clone https://github.com/paulusgi/asir-vps-defense.git "$PROJECT_DIR"
    fi

    # Asegurar que la propiedad es correcta inmediatamente
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" "$PROJECT_DIR"
    
    # Cambiar contexto al nuevo directorio
    cd "$PROJECT_DIR" || exit 1
    log_success "Directorio de trabajo establecido: $(pwd)"

    # Paso 4: Despliegue de la Aplicación
    generate_env
    generate_db_seed
    
    # Corregir permisos para secretos generados
    chown "$SECURE_ADMIN:$SECURE_ADMIN" .env
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" mysql/init
    
    # Corregir permisos para webroot (usuario contenedor 101/1000 necesita acceso)
    log_info "Ajustando permisos de archivos web..."
    chown -R "$SECURE_ADMIN:$SECURE_ADMIN" src
    chmod -R 755 src

    log_info "Desplegando contenedores Docker..."
    docker compose up -d --build
    
    # Paso 5: Limpieza Final y Acciones Diferidas
    finalize_deferred_conversion
    history -c
    
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}   INSTALACIÓN FINALIZADA                         ${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
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
    echo -e "   ${YELLOW}ssh -L 8888:127.0.0.1:8888 $SECURE_ADMIN@$DOMAIN_NAME${NC}"
    echo -e ""
    echo -e "3. Abre tu navegador web y accede a:"
    echo -e "   - Panel de Administración + Métricas Loki: ${GREEN}http://localhost:8888${NC}"
    echo -e ""
    echo -e "Si recibes 'Connection Refused', espera unos segundos a que los contenedores terminen de arrancar."
    echo -e "${GREEN}==================================================${NC}"
}

main "$@"
