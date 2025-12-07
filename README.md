# 🛡️ ASIR VPS Defense - Automated Security Appliance

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Security](https://img.shields.io/badge/Security-Hardened-green)

**ASIR VPS Defense** es una solución integral de seguridad diseñada para desplegarse en servidores VPS limpios (Debian/Ubuntu). Transforma un servidor básico en una fortaleza monitorizada utilizando estrategias de **Defensa en Profundidad**.

> 🎓 **Proyecto Final de Ciclo (ASIR):** Administración de Sistemas Informáticos en Red.

---

## 🚀 Características Principales

*   🧱 **WAF (Web Application Firewall):** Nginx + ModSecurity con reglas OWASP CRS para bloquear ataques web (SQLi, XSS, etc.).
*   🍯 **SSH Honeypot Inteligente:** Estrategia de "Split Authentication". El administrador usa llaves SSH, mientras que un usuario "cebo" permite contraseñas para atraer y banear bots.
*   👁️ **Observabilidad Completa:** Stack PLG (Promtail, Loki, Grafana) preconfigurado para visualizar ataques en tiempo real.
*   🔒 **Acceso Zero-Trust:** El panel de administración no está expuesto a internet. Solo es accesible mediante Túneles SSH.
*   ⚡ **Despliegue Automatizado:** Un único script en Bash configura el host, Docker, usuarios y firewall en minutos.

## 🛠️ Arquitectura Técnica

El sistema utiliza **Docker Compose** para orquestar servicios aislados en redes seguras:

| Servicio | Tecnología | Función | Puerto (Host) |
|----------|------------|---------|---------------|
| **WAF** | Nginx + ModSec | Filtrado de tráfico HTTP/S | `8000` / `8443` |
| **Panel** | PHP 8.2 + Nginx | Dashboard de Gestión Unificado | `8888` (Localhost) |
| **DB** | MySQL 8.0 | Gestión de Usuarios y Auditoría | *Aislado* |
| **Logs** | Loki + Promtail | Ingesta y almacenamiento de logs | *Aislado* |
| **Monitor**| Grafana | Visualización de amenazas | `3000` (Localhost) |

## 📦 Instalación Rápida

Conéctate a tu VPS por SSH y ejecuta el siguiente comando:

```bash
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/main/deploy.sh | sudo bash
```

El asistente interactivo te guiará para:
1.  Crear tu usuario administrador (Key-only).
2.  Configurar el usuario cebo (Honeypot).
3.  Generar credenciales seguras automáticamente.

## 🖥️ Acceso al Panel de Control

Por seguridad, el panel de control **no es accesible desde internet**. Debes usar un Túnel SSH.

1.  **Establece el túnel desde tu PC:**
    ```bash
    ssh -L 8888:127.0.0.1:8888 -L 3000:127.0.0.1:3000 tu_usuario@tu_vps_ip
    ```

2.  **Accede en tu navegador:**
    *   Abre `http://localhost:8888`
    *   Inicia sesión con las credenciales generadas en la instalación (`admin_credentials.txt`).

## 🛡️ Estrategia de Seguridad (Honeypot)

El sistema configura SSH (`/etc/ssh/sshd_config`) para permitir autenticación por contraseña **solo** para un usuario cebo.
*   Los bots atacan al usuario cebo.
*   **Fail2Ban** detecta los fallos y banea la IP.
*   **Promtail** envía el log a **Loki**.
*   Tú ves el ataque en tiempo real en **Grafana**.

## 📄 Licencia

Este proyecto es de código abierto bajo la licencia MIT. Diseñado con fines educativos y de demostración de competencias en administración de sistemas.
