# 🛡️ ASIR VPS Defense - Automated Security Appliance

# ATENCIÓN ESTE README.md ES SOLO UNA PRUEBA.
## No esta actualizado y tiene errores.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Security](https://img.shields.io/badge/Security-Hardened-green)

**ASIR VPS Defense** es una solución integral de seguridad diseñada para desplegarse en servidores VPS limpios (Debian/Ubuntu). Transforma un servidor básico en una fortaleza monitorizada utilizando **Defensa en Profundidad**, con mínima superficie expuesta (solo SSH).

> 🎓 **Proyecto Final de Ciclo (ASIR):** Administración de Sistemas Informáticos en Red.

---

## 🚀 Características Principales

*   🧱 **Firewall de host (UFW) mínimo:** Solo expone SSH (22) con rate-limit; el resto queda cerrado por defecto.
*   🍯 **SSH Honeypot Inteligente:** "Split Authentication". Admin por llave pública; usuario cebo con password controlada para disparar bans.
*   👁️ **Observabilidad de acceso:** Promtail + Loki alimentan un panel nativo que muestra actividad SSH y Fail2Ban en tiempo real.
*   🔒 **Acceso Zero-Trust:** El panel de administración no está expuesto a internet; solo vía túnel SSH a `127.0.0.1:8888`.
*   ⚡ **Despliegue Automatizado:** Un único script en Bash configura host, Docker, usuarios y firewall en minutos.

## 🛠️ Arquitectura Técnica

El sistema utiliza **Docker Compose** para orquestar servicios aislados en redes seguras:

| Servicio | Tecnología | Función | Puerto (Host) |
|----------|------------|---------|---------------|
| **Panel** | PHP 8.2 + Nginx | Dashboard de gestión y métricas SSH/Fail2Ban | `127.0.0.1:8888` (solo túnel SSH) |
| **DB** | MySQL 8.0 | Gestión de usuarios y auditoría | No expuesto (red interna) |
| **Logs** | Loki + Promtail | Ingesta y almacenamiento de logs de SSH y Fail2Ban | No expuesto (red interna) |
| **SSH** | OpenSSH + Fail2Ban | Acceso de administración y honeypot | `22/tcp` |

> Nota: El WAF queda deshabilitado/no publicado por defecto. Si en el futuro se expone una aplicación web, se puede reactivar y publicar un servicio detrás de él.

## 📦 Instalación Rápida

### Requisitos Previos (Best Practices)
Para garantizar un despliegue limpio y seguro, se recomienda:
1.  **VPS Limpio:** Una instalación fresca de Debian 11/12 o Ubuntu 20.04/22.04.
2.  **Acceso Inicial:** Conéctate como `root` (o un usuario con `sudo` completo).
    *   *Nota:* No es necesario pre-configurar usuarios complejos en el panel de tu proveedor (Contabo, Hetzner, AWS). El script se encargará de crear la estructura de usuarios segura.
3.  **Clave SSH:** Ten a mano tu clave pública (archivo `.pub`) para configurar el acceso del administrador final.

### Comando de Despliegue
Conéctate a tu VPS y ejecuta:

```bash
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/main/deploy.sh | sudo bash
```

El asistente interactivo te guiará para:
1.  Crear tu usuario administrador (Key-only).
2.  Configurar el usuario cebo (Honeypot).
3.  Generar credenciales seguras automáticamente.

## 🖥️ Acceso al Panel de Control

Por seguridad, el panel **no es accesible desde internet**. Solo vía túnel SSH:

1.  **Túnel desde tu PC:**
    ```bash
    ssh -L 8888:127.0.0.1:8888 tu_usuario@tu_vps_ip
    ```

2.  **Navegador:**
    *   Abre `http://localhost:8888`
    *   Credenciales en `~/admin_credentials.txt` (usuario admin, password generada).

## 🛡️ Estrategia de Seguridad (Honeypot)

El sistema configura SSH (`/etc/ssh/sshd_config`) para permitir autenticación por contraseña **solo** para un usuario cebo.
*   Los bots atacan al usuario cebo.
*   **Fail2Ban** detecta los fallos y banea la IP.
*   **Promtail** envía el log a **Loki**.
*   Tú ves el ataque en tiempo real en el **panel nativo**.

## 📄 Licencia

Este proyecto es de código abierto bajo la licencia MIT. Diseñado con fines educativos y de demostración de competencias en administración de sistemas.
