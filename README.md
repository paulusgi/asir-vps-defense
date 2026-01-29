# 🛡️ ASIR VPS Defense - Automated Security Appliance

# Estado actual (modo demo)
## Panel por túnel SSH centrado en SSH/Fail2Ban.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Security](https://img.shields.io/badge/Security-Hardened-green)

**ASIR VPS Defense** despliega en un VPS Debian/Ubuntu un panel PHP (sólo accesible por túnel SSH) para ver intentos SSH y bans de Fail2Ban, apoyado en MySQL y Loki/Promtail. No expone HTTP.

> 🎓 **Proyecto Final de Ciclo (ASIR):** Administración de Sistemas Informáticos en Red.


## 🚀 Características Principales

*   🧱 **UFW básico:** Abre 22/tcp; panel solo en loopback:8888 (túnel SSH).
*   🍯 **SSH Honeypot (demo):** PasswordAuthentication ON para registrar intentos; admin real solo por clave pública.
*   👁️ **Observabilidad:** Promtail + Loki almacenan auth/fail2ban; panel muestra contadores y tablas.
*   🔒 **Panel no expuesto:** Solo túnel SSH a `127.0.0.1:8888`.
*   ⚡ **Deploy automático:** `deploy.sh` instala dependencias, crea usuarios, genera `.env` y levanta Docker Compose.

## 🛠️ Arquitectura Técnica

El sistema utiliza **Docker Compose** para orquestar servicios aislados en redes seguras:

| Servicio | Tecnología | Función | Puerto (Host) |
|----------|------------|---------|---------------|
| **Panel** | PHP 8.2 + Nginx | Dashboard SSH/Fail2Ban | `127.0.0.1:8888` (túnel) |
| **DB** | MySQL 8.0 | Usuarios, auditoría, cache GeoIP | No expuesto |
| **Logs** | Loki + Promtail | auth.log y fail2ban.log del host | No expuesto |
| **SSH** | OpenSSH + Fail2Ban | Admin clave; honeypot password | `22/tcp` |

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
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/mainv2/deploy.sh | sudo bash
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

## 🛡️ Estrategia (demo)

- `PasswordAuthentication yes` global para ver usuarios/contraseñas atacados; el admin real exige clave pública.
- Fail2Ban bantime 35d, maxretry 1 (actual). Eventos vistos en panel vía Loki.

## 📄 Licencia

MIT. Proyecto educativo/demostrativo.
