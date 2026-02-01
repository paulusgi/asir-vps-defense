# 🛡️ ASIR VPS Defense

![License](https://img.shields.io/badge/license-NonCommercial-red.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-green)

Panel de auditoría SSH para VPS Debian/Ubuntu. Monitoriza intentos de acceso y bans de Fail2Ban mediante Loki/Promtail. Acceso exclusivo por túnel SSH.

> 🎓 **Proyecto Final de Ciclo (ASIR)**

---

## 🚀 Características

| Función | Descripción |
|---------|-------------|
| **SSH Honeypot** | `PasswordAuthentication yes` global para capturar ataques; admin real solo por clave pública |
| **Fail2Ban** | 2 oportunidades (ban al 3er fallo) → ban 35 días; eventos visibles en el panel |
| **GeoIP Local** | Base GeoLite2-City.mmdb sin API externa |
| **Panel Seguro** | CSRF en login, rate-limit Nginx, cookies hardened |
| **Observabilidad** | Loki + Promtail con retención 31 días |
| **Backups** | Script interactivo con restauración completa, protección y cron |

---

## 🏗️ Arquitectura

| Componente | Tecnología | Puerto |
|------------|------------|--------|
| Panel | PHP 8.2 + Nginx | 127.0.0.1:8888 (túnel) |
| Base de datos | MySQL 8.0 | No expuesto |
| Logs | Loki 2.9.2 + Promtail | No expuesto |
| SSH | OpenSSH + Fail2Ban | 2929/tcp (configurable) |

**Sin WAF ni Grafana desplegados** — diseño minimalista centrado en SSH/Fail2Ban.

---

## 📦 Instalación

**Requisitos:** VPS Debian 11/12 o Ubuntu 20.04+, acceso root, clave SSH pública.

```bash
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/mainv2/deploy.sh | sudo bash
```

El asistente interactivo:
1. Solicita clave pública SSH
2. Crea usuario admin seguro
3. Configura honeypot SSH
4. Genera y cifra credenciales con `age`
5. Levanta contenedores Docker

---

## 🖥️ Acceso al Panel

1. **Túnel SSH** (ajusta puerto si lo cambiaste):
   ```bash
   ssh -p 2929 -L 8888:127.0.0.1:8888 tu_usuario@tu_vps
   ```

2. **Panel:** `http://localhost:8888`

3. **Credenciales:** En `~/admin_credentials.txt.age` (descifrar con `age`).

---

## ✅ Post-deploy

Ver [POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md) para comandos de verificación:
- Estado de contenedores
- Salud de MySQL, Loki, Promtail
- Fail2Ban y UFW
- Puertos en escucha

---

## 🔒 Seguridad Implementada

| Medida | Estado |
|--------|--------|
| CSRF en login | ✅ Implementado |
| Rate-limit Nginx | ✅ 5 req/min |
| Cookies httponly/samesite | ✅ Activo |
| Cifrado credenciales (age) | ✅ Activo |
| Fail2Ban (maxretry 3, ban 35d) | ✅ Activo |
| Healthchecks Docker | ✅ Loki + Promtail |
| Sanitización credenciales .env | ✅ Post-deploy |
| Backups con restauración | ✅ backups.sh |

**Limitaciones conocidas:**
- Sin roles admin/viewer diferenciados
- Sin MFA

---

## 💾 Gestión de Backups

El script `backups.sh` proporciona un menú interactivo para gestión completa:

```bash
sudo ./backups.sh          # Menú interactivo
sudo ./backups.sh create   # Crear backup (CLI)
sudo ./backups.sh list     # Listar backups
sudo ./backups.sh restore <archivo.tar.xz>  # Restaurar
```

**Contenido del backup:**
- Configuración: `docker-compose.yml`, `.env`, `nginx/`, `php/`
- Datos: `src/`, `mysql/init/`, datadir MySQL completo
- Logs: `promtail/`, `loki/`

**Características:**
- Protección de backups críticos (excluidos del prune automático)
- Programación de backups diarios vía cron
- Transferencia fácil con comandos `scp` generados
- Restauración completa con un comando

---

## 📄 Licencia

**Licencia de Uso No Comercial 1.0.0** (basada en PolyForm NC). Uso comercial no autorizado.

---

## ⚖️ Nota Ética

- **Propósito:** Monitorizar y endurecer VPS frente a ataques SSH con fines defensivos y formativos.
- **Prohibido:** Uso ofensivo, interceptar comunicaciones legítimas, explotar credenciales de atacantes.
- **Datos:** El honeypot recoge credenciales de atacantes; no almacenar, compartir ni reutilizar.
- **Responsabilidad:** El usuario es responsable de operar el sistema conforme a la ley de su jurisdicción.
