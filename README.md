# 🛡️ ASIR VPS Defense - Automated Security Appliance

![License](https://img.shields.io/badge/license-NonCommercial-red.svg)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Security](https://img.shields.io/badge/Security-Hardened-green)

**ASIR VPS Defense** despliega en Debian/Ubuntu un panel PHP (sólo por túnel SSH) para auditar intentos SSH y bans de Fail2Ban, con MySQL y Loki/Promtail como soporte. HTTP no se expone.

> 🎓 **Proyecto Final de Ciclo (ASIR)**

## 🚀 Características

*   🧱 **Red y acceso:** UFW abre 22/tcp; el panel vive en loopback:8888 y se accede con túnel SSH.
*   🍯 **SSH honeypot (demo):** PasswordAuthentication ON para cebar ataques; admin real sólo por clave pública.
*   👁️ **Observabilidad:** Promtail + Loki para auth/fail2ban; panel con métricas y tablas.
*   ⚡ **Deploy asistido:** `deploy.sh` instala dependencias, crea usuarios, genera `.env` y levanta Docker Compose.

## 🛠️ Arquitectura

| Servicio | Tecnología | Función | Puerto (host) |
|----------|------------|---------|---------------|
| Panel | PHP 8.2 + Nginx | Dashboard SSH/Fail2Ban | 127.0.0.1:8888 (túnel) |
| DB | MySQL 8.0 | Usuarios, auditoría, cache GeoIP | No expuesto |
| Logs | Loki + Promtail | auth.log y fail2ban.log del host | No expuesto |
| SSH | OpenSSH + Fail2Ban | Admin por clave; honeypot por password | 22/tcp |

## 📦 Instalación rápida

**Requisitos:** VPS Debian 11/12 o Ubuntu 20.04/22.04, acceso root/sudo, clave pública SSH (.pub).

**Despliegue:**

```bash
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/mainv2/deploy.sh | sudo bash
```

El asistente interactivo solicita la clave pública, crea el admin, configura el honeypot y genera las credenciales.

## 🖥️ Acceso al panel

1. Túnel desde tu equipo:
   ```bash
   ssh -L 8888:127.0.0.1:8888 tu_usuario@tu_vps_ip
   ```
2. URL del panel: `http://localhost:8888`

## 🛡️ Estrategia (demo)

- `PasswordAuthentication yes` global para registrar intentos; el admin real exige clave pública.
- Fail2Ban: 2 intentos fallidos banean 35 días; los eventos se ven en el panel vía Loki.
- GeoIP local con GeoLite2-City para geolocalizar IPs atacantes.
- MySQL registra también los inicios de sesión en el panel.

## ✅ Post-deploy checks

Consulta los comandos rápidos de verificación en [POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md). Incluye estado de contenedores, salud de MySQL, Fail2Ban, UFW y puertos en escucha.


## 🏭 Uso en Producción

- **Alcance del despliegue:** Enfocado a monitorear SSH/Fail2Ban en un único VPS. El panel sigue en loopback:8888 y sólo debe accederse por túnel SSH. No expone HTTP público ni incluye WAF o Grafana.
- **Proceso recomendado:** VPS limpio Debian/Ubuntu, ejecutar `deploy.sh` como root y usar una clave pública segura (ed25519 o RSA 4096). El usuario admin queda con `PasswordAuthentication no`; el honeypot conserva password para telemetría de ataques.
- **Seguridad operativa:** Mantén UFW sólo con 22/tcp, revisa que `sshd_config` no abra otros puertos, y valida Fail2Ban (`maxretry 2`, `bantime 35d`) ajustando estos valores si tu entorno requiere mayor tolerancia a falsos positivos. No copies el archivo descifrado de credenciales a ubicaciones compartidas; bórralo tras guardarlo en un gestor.
- **GeoIP local:** El deploy descarga `GeoLite2-City.mmdb` desde el CDN público de jsDelivr (sin API key) y lo monta en el contenedor; si no se logra descargar, el panel muestra "Desconocido". Para actualizar la base, basta con reejecutar `deploy.sh`.
- **Limitaciones conocidas:** Proyecto en modo demo; sólo cubre SSH/Fail2Ban y no tiene alta disponibilidad ni multi-tenant. El panel no implementa rate-limit/CSRF ni MFA. No hay backup automático de MySQL ni rotación de logs de Loki fuera de su configuración por defecto. Estas limitaciones son deliberadas y coherentes con el objetivo formativo y experimental del proyecto.
- **Buenas prácticas:** Ejecuta los checks de [POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md) tras cada instalación o cambio; actualiza el sistema operativo antes de desplegar; rota las claves SSH y credenciales periódicamente; mantén los contenedores actualizados con `docker compose pull && docker compose up -d`.


## 📄 Licencia

Licencia de Uso No Comercial 1.0.0 (basada en PolyForm Noncommercial 1.0.0). Uso no comercial permitido; usos con finalidad comercial no están autorizados. Véase el archivo LICENSE para el texto completo.

## ⚖️ Nota Ética

- **Propósito previsto:** Monitorizar y endurecer un VPS frente a ataques SSH, registrando intentos y bans para análisis defensivo y formativo.
- **Usos no permitidos:** No emplear para fines ofensivos, para interceptar comunicaciones legítimas ni para explotar credenciales obtenidas de atacantes. El proyecto no autoriza uso con finalidad comercial.
- **Datos y privacidad:** El honeypot recoge usuarios/contraseñas enviados por atacantes; evita almacenar, compartir o reutilizar esas credenciales. Comprueba la legalidad de operar un honeypot en tu jurisdicción y notifica a las partes interesadas según tus políticas.
- **Responsabilidad:** El usuario final es responsable de configurar y operar el sistema de forma ética y conforme a la ley. La documentación no garantiza protección completa; revisa y adapta la configuración a tu entorno. Si no estás seguro de que un uso concreto sea ético o legal, no lo implementes.
