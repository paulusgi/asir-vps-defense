<p align="center">
  <img src="https://img.shields.io/badge/Debian-11%2F12-A81D33?style=for-the-badge&logo=debian" alt="Debian">
  <img src="https://img.shields.io/badge/Ubuntu-20.04+-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Ubuntu">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-Non--Commercial-red?style=for-the-badge" alt="License">
</p>

<h1 align="center">ASIR VPS Defense</h1>

<p align="center">
  <strong>Sistema de defensa, hardening y observabilidad para VPS Linux</strong><br>
  <em>Proyecto Final de Ciclo Superior — ASIR 2025/2026</em>
</p>

---

## Resumen del proyecto

Sistema automatizado de defensa y observabilidad para servidores VPS Linux expuestos a Internet, centrado en el vector SSH. El proyecto combina **hardening del acceso administrativo**, despliegue de un **honeypot SSH** (Cowrie) para captura de telemetría de ataques, **bloqueo automático** con Fail2Ban, **centralización de logs** con Loki/Promtail y un **panel de métricas privado** accesible exclusivamente mediante túnel SSH.

El enfoque se basa en el principio de **mínima exposición**: el único servicio publicado a Internet es SSH (puerto 22 para el honeypot y un puerto alternativo para administración). El panel web no se expone públicamente.

### Objetivos del proyecto

| ID | Objetivo | Descripción |
|----|----------|-------------|
| OE1 | Hardening SSH | Acceso administrativo por clave pública en puerto alternativo; rechazo de contraseña |
| OE2 | Honeypot SSH | Cowrie en puerto 22, captura de intentos de autenticación y sesiones |
| OE3 | Respuesta automática | Fail2Ban con política estricta (ban de 35 días) sobre el SSH real |
| OE4 | Centralización de logs | Loki + Promtail para ingesta de auth.log, fail2ban.log y logs de Cowrie |
| OE5 | Panel privado | Visualización de métricas con geolocalización offline, solo accesible por túnel SSH |
| OE6 | Operación | Verificación post-despliegue y gestor de copias de seguridad |

---

## Arquitectura del sistema

```
Internet                         VPS Host
────────                    ┌────────────────────────────────────────────┐
                            │                                            │
  Atacante ──► :22 ─────────┼──► Cowrie (honeypot SSH)                   │
                            │       └─► /var/log/cowrie/ ──► Promtail    │
                            │                                  │         │
  Admin ────► :2929 ────────┼──► OpenSSH real (solo clave)     │         │
                            │       └─► /var/log/auth.log ──►  │         │
                            │                                  │         │
                            │   Fail2Ban ──► ban IPs           │         │
                            │       └─► /var/log/fail2ban.log ─┘         │
                            │                                  │         │
                            │                              Promtail      │
                            │                                  │         │
                            │                                Loki        │
                            │                                  │         │
                            │   127.0.0.1:8888 ──► Nginx ──► PHP ───┘    │
                            │       Panel privado (túnel SSH)    │       │
                            │                                  MySQL     │
                            └────────────────────────────────────────────┘
```

### Componentes

| Componente | Tecnología | Función |
|------------|-----------|---------|
| Honeypot SSH | Cowrie (contenedor) | Captura ataques en puerto 22, registra credenciales y sesiones TTY |
| SSH real | OpenSSH (host) | Acceso administrativo en puerto alternativo, solo clave pública |
| Bloqueo automático | Fail2Ban (host) | Detección de intentos fallidos en SSH real y ban automático |
| Centralización de logs | Loki + Promtail (contenedores) | Ingesta de auth.log, fail2ban.log, cowrie.log y cowrie.json |
| Panel de métricas | Nginx + PHP 8.2-FPM (contenedores) | Dashboard con métricas, tabla de ataques, mapa de geolocalización |
| Base de datos | MySQL 8.0 (contenedor) | Autenticación del panel, auditoría y caché GeoIP |
| Geolocalización | GeoLite2-City (local) | Enriquecimiento offline de IPs sin dependencia de APIs externas |

### Redes Docker

| Red | Tipo | Contenedores | Propósito |
|-----|------|-------------|-----------|
| `frontend_net` | bridge | Cowrie, Nginx, PHP | Acceso al panel y al honeypot |
| `backend_net` | internal | PHP, MySQL, Loki, Promtail | Aislamiento de servicios internos sin puertos expuestos |

### Puertos

| Puerto | Binding | Servicio | Exposición |
|--------|---------|----------|------------|
| 22/tcp | 0.0.0.0 | Cowrie (honeypot) | Internet (intencionado) |
| 2929/tcp | 0.0.0.0 | OpenSSH real | Internet (configurable) |
| 8888/tcp | 127.0.0.1 | Panel Nginx | Solo loopback (requiere túnel SSH) |

---

## Requisitos

| Requisito | Detalle |
|-----------|---------|
| **Sistema operativo** | Debian 11/12 o Ubuntu 20.04+ |
| **Acceso** | Root o sudo |
| **SSH** | Clave pública del administrador disponible |
| **Conectividad** | Internet (para instalación de dependencias y descarga de GeoLite2) |

---

## Instalación

El despliegue se realiza mediante un instalador interactivo que automatiza todas las fases:

```bash
sudo bash -c 'git clone https://github.com/paulusgi/asir-vps-defense.git /opt/asir-vps-defense && cd /opt/asir-vps-defense && ./deploy.sh'
```

El instalador ejecuta los siguientes pasos:

1. **Preparación del sistema**: instalación de dependencias (Docker, UFW, Fail2Ban, rsyslog).
2. **Creación de usuarios**: administrador seguro (clave SSH) y usuario honeypot.
3. **Configuración SSH**: split authentication (admin = solo clave pública, resto = contraseña para captura).
4. **Firewall UFW**: política deny incoming, puertos 22 y 2929 abiertos.
5. **Fail2Ban**: jail `sshd` con ban de 35 días, detección en 10 minutos.
6. **Despliegue Docker**: construcción y arranque de contenedores con `docker compose up`.
7. **Generación de credenciales**: contraseña del panel (bcrypt), Docker Secrets para MySQL, cifrado con `age`.
8. **Preparación de backups**: volumen LVM o loop, primer backup opcional.

> El instalador es **idempotente**: si se interrumpe, puede re-ejecutarse sin duplicar pasos gracias a marcas de estado persistentes.

---

## Acceso al panel

El panel no está expuesto a Internet. Para acceder se establece un túnel SSH:

```bash
ssh -p 2929 -L 8888:127.0.0.1:8888 <admin_user>@<IP_VPS> -N
```

Tras establecer el túnel, abrir `http://localhost:8888` en el navegador local.

Las credenciales de acceso se generan durante la instalación y se almacenan cifradas en `~/admin_credentials.txt.age`. Para descifrarlas:

```bash
age -d -i ~/.ssh/<clave_privada> -o credenciales.txt ~/admin_credentials.txt.age
```

---

## Medidas de seguridad implementadas

| Capa | Medida | Descripción |
|------|--------|-------------|
| SSH | Split Authentication | Admin: solo clave pública. Honeypot: contraseña (captura). Separación por `Match User` en sshd_config |
| SSH | Algoritmos post-quantum | `sntrup761x25519-sha512@openssh.com` como primer KEX |
| SSH | Hardening | `MaxAuthTries 1`, `LoginGraceTime 20`, `PermitRootLogin no` |
| Red | Firewall UFW | Política deny incoming; solo puertos 22 y SSH real abiertos |
| Red | Panel en loopback | Binding `127.0.0.1:8888`; inaccesible sin túnel SSH |
| Red | Red interna Docker | MySQL y Loki en `backend_net` (internal), sin puertos expuestos al host |
| Aplicación | CSRF | Token `bin2hex(random_bytes(32))` validado con `hash_equals` en login |
| Aplicación | Cookies endurecidas | `HttpOnly`, `SameSite=Strict`, `Secure` dinámico |
| Aplicación | Auditoría | Registro de LOGIN_SUCCESS/LOGIN_FAILED con IP y timestamp en MySQL |
| Contenedores | Hardening Docker | `read_only`, `no-new-privileges`, `cap_drop: ALL`, `tmpfs`, `mem_limit`, `pids_limit` |
| Credenciales | Docker Secrets | Passwords MySQL en archivos con permisos 600, leídos desde `/run/secrets/` |
| Credenciales | Cifrado age | Credenciales del panel cifradas con clave pública SSH del administrador |
| Observabilidad | Retención | Loki con retención de 31 días y compactación automática |

---

## Estructura del repositorio

```
.
├── deploy.sh                    # Instalador interactivo automatizado
├── backups.sh                   # Gestor de copias de seguridad
├── docker-compose.yml           # Orquestación de contenedores
├── MEMORIA_ASIR_VPS_DEFENSE_FINAL.md  # Memoria técnica del proyecto
├── POSTDEPLOY_CHECKS.md         # Checklist de verificación post-despliegue
├── LICENSE                      # Licencia de uso no comercial
│
├── cowrie/
│   ├── cowrie.cfg               # Configuración del honeypot (banner, backend, logs)
│   └── userdb.txt               # Base de credenciales (wildcard: acepta todo)
│
├── nginx/
│   └── conf.d/
│       └── admin.conf           # Configuración del panel privado (cabeceras, FastCGI)
│
├── php/
│   ├── Dockerfile               # Imagen PHP 8.2-FPM con extensión maxminddb
│   ├── conf.d/custom.ini        # Configuración PHP (seguridad, opcache)
│   └── pool.d/www.conf          # Pool PHP-FPM (tuning de workers)
│
├── src/
│   ├── index.php                # Panel web (login, dashboard, API de métricas)
│   └── includes/
│       ├── loki_client.php      # Cliente HTTP para Loki (query, query_range)
│       └── security_metrics.php # Extracción de métricas de Fail2Ban, SSH y Cowrie
│
├── mysql/
│   └── init/
│       └── 01-schema.sql        # Esquema inicial (users, audit_log, ip_geo_cache)
│
├── loki/
│   └── config.yml               # Configuración de Loki (retención 31d, caché)
│
├── promtail/
│   └── config.yml               # Configuración de Promtail (4 jobs: auth, fail2ban, cowrie, cowrie_json)
│
├── geoip/                       # Base de datos GeoLite2-City (descargada en deploy)
│
└── evidencias/                  # Evidencias técnicas organizadas por bloque
    ├── 01_infraestructura/      # EV-01 a EV-05: puertos, contenedores, firewall, banner
    ├── 02_honeypot_cowrie/      # EV-06 a EV-10: logs, sesiones TTY, prueba controlada
    ├── 03_fail2ban/             # EV-11 a EV-13: estado jail, bans, fragmento de log
    ├── 04_observabilidad/       # EV-14 a EV-17: Loki ready, jobs Promtail, consultas LogQL
    ├── 05_panel_privado/        # EV-18 a EV-23: túnel SSH, dashboard, mapa, gráfica
    ├── 06_ssh_real/             # EV-25 a EV-27: acceso por clave, rechazo contraseña, nmap
    └── 07_pipeline_completo/    # EV-28 a EV-29: ciclo ataque→Loki, ciclo intento→ban
```

---

## Evidencias técnicas

Se documentaron 28 evidencias numeradas (EV-01 a EV-29) organizadas en 7 bloques de validación. Cada evidencia incluye el comando ejecutado, la captura de pantalla y una descripción de lo que demuestra.

| Bloque | Evidencias | Qué valida |
|--------|------------|------------|
| Infraestructura | EV-01 a EV-05 | Puertos, contenedores healthy, firewall, banner honeypot |
| Honeypot Cowrie | EV-06 a EV-10 | Captura de ataques reales, sesiones TTY, prueba con Hydra |
| Fail2Ban | EV-11 a EV-13 | Jail activa, IPs baneadas, fragmento de log con Found+Ban |
| Observabilidad | EV-14 a EV-17 | Loki ready, jobs Promtail, consultas LogQL para cowrie y fail2ban |
| Panel privado | EV-18 a EV-23 | Bloqueo externo, túnel SSH, dashboard, tabla de ataques, mapa, gráfica |
| SSH real | EV-25 a EV-27 | Login por clave, rechazo de contraseña, separación de servicios con nmap |
| Pipeline completo | EV-28, EV-29 | Ciclo ataque→Cowrie→Promtail→Loki y ciclo intento→Fail2Ban→ban |

Para el detalle completo, consultar [evidencias/README.md](evidencias/README.md) y las carpetas de cada bloque con sus respectivos archivos `METODOLOGIA.md`.

---

## Copias de seguridad

```bash
sudo ./backups.sh
```

Gestor interactivo con las siguientes operaciones:

| Comando | Función |
|---------|---------|
| `create` | Crea un backup completo (configuración, código, datadir MySQL) |
| `list` | Lista backups disponibles con fecha y tamaño |
| `restore <fichero>` | Restaura un backup existente |
| `prune --keep N` | Conserva solo los N backups más recientes |
| `schedule <HH:MM>` | Programa backup automático (diario, semanal o mensual) |
| `delete <fichero>` | Elimina un backup concreto |

El contenido de cada backup incluye: `docker-compose.yml`, `.env`, configuraciones de servicios (`nginx/`, `php/`, `promtail/`, `loki/`), código fuente (`src/`), inicialización SQL (`mysql/init/`) y copia física del datadir de MySQL.

---

## Verificación post-despliegue

Consultar [POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md) para el checklist completo. Verificaciones principales:

```bash
# Estado de contenedores (todos deben mostrar Up/healthy)
docker compose ps

# Puertos (22=Cowrie, 2929=SSH real, 127.0.0.1:8888=panel)
sudo ss -tulpen | grep -E ':(22|2929|8888)\s'

# Fail2Ban activo
fail2ban-client status sshd

# Panel accesible desde loopback
curl -I http://127.0.0.1:8888

# Loki operativo
docker exec asir_loki wget -qO- http://localhost:3100/ready
```

---

## Alcance del MVP

### Implementado y validado

- Honeypot Cowrie operativo con captura de ataques reales en puerto 22.
- SSH real en puerto alternativo con autenticación exclusiva por clave pública.
- Fail2Ban con detección y ban automático (política de 35 días).
- Loki y Promtail ingiriendo logs de auth, fail2ban, cowrie (texto y JSON).
- Panel web con autenticación, métricas, tabla de ataques, mapa de geolocalización y gráfica temporal.
- Panel accesible exclusivamente mediante túnel SSH (binding a loopback).
- Geolocalización offline con GeoLite2-City.
- Gestor de backups con creación, rotación, restauración y programación.
- Despliegue automatizado e idempotente.

### Fuera de alcance (trabajo futuro)

- Exposición de servicios HTTP/HTTPS a Internet (por diseño, panel no publicado).
- Grafana como panel adicional de visualización.
- Alertas en tiempo real (umbrales de bans/hora, notificaciones).
- Sistema de roles efectivo en el panel (admin/viewer).
- Cobertura de otros vectores de ataque (RDP, HTTP).

---

## Documentación del proyecto

| Documento | Descripción |
|-----------|-------------|
| [MEMORIA_ASIR_VPS_DEFENSE_FINAL.md](MEMORIA_ASIR_VPS_DEFENSE_FINAL.md) | Memoria técnica completa del proyecto |
| [POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md) | Checklist de verificación post-despliegue |
| [evidencias/README.md](evidencias/README.md) | Índice de 28 evidencias técnicas con relación a objetivos |
| [LICENSE](LICENSE) | Licencia de uso no comercial |

---

## Licencia

Uso exclusivamente no comercial. Consultar [LICENSE](LICENSE) para los términos completos.

---

<p align="center">
  <strong>Aviso importante</strong>
</p>

<p align="center">
  Este proyecto tiene fines <strong>educativos y defensivos</strong>.<br>
  El honeypot captura credenciales de atacantes — no deben almacenarse, compartirse ni reutilizarse.<br>
  Uso responsable y conforme a la legislación vigente.
</p>
