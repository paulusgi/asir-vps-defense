<p align="center">
  <img src="https://img.shields.io/badge/Debian-11%2F12-A81D33?style=for-the-badge&logo=debian" alt="Debian">
  <img src="https://img.shields.io/badge/Ubuntu-20.04+-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Ubuntu">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-Non--Commercial-red?style=for-the-badge" alt="License">
</p>

<h1 align="center">🛡️ ASIR VPS Defense</h1>

<p align="center">
  <strong>Sistema de defensa, hardening y monitorización para VPS</strong><br>
  <em>Proyecto Final de Ciclo — ASIR 25/26</em>
</p>

<p align="center">
  Convierte tu servidor en un honeypot SSH inteligente.<br>
  Captura ataques, geolocalízalos y visualízalos en un panel privado.
</p>

---

## 💡 La idea

Los VPS expuestos a Internet reciben ataques SSH constantemente. En lugar de solo bloquearlos, ¿por qué no estudiarlos?

Este proyecto nació con dos objetivos:

1. **Aprender hardening de VPS** — Configurar SSH de forma segura, gestionar firewalls, implementar Fail2Ban, aislar servicios con Docker
2. **Observar al atacante** — Crear un honeypot que atraiga, registre y banee intentos de intrusión

El resultado es una infraestructura que:

```
┌─────────────────────────────────────────────────────────────────┐
│  🎯 Atrae atacantes    →  SSH abierto a contraseña (honeypot)   │
│  🔐 Protege al admin   →  Autenticación solo por clave pública  │
│  📊 Registra todo      →  Loki + panel web por túnel SSH        │
│  🚫 Banea agresivamente →  Fail2Ban con política de 35 días     │
│  🌍 Geolocaliza        →  Base de datos local, sin APIs         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔮 Visión de futuro

Este proyecto es el primer paso hacia algo más grande:

> **Una herramienta completa de securización, configuración y monitoreo de VPS**
> 
> Con alertas en tiempo real, dashboards avanzados, detección de anomalías y hardening automatizado para diferentes servicios.

Por ahora, el foco está en SSH y la base de observabilidad.

---

## 📋 Requisitos

| Requisito | Detalle |
|-----------|---------|
| **Sistema** | Debian 11/12 o Ubuntu 20.04+ |
| **Acceso** | Root (sudo) |
| **SSH** | Tu clave pública a mano |

---

## 🚀 Instalación

```bash
curl -sL https://raw.githubusercontent.com/paulusgi/asir-vps-defense/mainv2/deploy.sh | sudo bash
```

El instalador interactivo te guía: crea tu usuario admin, configura el honeypot, genera credenciales cifradas y levanta los contenedores.

> **💡 Sobre el puerto SSH**  
> Por defecto usa el **2929**. Si quieres maximizar la captura de ataques, pon el **22** (donde los bots escanean). El instalador te pregunta.

---

## 🖥️ Acceder al panel

El panel **no está expuesto a Internet**. Solo es accesible mediante túnel SSH:

```bash
# Ajusta el puerto si elegiste otro durante la instalación
ssh -p 2929 -L 8888:127.0.0.1:8888 tu_usuario@tu_vps
```

Abre `http://localhost:8888` en tu navegador.

> **🔑 Credenciales**  
> Están en `~/admin_credentials.txt.age`. Descífralas con `age` y tu clave privada SSH.

---

## 🏗️ Arquitectura

```
                    ┌──────────────────────────────────────┐
                    │           TU MÁQUINA LOCAL           │
                    │  localhost:8888 ◄── túnel SSH ──┐    │
                    └──────────────────────────────────┼────┘
                                                       │
┌──────────────────────────────────────────────────────┼────────────┐
│                         VPS                          │            │
│  ┌─────────────────────────────────────────────────┐ │            │
│  │ 🔒 SSH (puerto configurable)                    │◄┘            │
│  │    ├─ Admin: solo clave pública                 │              │
│  │    └─ Resto: contraseña (honeypot) → Fail2Ban   │              │
│  └─────────────────────────────────────────────────┘              │
│                              │                                    │
│  ┌───────────────────────────┼───────────────────────────────┐    │
│  │                     DOCKER NETWORK                        │    │
│  │  ┌─────────┐  ┌─────────┐  ┌──────┐  ┌──────────────┐    │    │
│  │  │  Nginx  │──│   PHP   │──│ MySQL│  │ Loki+Promtail│    │    │
│  │  │  :8888  │  │   8.2   │  │  8.0 │  │    (logs)    │    │    │
│  │  └─────────┘  └─────────┘  └──────┘  └──────────────┘    │    │
│  └───────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────┘
```

| Componente | Función |
|------------|---------|
| **Nginx + PHP 8.2** | Panel de administración |
| **MySQL 8.0** | Usuarios y logs de auditoría |
| **Loki + Promtail** | Ingesta y consulta de logs |
| **Fail2Ban** | Baneos automáticos (35 días) |
| **GeoLite2** | Geolocalización offline |

---

## 🔒 Seguridad implementada

<table>
<tr><td>🔑</td><td><strong>Split Authentication</strong></td><td>Admin entra con clave pública; el resto intenta con contraseña y es baneado</td></tr>
<tr><td>🛡️</td><td><strong>CSRF + Cookies hardened</strong></td><td>Protección en login, httponly, samesite=strict</td></tr>
<tr><td>⏱️</td><td><strong>Rate-limit</strong></td><td>Nginx limita peticiones al panel</td></tr>
<tr><td>🔐</td><td><strong>Credenciales cifradas</strong></td><td>age + clave SSH, nunca en texto plano</td></tr>
<tr><td>🐳</td><td><strong>Docker Secrets</strong></td><td>Contraseñas MySQL fuera del .env</td></tr>
<tr><td>🔥</td><td><strong>Firewall UFW</strong></td><td>Solo SSH abierto, resto bloqueado</td></tr>
</table>

---

## 💾 Backups

```bash
sudo ./backups.sh
```

Menú interactivo para crear, listar, restaurar y programar backups automáticos.  
Incluye configuración, datos de MySQL y logs.

---

## ✅ Post-instalación

Consulta **[POSTDEPLOY_CHECKS.md](POSTDEPLOY_CHECKS.md)** para verificar que todo funciona:
- Estado de contenedores y healthchecks
- Fail2Ban y UFW activos
- Puertos correctos

---

## 📄 Licencia

Uso no comercial únicamente. Ver [LICENSE](LICENSE).

---

<p align="center">
  <strong>⚠️ Aviso importante</strong>
</p>

<p align="center">
  Este proyecto tiene fines <strong>educativos y defensivos</strong>.<br>
  El honeypot captura credenciales de atacantes — no las almacenes, compartas ni reutilices.<br>
  Úsalo de forma responsable y conforme a la legislación de tu país.
</p>
