# Memoria final — ASIR VPS Defense (Proyecto Final ASIR 2025/2026)



---

## Resumen

En este proyecto se implementó un sistema de defensa y observabilidad para un VPS Linux orientado a entornos expuestos a Internet con alta presión de ataques sobre SSH. El enfoque combinó *hardening* del acceso administrativo, despliegue de un honeypot SSH y centralización de logs para análisis posterior, manteniendo un principio de mínima exposición: el panel de administración no se publicó en Internet y únicamente fue accesible mediante túnel SSH.

La solución se desplegó de forma automatizada mediante un instalador interactivo en Bash y se orquestó con Docker Compose. Se integraron los siguientes componentes: Cowrie como honeypot SSH en el puerto 22, OpenSSH real en un puerto alternativo para administración, Fail2Ban para respuesta automática, Loki y Promtail para centralización de logs y un panel privado (Nginx + PHP + MySQL) para visualización de métricas y geolocalización offline mediante GeoLite2.

El funcionamiento del sistema se comprobó mediante pruebas controladas y evidencias técnicas (capturas y fragmentos de logs), verificando la separación efectiva entre honeypot y SSH real, la generación de telemetría de ataques, la ingesta en Loki y la visualización en el panel.

## Palabras clave

VPS; hardening; SSH; honeypot; Cowrie; Fail2Ban; Loki; Promtail; observabilidad; Docker; geolocalización; panel privado.

---

## Índice

1. Introducción  
2. Objetivos  
3. Alcance del MVP y requisitos  
4. Metodología de trabajo  
5. Diseño y arquitectura del sistema  
6. Desarrollo e implementación (redacción en pasado)  
7. Pruebas, validación y evidencias  
8. Resultados obtenidos  
9. Conclusiones trazables a objetivos  
10. Cierre del MVP  
11. Trabajo futuro  
12. Bibliografía  
13. Anexos técnicos  

---

## 1. Introducción

Los servidores VPS expuestos a Internet reciben de forma continua intentos de intrusión, especialmente sobre SSH, debido a campañas automatizadas de fuerza bruta, credenciales por defecto y explotación de configuraciones inseguras. El reto no se limita a bloquear los ataques: en entornos formativos resulta de alto valor capturar y analizar telemetría real para comprender patrones, vectores y frecuencia.

Con esa motivación, se implementó un sistema que combinó defensa activa (reducción de superficie, autenticación robusta y bloqueo automático) con observabilidad (centralización de logs y panel de métricas). El elemento diferencial fue la separación intencionada del puerto 22 para un honeypot (Cowrie), mientras el acceso administrativo real se trasladó a un puerto alternativo y se restringió a clave pública.

---

## 2. Objetivos

### 2.1 Objetivo general

Implementar y validar un sistema reproducible de defensa y observabilidad para VPS centrado en ataques sobre SSH, capaz de atraer ataques controladamente (honeypot), registrar telemetría, responder con bloqueo automático y proporcionar visualización mediante un panel privado no expuesto públicamente.

### 2.2 Objetivos específicos

- **OE1 — Hardening del acceso administrativo:** se aseguró el acceso real por SSH mediante autenticación por clave pública en un puerto alternativo y se redujo la exposición de servicios en red.
- **OE2 — Captura de ataques con honeypot:** se desplegó Cowrie para registrar intentos de autenticación y sesiones simuladas en el puerto 22.
- **OE3 — Respuesta automática ante abuso:** se configuró Fail2Ban para detectar intentos fallidos en el SSH real y aplicar bans con política estricta.
- **OE4 — Centralización y consulta de logs:** se integró Loki + Promtail para ingesta de logs de host y del honeypot, con retención definida.
- **OE5 — Panel privado y geolocalización offline:** se implementó un panel web accesible solo por túnel SSH, con autenticación, auditoría y enriquecimiento GeoIP local.
- **OE6 — Operación y mantenimiento:** se prepararon verificaciones post-despliegue y un mecanismo de copias de seguridad del sistema.

---

## 3. Alcance del MVP y requisitos

### 3.1 Alcance logrado (MVP)

El MVP se consideró cerrado cuando se verificaron, con evidencias, los siguientes criterios:

- Honeypot Cowrie operativo atendiendo conexiones en el **puerto 22** del host.
- SSH real de administración operativo en **puerto alternativo** (p. ej., 2929), con **acceso por clave** y rechazo de contraseña.
- Fail2Ban operativo aplicando bans automáticos con política estricta.
- Loki y Promtail operativos ingiriendo logs de *auth*, *fail2ban* y Cowrie.
- Panel web operativo con autenticación y métricas reales, accesible únicamente mediante túnel SSH a loopback.
- Geolocalización offline basada en base de datos local GeoLite2.
- Backups de configuración, datos y logs mediante script de operación.

### 3.2 Fuera de alcance (no MVP)

- Exposición pública de servicios HTTP/HTTPS (por diseño, el panel no se publicó a Internet).
- WAF (ModSecurity) como control en el perímetro HTTP público.
- Grafana como panel adicional (se priorizó un panel específico en PHP).
- Alertas en tiempo real (por ejemplo, notificaciones ante picos).

### 3.3 Requisitos técnicos

- VPS con Debian 11/12 o Ubuntu 20.04+.
- Acceso *root* o sudo.
- Conectividad a Internet para instalación y obtención de dependencias.
- Clave pública SSH disponible para el usuario administrador.

---

## 4. Metodología de trabajo

El proyecto se ejecutó siguiendo una metodología incremental orientada a MVP:

1. **Diseño y arquitectura:** se definió la separación de “SSH real” y “SSH honeypot” mediante puertos distintos, así como la mínima exposición del panel.
2. **Implementación del despliegue automatizado:** se desarrolló un instalador (`deploy.sh`) con verificación de requisitos, configuración de SSH y despliegue de contenedores.
3. **Integración de observabilidad:** se configuró Promtail para lectura de logs del host y de Cowrie, y Loki como almacenamiento con retención.
4. **Implementación del panel privado:** se integraron consultas a Loki desde PHP, autenticación de panel y controles de seguridad (CSRF, cookies endurecidas, rate-limit).
5. **Pruebas y validación con evidencias:** se ejecutaron pruebas controladas, se capturaron capturas y se conservaron fragmentos de logs relevantes.
6. **Operación:** se implementó un procedimiento de verificación post-despliegue y un mecanismo de backups.

---

## 5. Diseño y arquitectura del sistema

### 5.1 Principios de diseño

- **Mínima exposición:** únicamente se expuso a Internet el servicio SSH, manteniendo el panel en loopback.
- **Separación de planos:** el honeypot atendió el puerto estándar 22 para capturar ataques; el plano administrativo se aisló en un puerto alternativo.
- **Trazabilidad:** cada objetivo se vinculó a evidencias (capturas y fragmentos de logs).
- **Reproducibilidad:** se orquestó el despliegue con Docker Compose y configuración versionada.

### 5.2 Componentes

- **Cowrie (honeypot SSH):** escuchó en el puerto 22 del host (mapeado a 2222 del contenedor). Registró intentos de autenticación y sesiones.
- **OpenSSH (host):** proporcionó el acceso administrativo real en un puerto alternativo, con autenticación por clave.
- **Fail2Ban (host):** detectó abuso sobre el SSH real y aplicó bans automáticos.
- **Loki + Promtail (contenedores):** centralizaron logs del host y del honeypot; Loki retuvo logs durante 31 días.
- **Panel privado (Nginx + PHP + MySQL):** mostró métricas agregadas y detalle de eventos con geolocalización. El acceso se restringió a túnel SSH.
- **GeoLite2 (local):** enriqueció IPs con localización sin depender de APIs externas.

---

## 6. Desarrollo e implementación (redacción en pasado)

### 6.1 Despliegue automatizado

Se implementó un instalador interactivo en Bash que verificó requisitos del sistema, instaló dependencias y orquestó el despliegue de contenedores mediante Docker Compose. El instalador registró su ejecución en un log de instalación y aplicó un modelo de despliegue idempotente mediante marcas de estado, reduciendo errores por re-ejecución.

### 6.2 Hardening de red y acceso administrativo

Se configuró el firewall del host para permitir exclusivamente los puertos necesarios (SSH real y puerto 22 para el honeypot). Se comprobó que el panel no era accesible desde el exterior al estar vinculado a loopback.

Para el acceso administrativo, se aplicó una separación de autenticación: el usuario administrador se restringió a clave pública, mientras el honeypot admitió intentos con contraseña (entorno simulado) para atraer ataques. Se verificó que la autenticación por contraseña quedaba rechazada en el SSH real.

### 6.3 Honeypot SSH con Cowrie

Se desplegó Cowrie como honeypot SSH escuchando en el puerto 22 del host. Se configuró un banner falso de OpenSSH para simular un servidor real y se habilitó el log en formato texto y JSON. Se montaron volúmenes para persistir logs y sesiones (TTY), permitiendo su análisis posterior.

Durante la validación, se comprobó que Cowrie registró conexiones entrantes reales, intentos de login y credenciales proporcionadas por atacantes, demostrando la capacidad de captura de telemetría.

### 6.4 Observabilidad: Promtail y Loki

Se configuró Promtail para recopilar logs del host (auth.log y fail2ban.log) y los logs de Cowrie (texto y JSON). Se definieron *pipeline stages* para extraer timestamps y preservar la consistencia temporal en consultas.

Se desplegó Loki como almacenamiento de logs, habilitando *healthchecks* y estableciendo una política de retención de 31 días. Asimismo, se habilitó un margen temporal para tolerar desfases horarios en entradas.

### 6.5 Panel privado (Nginx + PHP + MySQL)

Se implementó un panel web con autenticación mediante usuario/contraseña almacenada como hash y auditoría de accesos en MySQL. Se incluyeron medidas de seguridad:

- Se aplicó protección CSRF en el formulario de login.
- Se endurecieron cookies de sesión (HttpOnly, SameSite=Strict y Secure dinámico).
- Se definió una zona de limitación de peticiones en Nginx como base para control anti-fuerza-bruta a nivel HTTP, quedando su aplicación estricta al login como mejora prioritaria para no interferir con el endpoint de métricas durante la validación.
- Se aisló MySQL y Loki en una red Docker interna sin puertos expuestos al host.
- Se consumieron credenciales de MySQL mediante Docker Secrets en lugar de variables de entorno.

El panel consultó Loki para extraer métricas agregadas y eventos recientes (SSH, Fail2Ban y Cowrie), enriqueciendo los resultados con geolocalización offline basada en GeoLite2.

### 6.6 Copias de seguridad y operación

Se implementó un gestor de backups en Bash capaz de crear, listar, restaurar y rotar copias, incluyendo configuración, secretos, código del panel y copia física del datadir de MySQL. Para operación, se documentó un checklist post-despliegue con verificaciones de servicios, healthchecks y puertos.

---

## 7. Pruebas, validación y evidencias

La validación se documentó mediante evidencias numeradas, organizadas por bloques: infraestructura, honeypot, Fail2Ban, observabilidad, panel privado, SSH real y pipeline completo.

### 7.1 Infraestructura

- Se verificó el estado de puertos y bindings del host (Cowrie en 22 y SSH real en puerto alternativo). **Evidencia:** EV-01.
- Se verificó el estado de contenedores y healthchecks. **Evidencias:** EV-02, EV-03.
- Se verificó el estado del firewall UFW y ausencia de exposición del panel. **Evidencia:** EV-04.
- Se verificó el banner falso del honeypot. **Evidencia:** EV-05.

### 7.2 Honeypot Cowrie

- Se verificó la captura de intentos de autenticación y eventos en logs. **Evidencias:** EV-06, EV-07.
- Se verificó la persistencia de sesiones y posibilidad de replay. **Evidencias:** EV-08, EV-09.
- Se documentó una prueba controlada para generar telemetría y validar captura. **Evidencia:** EV-10.

### 7.3 Fail2Ban

- Se verificó el estado de la jail `sshd` y existencia de IPs baneadas. **Evidencia:** EV-11.
- Se verificó el registro de bans en el log de Fail2Ban y se extrajo un fragmento para anexo. **Evidencias:** EV-12, EV-13.

### 7.4 Observabilidad (Loki + Promtail)

- Se verificó el estado *ready* de Loki. **Evidencia:** EV-14.
- Se verificó la existencia de jobs activos entregados por Promtail. **Evidencia:** EV-15.
- Se verificó la disponibilidad de eventos Cowrie y Fail2Ban consultables en Loki. **Evidencias:** EV-16, EV-17.

### 7.5 Panel privado

- Se verificó la inaccesibilidad del panel desde el exterior sin túnel. **Evidencia:** EV-18.
- Se verificó el acceso mediante túnel SSH y la visualización de métricas reales. **Evidencias:** EV-19, EV-20.
- Se verificó el detalle de ataques y geolocalización en mapa. **Evidencias:** EV-21, EV-22.
- Se verificó la gráfica temporal de actividad. **Evidencia:** EV-23.

### 7.6 SSH real y separación honeypot/administración

- Se verificó el acceso al SSH real por clave en puerto alternativo. **Evidencia:** EV-25.
- Se verificó el rechazo de contraseña en el SSH real. **Evidencia:** EV-26.
- Se verificó la separación por escaneo de servicios y ausencia de exposición del panel. **Evidencia:** EV-27.

### 7.7 Validación del pipeline completo

- Se acreditó el ciclo ataque → registro Cowrie → ingesta Promtail → consulta Loki. **Evidencia:** EV-28.
- Se acreditó el ciclo detección → registro Fail2Ban → ban efectivo. **Evidencia:** EV-29.

---

## 8. Resultados obtenidos

- **Captura de telemetría real en el puerto 22:** se obtuvieron múltiples intentos de login procedentes de IPs externas en un intervalo corto y se conservaron fragmentos de log. **Evidencia:** EV-07.
- **Bloqueo automático en el plano administrativo:** se observaron eventos de “Found” y “Ban” en Fail2Ban frente a intentos fallidos, confirmando respuesta automática. **Evidencia:** EV-13.
- **Centralización y consulta de logs:** se consultaron eventos mediante LogQL desde Loki, demostrando la trazabilidad de los eventos de seguridad. **Evidencias:** EV-16, EV-17.
- **Panel operativo sin exposición pública:** se demostró que el panel no aceptó conexión directa desde el exterior y que fue accesible únicamente por túnel SSH. **Evidencias:** EV-18, EV-19.
- **Visualización y enriquecimiento:** se visualizaron tablas de ataques y mapa de geolocalización con GeoLite2. **Evidencias:** EV-21, EV-22.

---

## 9. Conclusiones trazables a objetivos

En esta sección se redactaron conclusiones ligadas a objetivos siguiendo el esquema: **objetivo → resultado → evidencia → limitación**.

### OE1 — Hardening del acceso administrativo

- **Objetivo:** asegurar el acceso administrativo real y reducir superficie expuesta.
- **Resultado:** se aisló el SSH real en un puerto alternativo y se deshabilitó la autenticación por contraseña, manteniendo el puerto 22 para el honeypot.
- **Evidencia:** EV-01 (puertos), EV-25 (acceso por clave), EV-26 (rechazo de contraseña), EV-27 (escaneo de puertos).
- **Limitación:** el uso de un puerto alternativo reduce ruido pero no sustituye medidas adicionales (por ejemplo, listas permitidas, segmentación o MFA). Además, la configuración depende de disciplina operativa para no abrir otros servicios innecesarios.

### OE2 — Captura de ataques con honeypot

- **Objetivo:** atraer y registrar ataques SSH y su interacción.
- **Resultado:** Cowrie registró conexiones reales, intentos de login y sesiones; se habilitó registro en texto y JSON y persistencia de TTY.
- **Evidencia:** EV-06/EV-07 (logs), EV-08/EV-09 (sesiones y replay), EV-05 (banner).
- **Limitación:** el honeypot no sustituye sistemas de detección completos; además, el análisis de credenciales capturadas se consideró material sensible y se limitó a su uso académico controlado.

### OE3 — Respuesta automática ante abuso

- **Objetivo:** detectar intentos de autenticación fallidos en el SSH real y bloquear IPs automáticamente.
- **Resultado:** Fail2Ban detectó intentos fallidos y aplicó bans con política estricta, dejando traza en logs.
- **Evidencia:** EV-11 (estado jail), EV-12/EV-13 (log con bans), EV-29 (pipeline de ban).
- **Limitación:** el ban por IP puede ser menos eficaz frente a atacantes con rotación rápida o botnets; además, una política demasiado agresiva incrementa el riesgo de falsos positivos si no se ajusta el umbral.

### OE4 — Centralización y consulta de logs

- **Objetivo:** centralizar logs relevantes y consultarlos de forma consistente.
- **Resultado:** Promtail ingirió logs del host y del honeypot, y Loki permitió consultas LogQL con retención de 31 días.
- **Evidencia:** EV-14 (ready), EV-15 (jobs), EV-16/EV-17 (consultas), EV-28 (pipeline Cowrie→Loki).
- **Limitación:** el almacenamiento en filesystem local en VPS simplifica el MVP pero no ofrece alta disponibilidad; en escenarios de producción se requeriría redundancia, rotación y dimensionamiento más exhaustivo.

### OE5 — Panel privado y geolocalización offline

- **Objetivo:** visualizar métricas y detalle de eventos sin exponer un servicio web públicamente.
- **Resultado:** el panel fue accesible solo por túnel SSH; se incorporó autenticación, auditoría y enriquecimiento GeoIP local.
- **Evidencia:** EV-18/EV-19 (restricción + túnel), EV-20/EV-21 (dashboard + tabla), EV-22 (mapa), EV-23 (gráfica).
- **Limitación:** el panel dependió de un túnel manual; además, el endpoint de métricas solo se protegió por sesión. En la configuración final no se aplicó limitación de peticiones (rate-limit) de forma estricta al login para no provocar respuestas 503 en la obtención de métricas durante la validación, quedando como mejora prioritaria su aplicación (junto con token, control de rol y/o aislamiento por ruta).

### OE6 — Operación y mantenimiento

- **Objetivo:** facilitar verificación post-despliegue y copias de seguridad.
- **Resultado:** se documentó un checklist de verificación y se implementó un gestor de backups con rotación y restauración.
- **Evidencia:** checklist post-despliegue (Anexo técnico), script de backups (Anexo técnico).
- **Limitación:** la restauración completa requiere coordinación (parada de servicios, consistencia del datadir y permisos). En despliegues multi-host se requeriría una estrategia distinta.

---

## 10. Cierre del MVP

### 10.1 Alcance logrado

Se cerró el MVP al haberse desplegado y validado un sistema completo que:

- Capturó ataques reales de SSH sobre el puerto 22 mediante Cowrie.
- Protegió el acceso administrativo real con autenticación por clave en puerto alternativo.
- Bloqueó automáticamente IPs abusivas con Fail2Ban.
- Centralizó logs con Loki/Promtail y permitió su consulta.
- Mostró métricas y eventos en un panel privado no expuesto, accesible por túnel SSH.
- Enriqueció eventos con geolocalización offline.
- Incluyó procedimientos de verificación y backups.

### 10.2 Alcance no logrado

- No se implementó un sistema de roles completo en el panel (aunque el esquema contempló `admin` y `viewer`).
- No se endureció adicionalmente el endpoint de métricas más allá de la validación de sesión.
- No se desplegó un WAF operativo en entorno expuesto (al no existir superficie HTTP pública en el diseño MVP).
- No se integraron alertas en tiempo real ni notificaciones.

### 10.3 Causas, limitaciones y condicionantes

- **Condicionante de diseño:** al priorizar “mínima exposición”, se decidió no publicar un servicio web en Internet, reduciendo el valor práctico de un WAF en el MVP.
- **Limitación de tiempo y complejidad:** el desarrollo se centró en cerrar el ciclo completo de telemetría y defensa sobre SSH con evidencias reproducibles.
- **Limitación operativa:** el uso de túnel SSH implica dependencia del canal administrativo y requiere disciplina de operación.

---

## 11. Trabajo futuro

- Implementar control de roles efectivo (admin/viewer) en el panel y restricciones por endpoint.
- Endurecer el endpoint `metrics` con token de aplicación y/o control de cabeceras/origen.
- Integrar alertas (por ejemplo, umbrales de bans/hora) y notificación.
- Diseñar un modo “producción” con alta disponibilidad de logs (almacenamiento externo o replicación).
- Incorporar un modo *dry-run* en el despliegue para validar cambios sin aplicarlos.
- Extender la cobertura a otros servicios comúnmente atacados (por ejemplo, RDP, HTTP de aplicaciones), manteniendo el principio de mínima exposición.

---

## 12. Bibliografía (formato IEEE)

[1] Grafana Labs, “Loki Configuration,” *Grafana Loki Documentation*. [En línea]. Disponible: https://grafana.com/docs/loki/latest/configuration/. [Accedido: 02-mar-2026].

[2] Grafana Labs, “Promtail Pipelines,” *Grafana Loki Documentation*. [En línea]. Disponible: https://grafana.com/docs/loki/latest/clients/promtail/pipelines/. [Accedido: 02-mar-2026].

[3] Fail2Ban Project, “Fail2Ban Manual,” *Fail2Ban Wiki*. [En línea]. Disponible: https://www.fail2ban.org/wiki/index.php/MANUAL_0_8. [Accedido: 02-mar-2026].

[4] F. Valsorda, "age: A simple, modern and secure file encryption tool," *GitHub repository*. [En línea]. Disponible: https://github.com/FiloSottile/age. [Accedido: 02-mar-2026].

[5] Cowrie Project, “Cowrie SSH/Telnet Honeypot,” *GitHub repository*. [En línea]. Disponible: https://github.com/cowrie/cowrie. [Accedido: 02-mar-2026].

[6] Docker, Inc., “Docker Compose,” *Docker Documentation*. [En línea]. Disponible: https://docs.docker.com/compose/. [Accedido: 02-mar-2026].

[7] Nginx, Inc., “NGINX Documentation,” *NGINX Docs*. [En línea]. Disponible: https://nginx.org/en/docs/. [Accedido: 02-mar-2026].

[8] MaxMind, Inc., “GeoLite2 Free Geolocation Data,” *MaxMind Documentation*. [En línea]. Disponible: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data. [Accedido: 02-mar-2026].

---

## 13. Anexos técnicos

> Nota: en el depósito se adjuntó el repositorio del proyecto. Los anexos referenciaron los ficheros de configuración y evidencias con objeto de garantizar trazabilidad y reproducibilidad.

### Anexo A — Configuraciones relevantes

**A.1 — Orquestación Docker Compose**  
- Fichero: `docker-compose.yml`  
- Elementos clave documentados:
  - Mapeo de puertos: `0.0.0.0:22→Cowrie:2222` y `127.0.0.1:8888→Nginx:80`.
  - Aislamiento de backend: red `backend_net` interna sin puertos expuestos para MySQL y Loki.
  - Endurecimiento de PHP: `read_only`, `tmpfs`, `no-new-privileges`, `cap_drop: ALL`.
  - Uso de Docker Secrets para credenciales MySQL.

**A.2 — Configuración de Cowrie**  
- Fichero: `cowrie/cowrie.cfg`  
- Elementos clave:
  - Banner falso de OpenSSH.
  - Logs en texto y JSON en volumen persistente.
  - Backend `shell` (no proxy al SSH real).

**A.3 — Configuración de Promtail**  
- Fichero: `promtail/config.yml`  
- Elementos clave:
  - Scrape de `fail2ban.log`, `auth.log` y logs de Cowrie.
  - Pipelines de extracción de timestamps.

**A.4 — Configuración de Loki**  
- Fichero: `loki/config.yml`  
- Elementos clave:
  - Retención `744h` (31 días).
  - Cache embebida para queries.

**A.5 — Configuración Nginx del panel privado**  
- Fichero: `nginx/conf.d/admin.conf`  
- Elementos clave:
  - Cabeceras de seguridad (CSP, XFO, etc.).
  - Configuración FastCGI hacia PHP-FPM.
  - Zona de rate-limit definida como base de control anti-fuerza-bruta HTTP (pendiente de aplicar de forma estricta al login en el ajuste final).

### Anexo B — Scripts

**B.1 — Instalador**  
- Fichero: `deploy.sh`  
- Descripción: script interactivo que automatizó instalación y configuración (Docker, UFW, Fail2Ban, separación SSH, despliegue de contenedores y cifrado de credenciales).

**B.2 — Gestor de backups**  
- Fichero: `backups.sh`  
- Descripción: script de operación para crear/restaurar/rotar backups (configuración, secretos, código, inicialización SQL y datadir MySQL).

### Anexo C — Checklist de verificación

**C.1 — Checklist post-despliegue**  
- Fichero: `POSTDEPLOY_CHECKS.md`  
- Descripción: conjunto de verificaciones reproducibles de contenedores, healthchecks, puertos, Fail2Ban y pipeline de logs.

### Anexo D — Logs y evidencias

**D.1 — Fragmento log Cowrie**  
- Fichero: `evidencias/02_honeypot_cowrie/ev07_cowrie_log_fragmento.txt`  
- Contenido: intentos de login y conexiones capturadas.

**D.2 — Fragmento log Fail2Ban**  
- Fichero: `evidencias/03_fail2ban/ev13_fail2ban_log_fragmento.txt`  
- Contenido: eventos Found y Ban con timestamps.

**D.3 — Evidencias gráficas (capturas)**  
- Carpeta: `evidencias/`  
- Contenido: capturas EV-01…EV-29 que acreditaron el estado y funcionamiento del MVP.

### Anexo E — Pruebas reproducibles (sin herramientas de fuerza bruta)

> Estas pruebas se orientaron a verificar el MVP sin introducir herramientas de ataque automatizado. Para el checklist completo de operación se utilizó el documento post-despliegue.

**E.1 — Verificación de estado de contenedores**

```bash
docker compose ps
docker compose logs --tail=80 admin-nginx php-app mysql loki promtail cowrie
```

**E.2 — Verificación de puertos y exposición**

```bash
sudo ss -tulpen | grep -E ':(22|2929|8888)\s'
sudo ufw status numbered
```

**E.3 — Verificación de panel en loopback (desde el propio VPS)**

```bash
curl -I http://127.0.0.1:8888
```

**E.4 — Verificación de acceso al panel mediante túnel SSH (desde la máquina de administración)**

```bash
ssh -p 2929 -L 9999:127.0.0.1:8888 <admin_user>@<IP_VPS> -N
# Navegador: http://localhost:9999
```

**E.5 — Verificación de separación honeypot / SSH real**

```bash
# Honeypot (puerto 22): se conecta al entorno simulado
ssh -p 22 -o StrictHostKeyChecking=no test@<IP_VPS>

# SSH real (puerto alternativo): debe requerir clave pública
ssh -p 2929 <admin_user>@<IP_VPS>
```
