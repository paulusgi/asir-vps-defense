# 05 — Panel privado (acceso por túnel SSH)

Este bloque documenta el mecanismo de acceso restringido al panel de administración, que expone métricas del honeypot exclusivamente a través de un túnel SSH local, sin ninguna exposición pública directa.

---

## EV-18 — `ev18_panel_bloqueado_ext.png`

Se intentó acceder al puerto 8888 del servidor directamente desde una máquina externa para verificar que no existía exposición pública del panel. La conexión fue rechazada, conforme a la configuración del `docker-compose.yml` que vincula el contenedor `admin-nginx` exclusivamente a `127.0.0.1:8888`.

```bash
curl -v --connect-timeout 5 http://<IP_VPS>:8888/
```

---

## EV-19 — `ev19_tunel_ssh_activo.png`

Para acceder al panel, se estableció un túnel SSH desde la máquina de administración hacia el servidor. El túnel redirigía el puerto local 9999 al puerto 8888 de loopback del servidor, canalizando el tráfico a través de la sesión SSH autenticada con clave pública.

```bash
ssh -L 9999:127.0.0.1:8888 -p 2929 adminuser@<IP_VPS> -N
```

---

## EV-20 — `ev20_panel_dashboard.png`

Con el túnel activo, se accedió al panel mediante el navegador en `http://localhost:9999`. El dashboard presentó los contadores de actividad del honeypot actualizados con los datos generados durante las pruebas controladas realizadas previamente.

---

## EV-21 — `ev21_panel_tabla_ataques.png`

Se capturó la sección de listado detallado del panel, que mostraba cada intento de conexión registrado por Cowrie con sus metadatos completos: IP de origen, usuario empleado, contraseña utilizada, timestamp y geolocalización del atacante.

---

## EV-22 — `ev22_panel_mapa_geo.png`

El panel incorpora un mapa de geolocalización que sitúa geográficamente las IPs atacantes utilizando la base de datos GeoLite2-City de MaxMind. La captura muestra la distribución geográfica real de los ataques recibidos durante el período de actividad del honeypot.

---

## EV-23 — `ev23_panel_grafica_tiempo.png`

Se capturó la gráfica de actividad temporal del panel, que refleja la distribución de intentos de conexión a lo largo del tiempo. El pico correspondiente al ataque controlado con Hydra es claramente identificable, validando que el sistema registraba y graficaba los eventos en tiempo real.

---

## EV-24 — `ev24_panel_url_localhost.png`

Se capturó el panel con la barra de dirección del navegador visible, mostrando la URL `http://localhost:9999`. Esta evidencia acredita que el acceso se realizó a través del túnel SSH local y no mediante exposición directa del servicio a Internet.

---

## Antes de empezar: establecer el túnel

```bash
# Ejecutar en tu máquina LOCAL (no en el VPS):
ssh -L 9999:127.0.0.1:8888 -p 2929 adminuser@<IP_VPS> -N -f

# Verificar que el túnel está activo:
ss -tlnp | grep 9999   # debe mostrar proceso ssh escuchando
```

Luego abrir el navegador en: **http://localhost:9999**

---

## EV-18 — `ev18_panel_bloqueado_ext.png`

**Qué demuestra:** El panel NO es accesible desde el exterior (sin túnel).

**Comando desde una máquina externa (NO el VPS, NO con túnel activo):**
```bash
curl -v --connect-timeout 5 http://<IP_VPS>:8888/
```

**Qué debe aparecer:** `Connection refused` o `curl: (7) Failed to connect` → el puerto 8888 no está expuesto públicamente.

> También se puede hacer desde el propio VPS con: `curl -v http://<IP_PUBLICA>:8888/`

---

## EV-19 — `ev19_tunel_ssh_activo.png`

**Qué demuestra:** El túnel SSH está establecido y es el único medio de acceso al panel.

**Captura de pantalla:** Terminal con el comando de túnel visible:
```bash
ssh -L 9999:127.0.0.1:8888 -p 2929 adminuser@<IP_VPS> -N
```
O si se usó `-f` (background), mostrar:
```bash
ps aux | grep "ssh -L"
```

---

## EV-20 — `ev20_panel_dashboard.png`

**Qué demuestra:** El panel muestra el dashboard completo con datos reales.

**Cómo:** Con el túnel activo, captura de pantalla del navegador en `http://localhost:9999`.

**Qué debe aparecer:** Dashboard con contadores (conexiones honeypot, IPs únicas, bans totales) y datos recientes.

> Hacer las pruebas de ataque controlado (carpeta 02 y 03) ANTES de esta captura para tener datos reales.

---

## EV-21 — `ev21_panel_tabla_ataques.png`

**Qué demuestra:** El panel registra cada intento individual con todos los metadatos.

**Cómo:** Captura de la sección de tabla/listado del panel en `http://localhost:9999`.

**Qué debe aparecer:** Filas con: IP atacante, usuario intentado, contraseña intentada, timestamp, país/geolocalización.

---

## EV-22 — `ev22_panel_mapa_geo.png`

**Qué demuestra:** Los ataques se geolocalizan en el mapa mundial.

**Cómo:** Captura de la sección de mapa del panel en `http://localhost:9999`.

**Qué debe aparecer:** Pines/markers en el mapa en las ubicaciones de las IPs atacantes.

> Si el mapa aparece vacío, verificar que `geoip/GeoLite2-City.mmdb` existe y tiene tamaño > 0.

---

## EV-23 — `ev23_panel_grafica_tiempo.png`

**Qué demuestra:** La actividad de ataques varía en el tiempo y se grafica correctamente.

**Cómo:** Captura de la gráfica temporal del panel.

**Qué debe aparecer:** Gráfica con un pico visible en el momento de las pruebas controladas (hydra).

> Para tener un pico claro: ejecutar hydra, esperar 2-3 minutos y entonces capturar.

---

## EV-24 — `ev24_panel_url_localhost.png`

**Qué demuestra:** La URL del panel es `localhost:9999`, no una IP pública — prueba de acceso por túnel.

**Cómo:** Captura del navegador con **la barra de dirección visible** mostrando `http://localhost:9999`.

Esta evidencia es crítica: demuestra que el acceso es exclusivamente via túnel SSH local.
