# 02 — Honeypot Cowrie

Este bloque documenta la capacidad de Cowrie para registrar conexiones, intentos de autenticación, sesiones interactivas y comandos ejecutados por los atacantes.

---

## EV-06 — `ev06_cowrie_log_ataques.png`

Se consultó el log principal de Cowrie en tiempo real mediante `docker exec` sobre el contenedor `asir_cowrie`. El log reflejó conexiones entrantes con IP de origen, puerto efímero, usuario y contraseña utilizados en cada intento, así como el resultado de la autenticación. Cowrie aceptó todas las credenciales conforme a la configuración del archivo `userdb.txt`.

```bash
docker exec asir_cowrie tail -100 /cowrie/var/log/cowrie/cowrie.log \
  | grep -E "New connection|login attempt|login failed"
```

---

## EV-07 — `ev07_cowrie_log_fragmento.txt`

Se extrajo un fragmento representativo del log de texto de Cowrie para su inclusión literal en la memoria técnica. Se seleccionaron líneas que cubren el ciclo completo: nueva conexión, intento de login y ejecución de comandos.

```bash
docker exec asir_cowrie grep -E "login attempt|New connection|Command found" \
  /cowrie/var/log/cowrie/cowrie.log | tail -30
```

---

## EV-08 — `ev08_sesion_tty_lista.png`

Se listó el directorio de sesiones TTY dentro del contenedor para confirmar que Cowrie había grabado las sesiones interactivas de los atacantes. Cada archivo `.tty` corresponde a una sesión completa con timestamp de inicio.

```bash
docker exec asir_cowrie ls -lh /cowrie/var/lib/cowrie/tty/
```

---

## EV-09 — `ev09_sesion_tty_replay.png`

Se reprodujo una de las sesiones grabadas mediante la herramienta `playlog` incluida en Cowrie. La reproducción mostró en tiempo real los comandos ejecutados por el atacante dentro del entorno simulado, incluyendo reconocimiento del sistema y lectura de ficheros sensibles.

```bash
docker exec asir_cowrie python3 /cowrie/bin/playlog \
  /cowrie/var/lib/cowrie/tty/<archivo>.tty
```

---

## EV-10 — `ev10_hydra_result.txt`

Como prueba controlada, se lanzó un ataque de fuerza bruta con Hydra desde una máquina externa contra el puerto 22 del servidor. Hydra registró en su fichero de salida las credenciales con las que Cowrie concedió acceso, confirmando que el honeypot admitía cualquier combinación de usuario y contraseña sin restricción, a la vez que registraba cada intento en sus logs.

```bash
hydra -l root -P /tmp/passwords.txt -t 4 -s 22 \
  -o /tmp/hydra_result.txt ssh://<IP_VPS>
```

---

## EV-06 — `ev06_cowrie_log_ataques.png`

**Qué demuestra:** Cowrie registra intentos de login con IP, usuario y contraseña.

**Comando en el VPS:**
```bash
docker exec asir_cowrie tail -100 /cowrie/var/log/cowrie/cowrie.log | grep -E "New connection|login attempt|login failed"
```

**Qué debe aparecer:**
```
New connection: 185.x.x.x:54821 (...)
login attempt [root/admin123] failed
login attempt [root/123456] succeeded
```

---

## EV-07 — `ev07_cowrie_log_fragmento.txt`

**Qué demuestra:** Fragmento de log real para incluir literalmente en la memoria.

**Cómo obtenerlo:**
```bash
docker exec asir_cowrie grep -E "login attempt|New connection|Command found" \
  /cowrie/var/log/cowrie/cowrie.log | tail -30
```

**Instrucción:** Copiar la salida de texto y pegarla directamente en este archivo `.txt`. No hace falta captura, se incluye como bloque de código en la memoria.

---

## EV-08 — `ev08_sesion_tty_lista.png`

**Qué demuestra:** Cowrie graba las sesiones TTY completas de los atacantes.

**Comando en el VPS:**
```bash
docker exec asir_cowrie ls -lh /cowrie/var/lib/cowrie/tty/
```

**Qué debe aparecer:** Uno o más archivos `.tty` con fecha reciente.

> Si la carpeta está vacía, el atacante no llegó a ejecutar comandos. Hacer PRUEBA-C (sesión interactiva manual al honeypot).

---

## EV-09 — `ev09_sesion_tty_replay.png`

**Qué demuestra:** Reproducción de la sesión de un atacante dentro del honeypot.

**Comando en el VPS (sustituir nombre de archivo):**
```bash
docker exec asir_cowrie python3 /cowrie/bin/playlog \
  /cowrie/var/lib/cowrie/tty/<NOMBRE_ARCHIVO>.tty
```

**Qué debe aparecer:** Los comandos que ejecutó el atacante dentro del honeypot (`ls`, `whoami`, `cat /etc/passwd`, etc.)

---

## EV-10 — `ev10_hydra_result.txt`

**Qué demuestra:** Prueba controlada de ataque con hydra al honeypot.

**Cómo obtenerlo (desde máquina atacante/externa):**
```bash
echo -e "admin\nroot\n123456\npassword\ntest" > /tmp/passwords.txt

hydra -l root -P /tmp/passwords.txt \
  -t 4 -s 22 -o /tmp/hydra_result.txt \
  ssh://<IP_VPS>

cat /tmp/hydra_result.txt
```

**Instrucción:** Copiar la salida de hydra y pegarla en este archivo `.txt`. También hacer screenshot (EV-06) de cómo esos intentos aparecen en cowrie.log.
