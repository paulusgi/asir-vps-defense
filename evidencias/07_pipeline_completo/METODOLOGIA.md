# 07 — Pipeline completo

Este bloque documenta la validación del ciclo completo del sistema, desde la recepción de un ataque hasta su visualización en el panel, pasando por el registro en logs, la centralización en Loki y, en el caso de Fail2Ban, la aplicación del bloqueo. Se trata de la evidencia de mayor valor técnico del proyecto.

---

## EV-28 — `ev28_pipeline_ataque.png`

Se validó el pipeline de observabilidad del honeypot de forma integral. Se abrieron tres terminales simultáneas: la primera ejecutaba un `tail -f` del log de Cowrie en el servidor; desde la segunda se realizó una conexión al honeypot simulando el comportamiento de un atacante; la tercera lanzó, tras un intervalo de 35 segundos suficiente para que Promtail procesara el nuevo contenido del log, una consulta LogQL a Loki que devolvió el evento registrado. La captura muestra las tres ventanas de forma simultánea, acreditando la causalidad entre el ataque y su registro en el sistema de observabilidad.

```bash
# Terminal 1 — seguimiento en tiempo real del log Cowrie:
docker exec asir_cowrie tail -f /cowrie/var/log/cowrie/cowrie.log \
  | grep --line-buffered -E "login attempt|New connection"

# Terminal 2 — conexión al honeypot:
ssh -o StrictHostKeyChecking=no root@<IP_VPS> -p 22

# Terminal 3 — consulta Loki tras el ataque:
curl -s -G 'http://localhost:3100/loki/api/v1/query' \
  --data-urlencode 'query={job="cowrie"} |= "login attempt"' \
  | python3 -m json.tool | grep -A3 '"values"'
```

---

## EV-29 — `ev29_pipeline_ban.png`

De forma análoga, se validó el pipeline de Fail2Ban. La primera terminal seguía el log de Fail2Ban en tiempo real; desde la segunda se ejecutaron múltiples intentos de autenticación fallidos contra el puerto SSH real; la tercera mostraba en bucle el estado de la jail `sshd` mediante `watch`. La captura recoge el momento en que, tras superar el umbral de intentos configurado, Fail2Ban aplicó la regla de ban y la IP quedó bloqueada, cerrando el ciclo detección-respuesta.

```bash
# Terminal 1 — seguimiento del log Fail2Ban:
tail -f /var/log/fail2ban.log | grep --line-buffered -E "Ban|Found|WARNING"

# Terminal 2 — intentos fallidos desde IP externa:
for i in {1..5}; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      -o PreferredAuthentications=password \
      -p 2929 wronguser@<IP_VPS> 2>&1 | head -1
  sleep 2
done

# Terminal 3 — estado de la jail en tiempo real:
watch -n 5 'fail2ban-client status sshd | grep -E "Currently banned|Banned IP"'
```
Es la evidencia de mayor valor técnico para la memoria.

---

## Cómo hacer las capturas de pipeline

Usar un **gestor de ventanas divididas** (tmux, Windows Terminal split, iTerm2):
- **Ventana izquierda:** tail -f del log relevante en el VPS
- **Ventana central:** ejecutar el ataque desde máquina externa
- **Ventana derecha:** verificar resultado (Loki query o fail2ban status)

Capturar las tres ventanas simultáneamente para demostrar la causalidad.

---

## EV-28 — `ev28_pipeline_ataque.png`

**Qué demuestra:** Un ataque al honeypot genera logs que llegan a Loki en tiempo real.

**Preparación (3 terminales simultáneas):**

```bash
# Terminal 1 (VPS) — tail en tiempo real del log Cowrie:
docker exec asir_cowrie tail -f /cowrie/var/log/cowrie/cowrie.log | \
  grep --line-buffered -E "login attempt|New connection"

# Terminal 2 (máquina atacante) — lanzar ataque al honeypot:
ssh -o StrictHostKeyChecking=no root@<IP_VPS> -p 22
# introducir cualquier contraseña cuando pida

# Terminal 3 (VPS) — verificar en Loki después del ataque:
sleep 35 && curl -s -G 'http://localhost:3100/loki/api/v1/query' \
  --data-urlencode 'query={job="cowrie"} |= "login attempt"' \
  | python3 -m json.tool | grep -A3 '"values"'
```

**Captura:** Las tres terminales con el ataque visible en Terminal 1 y el resultado en Terminal 3.

---

## EV-29 — `ev29_pipeline_ban.png`

**Qué demuestra:** Varios intentos fallidos generan un ban automático de Fail2Ban.

**Preparación (3 terminales simultáneas):**

```bash
# Terminal 1 (VPS) — tail en tiempo real del log Fail2Ban:
tail -f /var/log/fail2ban.log | grep --line-buffered -E "Ban|Found|WARNING"

# Terminal 2 (máquina atacante) — generar intentos fallidos SSH real:
for i in {1..5}; do
  ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 \
      -o PreferredAuthentications=password \
      -p 2929 wronguser@<IP_VPS> 2>&1 | head -1
  sleep 2
done

# Terminal 3 (VPS) — verificar ban resultante:
watch -n 5 'fail2ban-client status sshd | grep -E "Currently banned|Banned IP"'
```

**Captura:** Las tres terminales mostrando el flujo completo: intentos → detección → ban.
