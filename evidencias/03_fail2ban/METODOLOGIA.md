# 03 — Fail2Ban

Este bloque acredita el funcionamiento del sistema de detección y bloqueo automático de IPs mediante Fail2Ban, incluyendo el ciclo completo de detección, registro y aplicación de la regla de ban.

---

## EV-11 — `ev11_fail2ban_status.png`

Se consultó el estado de la jail `sshd` de Fail2Ban en el momento de la validación. La salida mostró los contadores de intentos fallidos detectados, el total acumulado de bans aplicados desde el inicio del servicio, y la lista de IPs bloqueadas activamente en ese instante.

```bash
fail2ban-client status sshd
```

---

## EV-12 — `ev12_fail2ban_log_bans.png`

Se inspeccionó el log de Fail2Ban filtrando por las entradas de tipo `NOTICE` correspondientes a acciones de ban y unban. Cada línea registrada incluye timestamp, nombre de la jail, acción ejecutada e IP afectada, constituyendo la traza de auditoría del sistema de bloqueo.

```bash
grep -E "Ban|Unban|NOTICE" /var/log/fail2ban.log | tail -30
```

---

## EV-13 — `ev13_fail2ban_log_fragmento.txt`

Se extrajo un fragmento del log de Fail2Ban para su inclusión en el anexo técnico de la memoria. El fragmento cubre el período de las pruebas controladas, mostrando la secuencia de detección de intentos fallidos y la aplicación subsiguiente de los bans correspondientes.

```bash
grep -E "Ban|Found|Restore" /var/log/fail2ban.log | tail -50
```

---

## EV-11 — `ev11_fail2ban_status.png`

**Qué demuestra:** Fail2Ban tiene IPs baneadas actualmente.

**Comando en el VPS:**
```bash
fail2ban-client status sshd
```

**Qué debe aparecer:**
```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  |- Total failed:     47
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 3
   |- Total banned:     12
   `- Banned IP list:   185.x.x.x 193.x.x.x ...
```

> Si `Currently banned` es 0, ejecutar PRUEBA-B (ataques fallidos desde IP externa) y esperar 1-2 minutos.

---

## EV-12 — `ev12_fail2ban_log_bans.png`

**Qué demuestra:** El log de Fail2Ban registra los bans con timestamp e IP.

**Comando en el VPS:**
```bash
grep -E "Ban|Unban|NOTICE" /var/log/fail2ban.log | tail -30
```

**Qué debe aparecer:**
```
2026-03-01 14:35:44,123 fail2ban.actions [1234]: NOTICE  [sshd] Ban 185.220.101.47
2026-03-01 14:35:44,456 fail2ban.actions [1234]: NOTICE  [sshd] Ban 193.106.191.3
```

---

## EV-13 — `ev13_fail2ban_log_fragmento.txt`

**Qué demuestra:** Fragmento de log de Fail2Ban para incluir en la memoria.

**Cómo obtenerlo:**
```bash
grep -E "Ban|Found|Restore" /var/log/fail2ban.log | tail -50
```

**Instrucción:** Copiar la salida y pegarla directamente en este archivo `.txt`. Se incluirá como bloque de código en el anexo técnico de la memoria.
