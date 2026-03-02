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
