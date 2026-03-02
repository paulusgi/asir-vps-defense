# 04 — Observabilidad (Loki + Promtail)

Este bloque verifica el funcionamiento del stack de observabilidad, comprobando que Promtail recopilaba activamente los logs del sistema y los enviaba a Loki, donde quedaban disponibles para consulta mediante LogQL.

---

## EV-14 — `ev14_loki_ready.png`

Se realizó una petición HTTP al endpoint `/ready` de Loki para verificar que el servicio había completado su inicialización y se encontraba en estado operativo. La respuesta `ready` confirmó que Loki estaba aceptando escrituras y sirviendo consultas.

```bash
curl -s http://localhost:3100/ready
```

---

## EV-15 — `ev15_promtail_targets.png`

Se consultó el endpoint `/targets` de Promtail para obtener el estado de cada job de recopilación configurado. Se verificó que los tres jobs definidos en `promtail/config.yml` — `cowrie`, `fail2ban` y `auth` — presentaban estado activo y estaban procesando sus fuentes de log respectivas.

```bash
curl -s http://localhost:9080/targets | python3 -m json.tool
```

---

## EV-16 — `ev16_loki_query_cowrie.png`

Se ejecutó una consulta LogQL contra la API de Loki para recuperar eventos del job `cowrie` dentro de la ventana temporal de las pruebas. La respuesta confirmó que los logs generados por el honeypot durante los ataques controlados habían llegado correctamente al sistema de centralización.

```bash
curl -s -G 'http://localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="cowrie"}' \
  --data-urlencode "start=$(date -d '1 hour ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  --data-urlencode 'limit=5' \
  | python3 -m json.tool | head -40
```

---

## EV-17 — `ev17_loki_query_fail2ban.png`

De forma análoga, se consultó Loki para el job `fail2ban`. La respuesta incluyó las entradas de ban generadas durante las pruebas, confirmando el pipeline completo: Fail2Ban escribe en su log → Promtail detecta el cambio → Loki indexa la entrada → la consulta lo devuelve.

```bash
curl -s -G 'http://localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="fail2ban"}' \
  --data-urlencode "start=$(date -d '1 hour ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  --data-urlencode 'limit=5' \
  | python3 -m json.tool | head -40
```
