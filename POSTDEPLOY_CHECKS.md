# Verificaciones post-deploy

Ubícate en la carpeta con `docker-compose.yml` (por defecto `/home/<tu_admin>/asir-vps-defense`).

## Comandos de check

**Contenedores en ejecución** (debe aparecer asir_cowrie como Up)
```bash
docker compose ps
```

**Logs Docker recientes (80 líneas)**
```bash
docker compose logs --tail=80 admin-nginx php-app mysql loki promtail cowrie
```

**Panel en loopback**
```bash
curl -I http://127.0.0.1:8888
```

**Salud MySQL** (esperado `healthy`)
```bash
docker inspect -f '{{.State.Health.Status}}' asir_mysql
```

**Fail2Ban activo**
```bash
systemctl status fail2ban --no-pager
fail2ban-client status sshd
```

**Firewall UFW** (puerto 22 Cowrie + puerto SSH real deben aparecer)
```bash
sudo ufw status numbered
```

**Puertos expuestos** (ajusta el puerto SSH si elegiste otro)
```bash
ss -tulpen | grep -E ':(22|2929|8888)\s'
```

**Salud Loki** (esperado `healthy`)
```bash
docker inspect -f '{{.State.Health.Status}}' asir_loki
```

**Promtail posiciones**
```bash
docker exec -it asir_promtail head /positions/positions.yaml
```

**Espacio en disco**
```bash
df -h / /var /home
```

---

## Verificación del Honeypot Cowrie

**Estado del contenedor Cowrie**
```bash
docker compose ps cowrie
docker inspect -f '{{.State.Health.Status}}' asir_cowrie
```

**Puerto 22 escuchando** (debe aparecer 0.0.0.0:22)
```bash
ss -tlnp | grep ':22 '
docker port asir_cowrie
```

**Logs en tiempo real de Cowrie**
```bash
docker compose logs -f cowrie
tail -f /var/log/cowrie/cowrie.log
```

**Simular ataque controlado al honeypot** (desde tu máquina local)
```bash
# Este ataque va al honeypot Cowrie en puerto 22, NO al SSH real
ssh -p 22 -o StrictHostKeyChecking=no root@<IP_VPS>
# Introduce cualquier contraseña — Cowrie la acepta y registra todo

# Verificar que el intento aparece en logs
tail -20 /var/log/cowrie/cowrie.log
```

**Verificar separación honeypot / SSH real**
```bash
# SSH real sigue en el puerto configurado (ej: 2929)
ssh -p 2929 <admin_user>@<IP_VPS>

# Puerto 22 es Cowrie — cualquier credencial "entra" al entorno falso
ssh -p 22 -o StrictHostKeyChecking=no testuser@<IP_VPS>
```

**Verificar pipeline: Cowrie → Promtail → Loki**
```bash
# Promtail tiene posición del log de Cowrie
docker exec asir_promtail cat /positions/positions.yaml | grep cowrie

# Loki contiene entradas del job=cowrie
curl -Gs 'http://127.0.0.1:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="cowrie"}' \
  --data-urlencode "start=$(date -d '1 hour ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  --data-urlencode 'limit=5' | python3 -m json.tool
```

**Ciclo completo de evidencia**
```
Atacante → puerto 22 → Cowrie captura
  → /var/log/cowrie/cowrie.log
    → Promtail (job=cowrie) → Loki
      → Panel PHP fetchCowrieMetrics()
        → Dashboard: IPs, usuarios, mapa
```
