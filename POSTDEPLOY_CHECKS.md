# Verificaciones post-deploy

Ubícate en la carpeta con `docker-compose.yml` (por defecto `/home/<tu_admin>/asir-vps-defense`).

## Comandos de check

**Contenedores en ejecución**
```bash
docker compose ps
```

**Logs Docker recientes (80 líneas)**
```bash
docker compose logs --tail=80 admin-nginx php-app mysql loki promtail
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

**Firewall UFW** (solo el puerto SSH elegido debe estar abierto)
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
