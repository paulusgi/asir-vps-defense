# Verificaciones post-deploy (mainv2)

## Comandos rápidos de chequeo (ejecutar en el VPS, como root o con sudo)
1) Estado de contenedores (health/puertos):
   - `cd /home/<tu_admin>/asir-vps-defense && docker compose ps`
2) Logs breves de servicios críticos:
   - `cd /home/<tu_admin>/asir-vps-defense && docker compose logs --tail=80 admin-nginx php-app mysql loki promtail`
3) Panel responde en loopback:
   - `curl -I http://127.0.0.1:8888`
4) MySQL vivo desde el contenedor:
   - `cd /home/<tu_admin>/asir-vps-defense && docker exec -it asir_mysql mysql -uroot -p"$(grep MYSQL_ROOT_PASSWORD .env | cut -d= -f2)" -e "select 1;"`
5) Fail2Ban activo y jail sshd cargada:
   - `systemctl status fail2ban --no-pager`
   - `fail2ban-client status`
   - `fail2ban-client status sshd`
6) Firewall UFW (sólo 22 y loopback 8888 expuesto vía bind):
   - `ufw status numbered`
7) Puertos realmente en escucha (deberías ver 22 en 0.0.0.0 y 8888 sólo en 127.0.0.1):
   - `ss -tulpen | grep -E ':22|:8888'`
8) Promtail leyendo logs host:
   - `docker exec -it asir_promtail cat /positions/positions.yaml | head`
9) Espacio en disco (volúmenes MySQL/Loki):
   - `df -h / /var /home`

## Si algo falla
- Contenedores reiniciando: `docker compose logs -f mysql` (clave root errónea en volumen previo) o `docker compose logs -f php-app` (extensiones).
- Puerto 8888 no responde: espera 30-60s y revisa `docker compose ps`; si sigue, mira `docker compose logs --tail=80 admin-nginx php-app`.
- Fail2Ban inactivo: `systemctl restart fail2ban` y re-ejecuta `fail2ban-client status`.
- GeoLite no descargado: revisa si tienes `geoip/GeoLite2-City.mmdb`; si no, exporta `GEOIP_LICENSE_KEY=<tu_key>` y re-lanza `./deploy.sh` (se saltará pasos hechos y sólo bajará mmdb/seed).
