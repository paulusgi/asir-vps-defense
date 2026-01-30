# Verificaciones post-deploy (mainv2)

## Comandos rápidos de chequeo (ejecutar en el VPS, como root o con sudo)
> Debes estar en la carpeta que tiene `docker-compose.yml`. Por defecto es `/home/<tu_admin>/asir-vps-defense`. Si lo tienes en otro sitio, cambia la ruta o usa `docker compose -f /ruta/docker-compose.yml ...`.

Modo corto (desde la carpeta del proyecto):
- `cd /home/<tu_admin>/asir-vps-defense`
- `docker compose ps`
- `docker compose logs --tail=80 admin-nginx php-app mysql loki promtail`

Checks de servicio:
1) Panel responde en loopback: `curl -I http://127.0.0.1:8888`
2) MySQL vivo (sin contraseñas): `docker inspect -f '{{.State.Health.Status}}' asir_mysql` (debe decir `healthy`). Si sale `starting` espera unos segundos.
3) Fail2Ban: `systemctl status fail2ban --no-pager` y `fail2ban-client status sshd`
4) Firewall UFW (deploy.sh lo instala y habilita; ejecuta con sudo para tener `/usr/sbin` en PATH): `sudo ufw status numbered`
5) Puertos en escucha (22 en 0.0.0.0, 8888 sólo en 127.0.0.1): `ss -tulpen | grep -E ':22|:8888'`
6) Promtail leyendo logs host: `docker exec -it asir_promtail cat /positions/positions.yaml | head`
7) Espacio en disco (volúmenes MySQL/Loki): `df -h / /var /home`

## Si algo falla
- Contenedores reiniciando: `docker compose logs -f mysql` (clave root errónea en volumen previo) o `docker compose logs -f php-app` (extensiones).
- Puerto 8888 no responde: espera 30-60s y revisa `docker compose ps`; si sigue, mira `docker compose logs --tail=80 admin-nginx php-app`.
- Fail2Ban inactivo: `systemctl restart fail2ban` y re-ejecuta `fail2ban-client status`.
- GeoLite no descargado: revisa si tienes `geoip/GeoLite2-City.mmdb`; si no, exporta `GEOIP_LICENSE_KEY=<tu_key>` y re-lanza `./deploy.sh` (se saltará pasos hechos y sólo bajará mmdb/seed).
