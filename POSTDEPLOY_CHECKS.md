# Post-deployment checks

Commands to verify a v3.0.0 deployment. Run them on the server as the admin user, from the project folder (by default `/home/<admin_user>/asir-vps-defense`). The installer adds the admin to the `docker` group, so `docker` works without `sudo` once you have logged in again after the installation. Replace `2929` if you chose another SSH port.

The expected results follow from the v3.0.0 configuration. v3.0.0 has not yet been re-deployed end to end on a VPS, so they have not all been observed on one; the [evidence](evidence/README.md) shows v2.1.0.

> **Test from another address.** Fail2Ban does not exempt your workstation. Two failed attempts on the real SSH in 10 minutes ban that address from port 2929 for 35 days, and five connections to Cowrie (port 22) in 10 minutes block it from every port of the host for 7 days. The ban also cuts sessions that are already open. Run the negative tests and the honeypot tests below from an address you do not administer from, or make sure you can reach the provider's console to lift a ban with `sudo fail2ban-client set sshd unbanip <ADMIN_IP>` (or `set cowrie unbanip`).

## Containers

```bash
docker compose ps
```

Expected: six services running, `cowrie`, `admin-nginx`, `php-app`, `mysql`, `loki` and `promtail`. nginx and PHP-FPM have no health check; the other four should report `healthy` about a minute after starting:

```bash
for c in asir_cowrie asir_mysql asir_loki asir_promtail; do
  printf '%s: ' "$c"; docker inspect -f '{{.State.Health.Status}}' "$c"
done
```

The Promtail image has no `wget` or `curl`, so its health check asks `/ready` through bash's `/dev/tcp`.

Recent container logs:

```bash
docker compose logs --tail=80 cowrie admin-nginx php-app mysql loki promtail
```

## Listening ports

```bash
sudo ss -tlnp | grep -E ':(22|2929|8888)[[:space:]]'
```

Without `sudo`, `ss` does not show the owning processes. Expected: port 22 held by `docker-proxy` (Cowrie), never by `sshd`; `sshd` on 2929; `docker-proxy` on `127.0.0.1:8888` only.

## Real SSH

```bash
sudo sshd -T | grep -E '^(port|allowusers|passwordauthentication|authenticationmethods|allowtcpforwarding) '
```

Expected (the order may differ):

```
port 2929
allowusers <admin_user>
passwordauthentication no
allowtcpforwarding local
authenticationmethods publickey
```

From another address (see the warning above), a password login and an unknown user should both be refused with `Permission denied (publickey).`:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2929 <admin_user>@<VPS_IP>
ssh -o BatchMode=yes -p 2929 nosuchuser@<VPS_IP>
```

The panel tunnel, from your workstation (then browse to <http://localhost:8888>):

```bash
ssh -N -L 8888:127.0.0.1:8888 -p 2929 <admin_user>@<VPS_IP>
```

## Fail2Ban

```bash
systemctl status fail2ban --no-pager
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status cowrie
```

Expected: the jail list contains `cowrie` and `sshd`; each status shows its log source, failure counts and banned IPs. The `cowrie` jail reads `/var/log/cowrie/cowrie.log`.

Check that the Cowrie filter matches the log and its UTC timestamps (in v2.1.0 it read them as local time):

```bash
sudo fail2ban-regex /var/log/cowrie/cowrie.log /etc/fail2ban/filter.d/cowrie.conf
```

Expected: one match per `New connection` line. Zero matches on a log that has such lines means the filter or its date pattern does not fit.

The firewall rules Fail2Ban creates:

```bash
sudo nft list table inet f2b-table
```

Expected: an address set per jail holding the banned IPs, and a chain on the `input` hook where the `sshd` rule is limited to port 2929 and the `cowrie` rule covers every port. This table exists only when Fail2Ban uses its nftables actions, and it may appear only after the first ban; with the iptables actions, look at `sudo iptables -S | grep f2b` instead.

## Firewall

```bash
sudo ufw status verbose
```

Expected: `Status: active`, a default of `deny (incoming), allow (outgoing)`, and rules allowing `22/tcp` (Cowrie) and `2929/tcp` (real SSH) for IPv4 and IPv6. Docker forwards port 22 to Cowrie with its own rules, so the `22/tcp` rule is not what lets that traffic in.

From outside (each command opens connections to the host; see the warning above):

```bash
nc -w3 <VPS_IP> 22                                   # Cowrie's banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
curl -sS -m 5 -o /dev/null http://<VPS_IP>:8888/     # times out: the panel is not reachable
```

## Docker networks

Compose prefixes network names with the project name, the folder's name by default (`docker network ls` lists them).

```bash
docker network inspect asir-vps-defense_honeypot_net \
  --format '{{.Name}}: {{range .Containers}}{{.Name}} {{end}}'
```

Expected: `asir_cowrie` alone.

```bash
docker network inspect asir-vps-defense_frontend_net asir-vps-defense_backend_net \
  --format '{{.Name}}: {{range .Containers}}{{.Name}} {{end}}'
```

Expected: `frontend_net` holds `asir_admin_nginx` and `asir_php`; `backend_net` holds `asir_php`, `asir_mysql`, `asir_loki` and `asir_promtail` (in any order).

## Panel on loopback

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8888/
```

Expected: an HTTP status code from nginx, such as `200` for the login page, not a connection error.

## Loki and Promtail

Loki's port is not published on the host, so it is queried from inside its container.

```bash
docker exec asir_loki wget -qO- http://localhost:3100/ready
```

Expected: `ready`. Right after a start Loki may report that it is not ready yet; try again a minute later.

Jobs that sent logs in the last 24 hours (without `start`, Loki only looks at the last 6 hours):

```bash
START="$(date -d '24 hours ago' +%s)000000000"
docker exec asir_loki wget -qO- "http://localhost:3100/loki/api/v1/label/job/values?start=${START}"
```

Expected: those of `auth`, `cowrie`, `cowrie_json` and `fail2ban` that wrote at least one line in that period.

Newest Cowrie lines in the last hour (`python3` only pretty-prints the JSON; with no `end`, Loki uses the current time):

```bash
START="$(date -d '1 hour ago' +%s)000000000"
docker exec asir_loki wget -qO- \
  "http://localhost:3100/loki/api/v1/query_range?query=%7Bjob%3D%22cowrie%22%7D&start=${START}&limit=5" \
  | python3 -m json.tool | head -40
```

Promtail's read positions:

```bash
docker exec asir_promtail cat /positions/positions.yaml
```

Expected: one entry per log file Promtail follows (paths under `/var/log/host/`), each with the byte offset read so far. The file lives in the named volume `promtail_positions` (on the host, `asir-vps-defense_promtail_positions`), mounted at `/positions`, so the offsets survive container restarts.

## Cowrie

From another address (see the warning above), log in to the honeypot. Any password is accepted and you land in Cowrie's fake shell:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 root@<VPS_IP>
```

Then, on the server, the last lines of Cowrie's log should show a `New connection` from that address and a `login attempt [root/...] succeeded`:

```bash
sudo tail -n 20 /var/log/cowrie/cowrie.log
```

Recorded sessions are on the `cowrie_data` volume:

```bash
sudo ls -lh "$(docker volume inspect asir-vps-defense_cowrie_data --format '{{.Mountpoint}}')/tty/"
```

## Disk space

```bash
df -h / /var /home
```
