# Evidence

Screenshots and log excerpts from a deployment of **ASIR VPS Defense v2.1.0** on a Debian 12 VPS exposed to the Internet, captured between 2 March and 6 April 2026. The current version is v3.0.2; what changed since the captures is listed under [Version notes](#version-notes).

Each folder covers one part of the system. Its `METHODOLOGY.md` describes every capture in the same way: what it shows, the command used, what it demonstrates, and notes on anything that needs context.

## Reading the captures

- **Version.** Everything here is v2.1.0. Where a capture shows behaviour that v3.0.0 changed, its entry says so.
- **Panel language.** The panel UI was in Spanish at the time, and the screenshots show it that way. Labels that appear often: *Baneos* = bans, *Intentos* = attempts, *Usuario* = user, *Contraseña* = password, *País* = country, *Fecha* = date, *Resultado* = result, *Mapa* = map, *Auditoría* = audit, *Usuario inválido* = invalid user, *Anónimo* = anonymous, *hace 3m* = 3 minutes ago, *ahora mismo* = just now. Panel dates are day/month: `5/4` is 5 April.
- **Admin account.** Commands are written with `<admin_user>`. The screenshots show the real account, `sys_ops`. The panel has its own login, `admin`, which is not a Linux account.
- **Redactions.** The public IP of the VPS, the public IP of the admin's workstation and the provider's host name are covered in the images and replaced in the text files by `<VPS_IP>`, `<ADMIN_IP>` and `<VPS_HOST>`. Attackers' IPs are left visible: they are what the evidence is about.
- **Time zones.** In March the host clock was on CET, UTC+1 (EV-03 shows `+01:00`). Fail2Ban writes host local time; Cowrie writes UTC, with a trailing `Z`. The panel shows times in the browser's time zone. See [04_observability](04_observability/METHODOLOGY.md#time-zones).
- **Terminal artefacts.** In some captures a pasted command appears a second time, highlighted, after the prompt. It is a display artefact of pasting into the terminal; the output is that of a single run.
- **Address bar.** No panel screenshot shows the browser's address bar. Why the panel can only have been reached through the SSH tunnel is explained in [05_private_panel](05_private_panel/METHODOLOGY.md).

## Index

| ID | File | Date | What it shows |
|----|------|------|---------------|
| EV-01 | [ev01_listening_ports.png](01_infrastructure/ev01_listening_ports.png) | not shown | `ss -tlnp`: Docker on :22, `sshd` on :2929, panel on 127.0.0.1:8888 |
| EV-02 | [ev02_docker_ps.png](01_infrastructure/ev02_docker_ps.png) | not shown | Six containers up; Cowrie and Promtail 12 s after a restart, health check still starting |
| EV-03 | [ev03_docker_inspect_cowrie.png](01_infrastructure/ev03_docker_inspect_cowrie.png) | 2 Mar | Cowrie health check: `healthy`, one passing run |
| EV-04 | [ev04_ufw_status.png](01_infrastructure/ev04_ufw_status.png) | not shown | UFW rules: 22/tcp and 2929/tcp allowed, nothing else |
| EV-05 | [ev05_ssh_banner_port22.png](01_infrastructure/ev05_ssh_banner_port22.png) | not shown | Port 22 banner: Cowrie posing as OpenSSH 8.2p1 Ubuntu |
| EV-06 | [ev06_cowrie_log_attacks.png](02_cowrie_honeypot/ev06_cowrie_log_attacks.png) | 2 Mar | Cowrie log: connections and accepted logins from Internet hosts |
| EV-07 | [ev07_cowrie_log_excerpt.txt](02_cowrie_honeypot/ev07_cowrie_log_excerpt.txt) | 2 Mar | The same kind of log lines, as text |
| EV-08 | [ev08_tty_sessions_list.png](02_cowrie_honeypot/ev08_tty_sessions_list.png) | 2 Mar | Recorded sessions on the `cowrie_data` volume |
| EV-09 | [ev09_tty_session_replay.png](02_cowrie_honeypot/ev09_tty_session_replay.png) | 2 Mar | Replay of one session: `whoami`, `ifconfig`, `ls /root`, `cd` |
| EV-10 | [ev10_hydra_result.txt](02_cowrie_honeypot/ev10_hydra_result.txt) | 2 Mar | Controlled Hydra test, 4 passwords for `root`, all accepted by Cowrie |
| EV-10b | [ev10b_panel_honeypot_commands.png](02_cowrie_honeypot/ev10b_panel_honeypot_commands.png) | 6 Apr | Panel, Honeypot tab: top IPs, user names, recent attempts, commands |
| EV-11 | [ev11_fail2ban_status.png](03_fail2ban/ev11_fail2ban_status.png) | not shown | `sshd` jail: 24 failures counted, 2 IPs banned |
| EV-12 | [ev12_fail2ban_log_bans.png](03_fail2ban/ev12_fail2ban_log_bans.png) | 2 Mar | The only two `Ban` lines in `fail2ban.log` at the time (00:08) |
| EV-13 | [ev13_fail2ban_log_excerpt.txt](03_fail2ban/ev13_fail2ban_log_excerpt.txt) | 2 Mar | `Found` and `Ban` lines leading to those two bans, as text |
| EV-13b | [ev13b_panel_bans.png](03_fail2ban/ev13b_panel_bans.png) | 5 Apr | Panel, Bans tab: one real-SSH ban, three Cowrie-jail bans |
| EV-14 | [ev14_loki_ready.png](04_observability/ev14_loki_ready.png) | not shown | Loki `/ready` returns `ready` |
| EV-15 | [ev15_loki_job_labels.png](04_observability/ev15_loki_job_labels.png) | not shown | Loki's `job` label values: `auth`, `cowrie`, `cowrie_json` |
| EV-16 | [ev16_loki_query_cowrie.png](04_observability/ev16_loki_query_cowrie.png) | 2 Mar | LogQL query on `{job="cowrie"}`: commands from a honeypot session |
| EV-17 | [ev17_loki_query_fail2ban.png](04_observability/ev17_loki_query_fail2ban.png) | 2 Mar | LogQL query on `{job="fail2ban"}`: a `Ban` and four `Found` lines |
| EV-18 | [ev18_panel_unreachable_from_internet.png](05_private_panel/ev18_panel_unreachable_from_internet.png) | not shown | `curl` to port 8888 from outside times out |
| EV-19 | [ev19_ssh_tunnel.png](05_private_panel/ev19_ssh_tunnel.png) | not shown | The tunnel command, stopped at the key passphrase prompt |
| EV-20 | [ev20_panel_dashboard.png](05_private_panel/ev20_panel_dashboard.png) | 5 Apr | Panel dashboard: host metrics, Fail2Ban and SSH counters; Cowrie counters at 0 |
| EV-21 | [ev21_panel_ssh_attempts.png](05_private_panel/ev21_panel_ssh_attempts.png) | ~2 Mar | Panel, SSH tab: failed logins on the real SSH, per IP and user |
| EV-22 | [ev22_panel_geo_map.png](05_private_panel/ev22_panel_geo_map.png) | not shown | Panel map: 23 locations (6 bans, 1 SSH, 16 honeypot) |
| EV-23 | [ev23_panel_recent_attempts.png](05_private_panel/ev23_panel_recent_attempts.png) | ~2 Mar | Panel, SSH tab: table of recent attempts (date and user) |
| EV-24 | [ev24_panel_audit_log.png](05_private_panel/ev24_panel_audit_log.png) | 5 Apr | Panel, Audit tab: two successful logins and one failed |
| EV-25 | [ev25_real_ssh_key_login.png](06_real_ssh/ev25_real_ssh_key_login.png) | 2 Mar | Admin logs in to :2929 with a key; no server password prompt |
| EV-26 | [ev26_real_ssh_password_rejected.png](06_real_ssh/ev26_real_ssh_password_rejected.png) | not shown | Password-only login as the admin: `Permission denied (publickey)` |
| EV-27 | [ev27_nmap_ports.png](06_real_ssh/ev27_nmap_ports.png) | 2 Mar | `nmap -sV`: Ubuntu banner on 22, Debian OpenSSH on 2929, 8888 filtered |
| EV-28 | [ev28_pipeline_attack_to_loki.png](07_end_to_end_pipeline/ev28_pipeline_attack_to_loki.png) | 2 Mar | Test login to Cowrie, its log line, and a Loki entry with the same timestamp |
| EV-29 | [ev29_pipeline_attempts_to_ban.png](07_end_to_end_pipeline/ev29_pipeline_attempts_to_ban.png) | 2 Mar | Six failed SSH attempts from the workstation, six `Found` lines, one ban |

"Date" is the date of the newest log line, panel entry or command output visible in the capture; the capture was taken then or later. "~2 Mar": the panel shows events of 1 March as 16 hours old.

## What the evidence covers

| Claim | Evidence | Limits |
|---|---|---|
| Cowrie answers on port 22; the host's OpenSSH listens only on 2929 | EV-01, EV-05, EV-27 | |
| Cowrie accepts any credentials and records connections, logins, sessions and commands | EV-06 to EV-10b, EV-16 | EV-09's session has no visible source IP |
| The real SSH refuses password logins for the admin account | EV-25, EV-26 | In v2.1.0 other user names could still try passwords (EV-29) |
| Fail2Ban bans IPs that fail on the real SSH | EV-11 to EV-13, EV-29 | Threshold was 6 attempts in v2.1.0 |
| Promtail ships host and Cowrie logs to Loki, queryable with LogQL | EV-14 to EV-17, EV-28 | |
| The panel is reachable only from the host's loopback | EV-01, EV-02, EV-18, EV-19, EV-27 | Inferred from the bindings and the outside tests; no screenshot shows the address bar |
| The panel shows live data | EV-10b, EV-13b, EV-20 to EV-24 | Geolocation labels are unreliable (EV-13b); EV-20 shows Cowrie counters at 0 |
| An event can be followed end to end | EV-28 (Cowrie → Loki), EV-29 (SSH attempts → ban) | EV-28 matches the Loki entry by timestamp only |

## Version notes

The captures show v2.1.0. These are the changes in v3.0.0 that affect how they should be read.

1. **Real SSH: one account, public key only.** v3.0.0 sets `AllowUsers <admin_user>`, `AuthenticationMethods publickey` and `PasswordAuthentication no`. In v2.1.0 only the admin account was key-only, through a `Match User` block; every other user name was offered password authentication. That is why EV-26 shows `Permission denied (publickey)` for the admin, while EV-29 shows `Permission denied (password)` for `wronguser` on the same port, and why the panel's SSH tab (EV-21, EV-23) lists failed password logins on the real SSH. v2.1.0 also created a "bait" Linux account on the host, with a random password, as a target for those attempts. v3.0.0 does not create it.
2. **Fail2Ban `sshd` jail: 2 attempts.** Key-only SSH logs one line per rejected attempt, so v3.0.0 bans after 2 attempts in 10 minutes (35 days). v2.1.0 banned after 6, which is what EV-13 and EV-29 show.
3. **Fail2Ban `cowrie` jail.** In v2.1.0 this jail could not work as intended. Its filter read Cowrie's UTC timestamps as host local time, so on a host ahead of UTC every match looked at least an hour old and fell outside the 10-minute window. And its ban acted on the host's input path, which traffic to port 22 does not cross, because Docker forwards that port to the container. EV-13 has no `[cowrie]` lines, and EV-20 shows an empty "Cowrie bans" table. EV-13b, taken a few minutes after EV-20, does list three `[cowrie]` bans: with the filter as described they should not have happened, and the captures do not show why they did. In v3.0.0 the filter reads the time-zone offset, and an IP that makes 5 connections to Cowrie in 10 minutes is blocked from the real host (every host port, through an nftables rule on the input hook) for 7 days. It **can still reach Cowrie**, so it keeps feeding the honeypot.
4. **Honeypot network.** In v3.0.0 Cowrie runs alone on its own Docker network, `honeypot_net`. In v2.1.0 it shared a network with nginx and PHP-FPM. The captures do not show the networks.
5. **Panel.** v3.0.0 escapes everything that comes from logs (XSS), sends a nonce-based Content Security Policy and hardens the login. Its UI is in English; the screenshots show the earlier Spanish UI.
6. **Pinned images.** v3.0.0 pins Cowrie 2.9.0 (the version the captures were taken with), nginx 1.30, PHP 8.3, MySQL 8.4, and Loki and Promtail 2.9.17. The v2.1.0 Compose file used `cowrie/cowrie:latest`, `nginx:alpine`, PHP 8.2, MySQL 8.0, and Loki and Promtail 2.9.2.
7. **Geolocation.** The cities and continents in the panel's country column (EV-10b, EV-13b) came from a v2.1.0 parsing bug: the panel took the first English name in the GeoLite2 record. v3.0.0 reads the record through the MaxMind PHP extension and shows the country. The map in EV-22 used CARTO tiles, which now require an API key; since v3.0.2 the map is drawn from a bundled Natural Earth outline instead.
8. **Promtail health check.** The Promtail image has no `wget`, which the v2.1.0 health check called, so Promtail could never be reported healthy (EV-02 catches it still starting). v3.0.0 checks `/ready` with bash instead.
