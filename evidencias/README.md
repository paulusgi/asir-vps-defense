# Evidencias Técnicas — ASIR VPS Defense System

> Documentación de evidencias técnicas del proyecto ASIR VPS Defense System. Cada subcarpeta corresponde a un bloque de validación del sistema y contiene las capturas y fragmentos de log obtenidos durante las pruebas de funcionamiento.

---

## Índice de evidencias

| ID | Archivo | Qué demuestra | Criterio de éxito |
|----|---------|---------------|-------------------|
| EV-01 | `01_infraestructura/ev01_ss_puertos.png` | Cowrie en :22, sshd en :2929 | Ports correctos visibles en `ss -tlnp` |
| EV-02 | `01_infraestructura/ev02_docker_ps.png` | Todos los contenedores running/healthy | Estado `Up (healthy)` en todos |
| EV-03 | `01_infraestructura/ev03_docker_inspect_cowrie.png` | Healthcheck Cowrie passing | `"Status": "healthy"` |
| EV-04 | `01_infraestructura/ev04_ufw_status.png` | Reglas firewall correctas | :22 ALLOW, :8888 bloqueado |
| EV-05 | `01_infraestructura/ev05_banner_ssh_22.png` | Banner honeypot en puerto 22 | Banner falso OpenSSH 8.2p1 Ubuntu |
| EV-06 | `02_honeypot_cowrie/ev06_cowrie_log_ataques.png` | Login attempts capturados | Líneas `login attempt` con IP/usuario/password |
| EV-07 | `02_honeypot_cowrie/ev07_cowrie_log_fragmento.txt` | Log texto para memoria | Fragmento pegado directamente en memoria |
| EV-08 | `02_honeypot_cowrie/ev08_sesion_tty_lista.png` | Sesiones TTY grabadas | Archivos `.log` listados en volumen del host |
| EV-09 | `02_honeypot_cowrie/ev09_sesion_tty_replay.png` | Replay de sesión de atacante | Comandos del atacante reproducidos |
| EV-10 | `02_honeypot_cowrie/ev10_hydra_result.txt` | Resultado prueba controlada hydra | Conexiones al honeypot registradas |
| EV-11 | `03_fail2ban/ev11_fail2ban_status.png` | IPs baneadas actualmente | `Currently banned > 0` |
| EV-12 | `03_fail2ban/ev12_fail2ban_log_bans.png` | Entradas Ban en el log | Líneas `Ban <IP>` con timestamp |
| EV-13 | `03_fail2ban/ev13_fail2ban_log_fragmento.txt` | Log texto para memoria | Fragmento pegado directamente en memoria |
| EV-14 | `04_observabilidad/ev14_loki_ready.png` | Loki operativo | Respuesta `ready` |
| EV-15 | `04_observabilidad/ev15_promtail_targets.png` | Promtail recopilando logs | Jobs `auth`, `cowrie`, `cowrie_json` presentes en Loki |
| EV-16 | `04_observabilidad/ev16_loki_query_cowrie.png` | Datos cowrie llegando a Loki | Query devuelve líneas con eventos |
| EV-17 | `04_observabilidad/ev17_loki_query_fail2ban.png` | Datos fail2ban llegando a Loki | Query devuelve líneas con bans |
| EV-18 | `05_panel_privado/ev18_panel_bloqueado_ext.png` | Panel no accesible sin túnel | `Connection refused` o timeout desde exterior |
| EV-19 | `05_panel_privado/ev19_tunel_ssh_activo.png` | Túnel SSH establecido | Comando ssh -L visible en terminal |
| EV-20 | `05_panel_privado/ev20_panel_dashboard.png` | Panel con datos reales | Dashboard completo visible en localhost:9999 |
| EV-21 | `05_panel_privado/ev21_panel_tabla_ataques.png` | Tabla de intentos en panel | IPs, usuarios, contraseñas, timestamps |
| EV-22 | `05_panel_privado/ev22_panel_mapa_geo.png` | Mapa de geolocalización | Pines en IPs atacantes |
| EV-23 | `05_panel_privado/ev23_panel_grafica_tiempo.png` | Gráfica de actividad temporal | Pico visible durante prueba controlada |
| EV-24 | `05_panel_privado/ev24_panel_honeypot_comandos.png` | Pestaña Honeypot con comandos ejecutados | Se visualizan IPs, credenciales, intentos y comandos de la sesión controlada |
| EV-25 | `06_ssh_real/ev25_ssh_real_clave.png` | Conexión con clave a :2929 | Login exitoso, sin contraseña |
| EV-26 | `06_ssh_real/ev26_ssh_password_rechazado.png` | Contraseña rechazada en :2929 | `Permission denied (publickey)` |
| EV-27 | `06_ssh_real/ev27_nmap_puertos.png` | Separación de puertos confirmada | nmap distingue :22 (honeypot) vs :2929 (real) |
| EV-28 | `07_pipeline_completo/ev28_pipeline_ataque.png` | Ciclo ataque → cowrie.log → Loki | 3 ventanas simultáneas con el flujo |
| EV-29 | `07_pipeline_completo/ev29_pipeline_ban.png` | Ciclo intento → fail2ban.log → ban | 2 ventanas mostrando detección y ban |
| EV-30 | `07_pipeline_completo/ev30_pipeline_honeypot_comandos.png` | Flujo completo de comandos en honeypot | Ataque, registro en Cowrie y visualización posterior en panel |

---

## Relación evidencias ↔ objetivos del proyecto

| Objetivo MVP | Evidencias que lo demuestran |
|---|---|
| Honeypot activo en puerto 22 | EV-01, EV-02, EV-05, EV-06 |
| SSH real seguro en puerto alternativo | EV-01, EV-25, EV-26, EV-27 |
| Fail2Ban baneando automáticamente | EV-11, EV-12, EV-13 |
| Loki/Promtail recogiendo logs | EV-14, EV-15, EV-16, EV-17 |
| Panel con métricas reales | EV-20, EV-21, EV-22, EV-23, EV-24 |
| Panel solo accesible por túnel | EV-18, EV-19 |
| Separación honeypot / SSH real | EV-05, EV-25, EV-26, EV-27 |
| Pipeline completo demostrado | EV-28, EV-29, EV-30 |


