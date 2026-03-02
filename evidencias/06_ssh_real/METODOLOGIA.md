# 06 — SSH Real (puerto alternativo)

Este bloque verifica la separación efectiva entre el servicio SSH de administración y el honeypot Cowrie, comprobando tanto el comportamiento diferenciado de cada servicio como el aislamiento de la autenticación.

---

## EV-25 — `ev25_ssh_real_clave.png`

Se realizó una conexión SSH al puerto alternativo del servidor utilizando la clave pública de administración. La sesión se estableció correctamente mediante autenticación por clave, sin que el servidor solicitara contraseña, conforme a la directiva `PasswordAuthentication no` aplicada por el script de despliegue en `sshd_config`.

```bash
ssh -p 2929 adminuser@<IP_VPS>
```

---

## EV-26 — `ev26_ssh_password_rechazado.png`

Se intentó autenticar en el puerto de administración forzando el uso exclusivo de contraseña, deshabilitando la autenticación por clave pública. El servidor rechazó la conexión con el error `Permission denied (publickey)`, confirmando que el acceso por contraseña estaba deshabilitado en el SSH real, a diferencia del comportamiento del honeypot en el puerto 22.

```bash
ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -p 2929 adminuser@<IP_VPS>
```

---

## EV-27 — `ev27_nmap_puertos.png`

Se realizó un escaneo con detección de versiones sobre los puertos 22, 2929 y 8888 del servidor. Los resultados mostraron que el puerto 22 respondía con el banner configurado en Cowrie y el puerto 2929 con el banner real del demonio SSH del host, evidenciando la separación de servicios. El puerto 8888 no respondió, confirmando su ausencia de exposición pública.

```bash
nmap -sV -p 22,2929,8888 <IP_VPS>
```
