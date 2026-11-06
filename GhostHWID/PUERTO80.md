# Ghost HWID por el puerto 80 de Kira

Esta integracion agrega una ruta en el archivo `/usr/local/bin/ws_server.py`
observado en la conversacion. El cliente usa el puerto **80**, y su payload debe
pedir la ruta **/hwid**. El puente envia ese trafico al servicio Ghost HWID que ya
esta escuchando internamente en 8081. Las demas rutas mantienen su logica previa.

No se puede poner otro listener independiente en el mismo puerto 80 ya ocupado.
Tampoco es necesario cambiar el puerto SSH de administracion 22.

## Aplicacion

Descarga `GhostHWID_puerto80.py` desde esta rama al VPS como
`/root/GhostHWID_puerto80.py`, y ejecuta:

```bash
python3 /root/GhostHWID_puerto80.py
```

Requiere que `ghosthwid.service` este activo y que el puente de Kira se ejecute
directamente con Python en un servicio systemd dedicado. Detecta el servicio a
partir de los procesos activos y comprueba su ExecStart. Si no lo puede reconocer,
se detiene antes de modificar el archivo; comparte su mensaje para revisar como
se inicia el puente. No intenta matar procesos o reiniciar Kira en general.

Reinicia exclusivamente el servicio del puente WebSocket identificado. **Se
interrumpiran las conexiones existentes de ese puente durante el reinicio.**
No modifica OpenSSH, PAM, firewall, clientes ni los contadores de Ghost HWID.

Hace un respaldo en `/var/lib/ghosthwid-route/`. Tras reiniciar, comprueba que
`GET /hwid` por localhost:80 responda 101 y negocie la misma clave de servidor
SSH que el servicio Ghost HWID en localhost:8081. No realiza login en esas pruebas.
Si falla, restaura el archivo original e intenta levantar el puente anterior.
La comprobacion local no demuestra accesibilidad desde la red movil del cliente.

## HTTP Custom

- Servidor: tu IP o dominio actual.
- Puerto: **80**.
- Modo: SSH estandar con payload HTTP; esta ruta no ofrece TLS externo.
- Payload de prueba (reemplaza TU_DOMINIO por tu dominio o IP):

```text
GET /hwid HTTP/1.1[crlf]Host: TU_DOMINIO[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```

El cambio esencial frente al payload anterior es `/hwid` en la primera linea.
Con `GET /` se conserva el destino anterior de Kira.

Usuario y contrasena: el HWID completo registrado, incluida la h si aparece.
Si tu perfil tiene Login con HWID, la app debe llenar esos datos. El ID de acceso
HC2- es distinto y no se usa como cuenta SSH en este servicio.

El transporte usa la variante observada en Kira: respuesta HTTP 101 seguida de
SSH sin tramas WebSocket. No garantiza compatibilidad con modos WebSocket/HCR
distintos, payloads partidos, dobles o versiones de HTTP Custom no probadas.

Si persiste "el servidor cerro la conexion", revisa el LOG de la app y:

```bash
systemctl status ghosthwid --no-pager
journalctl -u ghosthwid -n 30 --no-pager
```

Un mensaje generico de cierre no permite atribuir la causa a HWID, puerto,
payload, cuota o algoritmos SSH sin estas comprobaciones.

## Revision y retirada

Revision sin cambiar archivos ni reiniciar servicios:

```bash
python3 /root/GhostHWID_puerto80.py --check
```

Retirar la ruta restaurando el respaldo (reinicia el mismo puente):

```bash
python3 /root/GhostHWID_puerto80.py --restore
```

La retirada se niega a sobrescribir un archivo que haya cambiado despues de la
integracion. Las cuentas y el consumo de Ghost HWID no se eliminan.

Validacion local: cinco tests cubren seleccion de ruta, conservacion de destinos
originales, rechazo de codigo inesperado, deteccion de unidades dedicadas,
aplicacion/restauracion simuladas y proteccion de modificaciones posteriores.
La integracion real con el puente completo y HTTP Custom queda pendiente de
ejecutar y comprobar en el VPS. No se ha accedido remotamente al VPS del usuario.
