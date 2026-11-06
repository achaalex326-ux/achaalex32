#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${1:-} == '--help' ]]; then
    echo 'Ghost HWID 0.1.1 (piloto): instala servicio independiente en TCP 8081.'
    echo 'No cambia Kira, OpenSSH, PAM ni firewall. Requiere Ubuntu 22.04.'
    echo 'Usa --extract DIRECTORIO para revisar el codigo sin instalarlo.'
    exit 0
fi
stage=$(mktemp -d /tmp/ghosthwid-build.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT

cat > "$stage/ghosthwid.py" <<'GHOST_PY_SOURCE'
#!/usr/bin/env python3
"""Ghost HWID 0.1.1: separate, experimental SSH forwarding endpoint.

Does not use system accounts or modify OpenSSH/PAM/Kira. Quota counts bytes
received on forwarding streams (upload + download), not IP/SSH overhead.
"""
import argparse
import contextlib
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import select
import socket
import sqlite3
import threading
import time

import paramiko

CONTACT = "@GhostProxy_Tech"
STATE = Path(os.environ.get("GHOSTHWID_STATE", "/var/lib/ghosthwid"))
GB = 1_000_000_000
LOCAL_PORTS = {7100, 7200, 7300, 7302}
ACTIVE = {}
ACTIVE_LOCK = threading.RLock()
SLOTS = threading.BoundedSemaphore(100)
LOG = logging.getLogger("ghosthwid")


def ident(value):
    if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|h[0-9a-fA-F]{31,32})", value):
        raise ValueError("HWID no valido: copia el ID del dispositivo completo, incluida la h si aparece. No uses el ID de acceso HC2-.")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


@contextlib.contextmanager
def db():
    conn = sqlite3.connect(STATE / "clients.sqlite3", timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, "
                  "name TEXT NOT NULL, expires REAL NOT NULL, quota INTEGER NOT NULL, "
                  "up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, "
                  "enabled INTEGER NOT NULL DEFAULT 1)")
    key = STATE / "host_key"
    if not key.exists():
        paramiko.RSAKey.generate(3072).write_private_key_file(str(key))
        key.chmod(0o600)


def get_client(key):
    with db() as c:
        row = c.execute("SELECT * FROM clients WHERE id=?", (key,)).fetchone()
        return dict(row) if row else None


def eligible(row):
    return bool(row and row["enabled"] and row["expires"] > time.time()
                and (row["quota"] == 0 or row["up"] + row["down"] < row["quota"]))


def charge(key, size, direction):
    """Atomically reserve the received payload bytes; zero means stop.

    Counters intentionally include data received for forwarding even if the
    other socket later fails. This is a traffic quota, not delivery accounting.
    """
    if direction not in ("up", "down"):
        raise ValueError("Invalid direction")
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM clients WHERE id=?", (key,)).fetchone()
        if not eligible(row):
            return 0
        left = row["quota"] - row["up"] - row["down"]
        allowed = size if not row["quota"] else min(size, left)
        c.execute(f"UPDATE clients SET {direction}={direction}+? WHERE id=?", (allowed, key))
        return allowed


def status_text(key):
    r = get_client(key)
    if not r:
        return "Cuenta no registrada.\r\n"
    expires = dt.datetime.fromtimestamp(r["expires"], dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    used = r["up"] + r["down"]
    left = "Sin limite" if not r["quota"] else f"{max(0, r['quota'] - used)/GB:.3f} GB"
    return (f"GHOST HWID | {r['name']}\r\n"
            f"Vence: {expires}\r\n"
            f"Subida: {r['up']/GB:.3f} GB | Bajada: {r['down']/GB:.3f} GB\r\n"
            f"Consumido: {used/GB:.3f} GB | Saldo: {left}\r\n"
            f"Una conexion SSH simultanea\r\nSoporte: {CONTACT}\r\n")


def connect_target(host, port):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Puerto invalido")
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    # Validate and connect the same numeric address: no second DNS resolution.
    last = OSError("Destino no permitido")
    for family, kind, proto, _, address in infos:
        ip = ipaddress.ip_address(address[0])
        permitted = ip.is_global or (str(ip) == "127.0.0.1" and port in LOCAL_PORTS)
        if not permitted:
            continue
        s = socket.socket(family, kind, proto)
        s.settimeout(4)
        try:
            s.connect(address)
            return s
        except OSError as exc:
            last = exc
            s.close()
    raise last


class Access(paramiko.ServerInterface):
    def __init__(self, transport):
        self.transport = transport
        self.key = None
        self.destinations = {}
        self.requests = {}
        self.lock = threading.Lock()
        self.ids = set()

    def get_banner(self):
        return (f"GHOST HWID - una conexion por cuenta. Soporte: {CONTACT}\r\n", "es")

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        try:
            key = ident(username)
        except ValueError:
            return paramiko.AUTH_FAILED
        if not hmac.compare_digest(username.encode(), password.encode()):
            return paramiko.AUTH_FAILED
        with ACTIVE_LOCK:
            # Also prevent a transport from reserving multiple identities.
            if self.key is not None:
                return paramiko.AUTH_FAILED
            if key in ACTIVE or not eligible(get_client(key)):
                return paramiko.AUTH_FAILED
            ACTIVE[key] = self.transport
            self.key = key
        LOG.info("Acceso aceptado cuenta=%s", key[:8])
        return paramiko.AUTH_SUCCESSFUL

    def reserve_channel(self, chanid):
        with self.lock:
            if not self.key or len(self.ids) >= 64 or not eligible(get_client(self.key)):
                return False
            self.ids.add(chanid)
            return True

    def check_channel_request(self, kind, chanid):
        if kind == "session" and self.reserve_channel(chanid):
            with self.lock:
                self.requests[chanid] = threading.Event()
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.reserve_channel(chanid):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        with self.lock:
            self.destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True  # Display-only session. No system terminal or shell is created.

    def check_channel_shell_request(self, channel):
        with self.lock:
            event = self.requests.get(channel.get_id())
        if event:
            event.set()
            return True
        return False

    def check_channel_exec_request(self, channel, command):
        # Some clients ask for a banner via an exec request. Nothing is executed.
        return self.check_channel_shell_request(channel)

    def release_channel(self, chanid):
        with self.lock:
            self.ids.discard(chanid)
            self.destinations.pop(chanid, None)
            self.requests.pop(chanid, None)


def channel_worker(access, channel):
    chanid = channel.get_id()
    upstream = None
    try:
        channel.settimeout(5)
        with access.lock:
            dest = access.destinations.get(chanid)
            event = access.requests.get(chanid)
        if dest is None:
            if not event or not event.wait(10):
                return
            channel.sendall(status_text(access.key).encode())
            # A display session stays open for clients that expect a shell.
            while access.transport.is_active() and not channel.closed:
                if not eligible(get_client(access.key)):
                    break
                ready, _, _ = select.select([channel], [], [], 1)
                if ready:
                    data = channel.recv(1024)
                    if not data:
                        break
                    channel.sendall(status_text(access.key).encode())
            return
        upstream = connect_target(*dest)
        while access.transport.is_active() and not channel.closed:
            ready, _, _ = select.select([channel, upstream], [], [], 1)
            for source in ready:
                data = source.recv(32768)
                if not data:
                    # Preserve the other direction after a half-close.
                    if source is channel:
                        upstream.shutdown(socket.SHUT_WR)
                    else:
                        channel.shutdown_write()
                    pump_tail(access, channel, upstream, source is channel)
                    return
                direction = "up" if source is channel else "down"
                allowed = charge(access.key, len(data), direction)
                if allowed:
                    (upstream if source is channel else channel).sendall(data[:allowed])
                if allowed < len(data):
                    access.transport.close()
                    return
    except (OSError, EOFError, paramiko.SSHException, ValueError):
        pass
    except Exception:
        LOG.exception("Error de canal")
        access.transport.close()
    finally:
        if upstream is not None:
            upstream.close()
        channel.close()
        access.release_channel(chanid)


def pump_tail(access, channel, upstream, client_eof):
    source = upstream if client_eof else channel
    target = channel if client_eof else upstream
    direction = "down" if client_eof else "up"
    while access.transport.is_active() and not channel.closed:
        ready, _, _ = select.select([source], [], [], 1)
        if not ready:
            continue
        data = source.recv(32768)
        if not data:
            return
        allowed = charge(access.key, len(data), direction)
        if allowed:
            target.sendall(data[:allowed])
        if allowed < len(data):
            access.transport.close()
            return


class PrefixSocket:
    def __init__(self, sock, prefix):
        self.sock, self.prefix = sock, prefix

    def recv(self, size):
        if self.prefix:
            data, self.prefix = self.prefix[:size], self.prefix[size:]
            return data
        return self.sock.recv(size)

    def __getattr__(self, key):
        return getattr(self.sock, key)


def prepare_socket(sock):
    """Kira-style HTTP upgrade followed by raw SSH; no WebSocket framing."""
    sock.settimeout(5)
    if not select.select([sock], [], [], 1)[0]:
        return sock  # Client waits for SSH banner.
    data = sock.recv(4096)
    if not data:
        raise EOFError()
    # First TCP packet may contain only part of the SSH greeting.
    while len(data) < 4 and b"SSH-".startswith(data):
        more = sock.recv(4 - len(data))
        if not more:
            raise EOFError()
        data += more
    if data.startswith(b"SSH-"):
        return PrefixSocket(sock, data)
    while b"\r\n\r\n" not in data and b"\n\n" not in data:
        if len(data) > 16384:
            raise ValueError("Cabecera demasiado larga")
        more = sock.recv(4096)
        if not more:
            raise EOFError()
        data += more
    a, b = data.find(b"\r\n\r\n"), data.find(b"\n\n")
    delimiter = b"\n\n" if b >= 0 and (a < 0 or b < a) else b"\r\n\r\n"
    header, _, rest = data.partition(delimiter)
    first = header.splitlines()[0].split()
    if not first or first[0].upper() not in (b"GET", b"CONNECT", b"POST"):
        raise ValueError("Peticion no admitida")
    if b"upgrade: websocket" in header.lower():
        import base64
        match = re.search(rb"(?im)^sec-websocket-key:\s*([^\r\n]+)", header)
        accept = b""
        if match:
            digest = hashlib.sha1(match[1].strip() + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            accept = b"Sec-WebSocket-Accept: " + base64.b64encode(digest) + b"\r\n"
        response = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n" + accept + b"\r\n")
    else:
        response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    sock.sendall(response)
    return PrefixSocket(sock, rest)


def connection(sock, key):
    transport = access = None
    try:
        transport = paramiko.Transport(prepare_socket(sock))
        transport.banner_timeout = 10
        transport.auth_timeout = 20
        transport.add_server_key(key)
        access = Access(transport)
        transport.start_server(server=access)
        deadline = time.monotonic() + 25
        while transport.is_active():
            if not transport.is_authenticated():
                if time.monotonic() > deadline:
                    break
            elif not eligible(get_client(access.key)):
                break
            channel = transport.accept(0.5)
            if channel is not None:
                threading.Thread(target=channel_worker, args=(access, channel), daemon=True).start()
    except (OSError, EOFError, paramiko.SSHException, ValueError):
        pass
    except Exception:
        LOG.exception("Error de conexion")
    finally:
        if transport is not None:
            transport.close()
        sock.close()
        # Keep the slot reserved until the transport has been closed.
        if access and access.key:
            with ACTIVE_LOCK:
                if ACTIVE.get(access.key) is transport:
                    ACTIVE.pop(access.key, None)
            LOG.info("Acceso cerrado cuenta=%s", access.key[:8])
        SLOTS.release()


def serve(host, port):
    import fcntl
    # One process owns reservations; do not launch workers or multiple instances.
    lockfile = (STATE / "server.lock").open("a")
    fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    key = paramiko.RSAKey.from_private_key_file(str(STATE / "host_key"))
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(128)
        LOG.info("Escuchando %s:%s; soporte %s", host, port, CONTACT)
        while True:
            sock, _ = listener.accept()
            if not SLOTS.acquire(blocking=False):
                sock.close()
                continue
            threading.Thread(target=connection, args=(sock, key), daemon=True).start()


def positive(value):
    number = int(value)
    if not 1 <= number <= 3650:
        raise ValueError("Dias: usa un numero de 1 a 3650.")
    return number


def quota_bytes(value):
    from decimal import Decimal
    number = Decimal(str(value))
    if not number.is_finite() or not 0 <= number <= 1_000_000:
        raise ValueError("GB: usa un numero entre 0 y 1000000 (0 = sin limite).")
    return int(number * GB)


def manage(action, hwid=None, name=None, days=None, gb=None):
    if action == "list":
        with db() as c:
            rows = c.execute("SELECT * FROM clients ORDER BY name").fetchall()
        if not rows:
            print("No hay clientes registrados.")
        for row in rows:
            end = dt.datetime.fromtimestamp(row["expires"], dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            used = (row["up"] + row["down"]) / GB
            quota = f"{row['quota']/GB:g}" if row["quota"] else "ilimitado"
            print(f"{row['name']} | {row['id'][:8]} | {'HABILITADO' if eligible(row) else 'BLOQUEADO'} | "
                  f"vence {end} | {used:.3f}/{quota} GB")
        return
    key = ident(hwid)
    with db() as c:
        if action == "add":
            if not name or len(name) > 64 or any(ord(x) < 32 or ord(x) == 127 for x in name):
                raise ValueError("Nombre: de 1 a 64 caracteres, sin caracteres de control.")
            expires = time.time() + positive(days) * 86400
            c.execute("INSERT INTO clients(id,name,expires,quota) VALUES(?,?,?,?)",
                      (key, name, expires, quota_bytes(gb)))
        else:
            row = c.execute("SELECT * FROM clients WHERE id=?", (key,)).fetchone()
            if not row:
                raise ValueError("HWID no registrado.")
            if action == "renew":
                end = max(time.time(), row["expires"]) + positive(days) * 86400
                c.execute("UPDATE clients SET expires=?,enabled=1 WHERE id=?", (end, key))
            elif action in ("enable", "disable"):
                c.execute("UPDATE clients SET enabled=? WHERE id=?", (int(action == "enable"), key))
            elif action == "quota":
                c.execute("UPDATE clients SET quota=? WHERE id=?", (quota_bytes(gb), key))
            elif action == "reset":
                c.execute("UPDATE clients SET up=0,down=0 WHERE id=?", (key,))
    print(status_text(key))


def menu():
    actions = {"1": "add", "2": "list", "3": "status", "4": "renew", "5": "disable",
               "6": "enable", "7": "quota", "8": "reset"}
    while True:
        print("\nGHOST HWID | " + CONTACT)
        print("1 Registrar HWID\n2 Listar clientes\n3 Consultar consumo\n4 Renovar dias\n"
              "5 Suspender\n6 Habilitar\n7 Cambiar cuota GB\n8 Reiniciar consumo\n0 Salir")
        option = input("Opcion: ").strip()
        if option == "0":
            return
        action = actions.get(option)
        if not action:
            continue
        try:
            values = {}
            if action != "list":
                values["hwid"] = input("HWID completo (incluye la h si aparece): ").strip()
            if action == "add":
                values["name"] = input("Nombre del cliente: ").strip()
            if action in ("add", "renew"):
                values["days"] = input("Dias: ").strip()
            if action in ("add", "quota"):
                values["gb"] = input("Cuota total GB (0 = ilimitado): ").strip()
            if action == "reset" and input("Borrar contadores de este cliente? Escribe SI: ") != "SI":
                continue
            manage(action, **values)
        except (ValueError, ArithmeticError, sqlite3.Error) as exc:
            print("No se completo: " + str(exc))


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    p = argparse.ArgumentParser(description="Ghost HWID 0.1.1 — servicio separado de prueba")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("menu")
    sub.add_parser("list")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", default=8081, type=int)
    for action in ("add", "status", "renew", "disable", "enable", "quota", "reset"):
        s = sub.add_parser(action)
        s.add_argument("hwid")
        if action == "add":
            s.add_argument("--name", required=True)
        if action in ("add", "renew"):
            s.add_argument("--days", required=True)
        if action in ("add", "quota"):
            s.add_argument("--gb", required=True)
    args = vars(p.parse_args())
    command = args.pop("command")
    if command == "init":
        init()
        print("Estado inicializado. No se ha creado ningun cliente.")
    elif command == "serve":
        serve(**args)
    elif command == "menu":
        menu()
    else:
        manage(command, **args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, ArithmeticError, sqlite3.Error, OSError) as exc:
        raise SystemExit("Error: " + str(exc))
GHOST_PY_SOURCE

if [[ ${1:-} == '--extract' ]]; then
    [[ $# -eq 2 ]] || { echo 'Uso: bash GhostHWID_instalar.sh --extract DIRECTORIO'; exit 1; }
    mkdir -p -- "$2"
    cp -- "$stage/ghosthwid.py" "$2/ghosthwid.py"
    echo "Codigo extraido en $2/ghosthwid.py. No se instalo ningun servicio."
    exit 0
fi
[[ $# -eq 0 ]] || { echo 'Argumento desconocido. Usa --help.' >&2; exit 1; }
if [[ ${EUID} -ne 0 ]]; then
    echo 'Ejecuta este instalador como root.' >&2
    exit 1
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 22.04 ]]; then
    echo 'Este instalador esta preparado para Ubuntu 22.04.' >&2
    exit 1
fi
for path in /opt/ghosthwid /var/lib/ghosthwid /usr/local/bin/ghosthwid /etc/systemd/system/ghosthwid.service; do
    if [[ -e "$path" || -L "$path" ]]; then
        echo "Ya existe $path. Se detiene para no sobrescribir datos." >&2
        exit 1
    fi
done
if getent passwd ghosthwid >/dev/null; then
    echo 'Ya existe el usuario ghosthwid. No se cambia su configuracion.' >&2
    exit 1
fi
if getent group ghosthwid >/dev/null; then
    echo 'Ya existe el grupo ghosthwid. No se cambia su configuracion.' >&2
    exit 1
fi
python3 - <<'CHECK_PORT'
import socket
with socket.socket() as s:
    try:
        s.bind(('0.0.0.0', 8081))
    except OSError:
        raise SystemExit('El puerto TCP 8081 esta ocupado. No se instala.')
CHECK_PORT

echo 'Instalando dependencia de Ubuntu: python3-paramiko...'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-paramiko
python3 -c 'import paramiko'
python3 -m py_compile "$stage/ghosthwid.py"

groupadd --system ghosthwid
useradd --system --gid ghosthwid --home-dir /var/lib/ghosthwid --shell /usr/sbin/nologin ghosthwid
install -d -m 0755 /opt/ghosthwid
install -m 0644 "$stage/ghosthwid.py" /opt/ghosthwid/ghosthwid.py
install -d -o ghosthwid -g ghosthwid -m 0700 /var/lib/ghosthwid
runuser -u ghosthwid -- /usr/bin/python3 /opt/ghosthwid/ghosthwid.py init

cat > /usr/local/bin/ghosthwid <<'ADMIN_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
    echo 'Ejecuta sudo ghosthwid' >&2
    exit 1
fi
if [[ $# -eq 0 ]]; then
    set -- menu
fi
exec /usr/sbin/runuser -u ghosthwid -- /usr/bin/python3 /opt/ghosthwid/ghosthwid.py "$@"
ADMIN_WRAPPER
chmod 0755 /usr/local/bin/ghosthwid

cat > /etc/systemd/system/ghosthwid.service <<'SYSTEMD_SERVICE'
[Unit]
Description=Ghost HWID - servicio SSH de prueba independiente
After=network.target

[Service]
Type=simple
User=ghosthwid
Group=ghosthwid
WorkingDirectory=/var/lib/ghosthwid
ExecStart=/usr/bin/python3 /opt/ghosthwid/ghosthwid.py serve --host 0.0.0.0 --port 8081
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ghosthwid
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
TasksMax=2048
MemoryMax=768M
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

systemctl daemon-reload
systemctl enable --now ghosthwid.service
sleep 1
if ! systemctl is-active --quiet ghosthwid.service; then
    systemctl disable --now ghosthwid.service || true
    echo 'El servicio no arranco. Kira sigue intacto. Revisa:' >&2
    echo 'journalctl -u ghosthwid -n 40 --no-pager' >&2
    exit 1
fi
echo
echo 'Instalado Ghost HWID 0.1.1 en TCP 8081.'
echo 'No hay clientes creados. Abre el menu con: ghosthwid'
echo 'Soporte mostrado: @GhostProxy_Tech'
echo 'No se modificaron Kira, OpenSSH, PAM ni las reglas del firewall.'
echo 'Si existe firewall en el VPS o proveedor, TCP 8081 debe estar permitido para la prueba.'
echo 'Para apagar solo este servicio: systemctl disable --now ghosthwid'

exit 0

# DOCUMENTACION Y RESULTADOS DE PRUEBA

# # Ghost HWID 0.1.1 — prueba con HTTP Custom
# 
# Preparado para Ubuntu 22.04, con contacto **@GhostProxy_Tech**.
# Es un servicio nuevo y experimental: todavía no se ha probado en tu VPS ni con
# tu versión de HTTP Custom. No es una actualización oficial de Kira.
# 
# ## Qué hace
# 
# - Administrador `ghosthwid` con menú: registrar HWID, listar, consultar consumo,
#   renovar, suspender, habilitar, cambiar cuota y reiniciar contadores.
# - Autenticación SSH por contraseña: usuario = HWID y contraseña = mismo HWID,
#   exactamente como los envía la opción de login por HWID de HTTP Custom.
# - Admite HWID antiguos de 32 caracteres hexadecimales y nuevos con prefijo h
#   seguido de 31 o 32 caracteres hexadecimales, respetando mayúsculas/minúsculas.
#   El prefijo h forma parte de la credencial: no se elimina. El ID HC2- es distinto. No genera una cuenta Linux por cada HWID.
# - Una conexión SSH autenticada simultánea por cuenta, con reserva exclusiva
#   durante la autenticación. Dentro de ella admite múltiples canales TCP para que
#   funcionen las aplicaciones del teléfono. Una conexión no significa una persona
#   ni impide compartir internet desde un teléfono.
# - Fecha de vencimiento y suspensión: corta las conexiones activas en el siguiente
#   ciclo de control (aproximadamente 0,5 segundos; la carga del servidor puede
#   aumentar ese tiempo).
# - Cuota de subida + bajada, con contadores persistentes en SQLite. Llegar a la
#   cuota bloquea nuevas conexiones y cierra la actual.
# - Mensaje de autenticación SSH con Telegram. Si el cliente solicita una sesión
#   de texto, muestra vencimiento, consumo y saldo; no abre un shell del sistema.
# 
# ## Arquitectura y diferencias con Kira
# 
# El servicio termina SSH por su cuenta usando Paramiko. No redirige la
# autenticación hacia el OpenSSH del puerto 22: así puede identificar cada HWID,
# limitar su conexión y contar sus canales sin cambiar PAM ni crear cuentas Linux.
# Esto cambia el motor SSH para este perfil, por lo que su rendimiento y
# compatibilidad deben evaluarse antes de usarlo con clientes.
# 
# Usa TCP **8081**, independiente de Kira (80/8080) y del SSH de administración
# (22). Admite SSH directo y una petición HTTP con respuesta 101 o 200, seguida
# de SSH sin tramas WebSocket, como el método de payload observado en el proxy.
# No es un servidor WebSocket completo para clientes que usan tramas WebSocket.
# No se ha implementado el manejo de todos los payloads partidos, dobles o de
# otras variantes de Kira. Empieza con el payload sencillo de la sección de prueba.
# 
# No modifica archivos de Kira, OpenSSH, PAM, banners existentes ni firewall.
# No incorpora por ahora una ruta en el puerto 80: esa integración requiere una
# prueba posterior y coordinar el reinicio del puente de Kira.
# 
# ## Instalación, paso a paso
# 
# 1. Copia **GhostHWID_instalar.sh** a `/root/GhostHWID_instalar.sh` en el VPS.
#    Puedes usar la función SFTP de tu cliente SSH. El archivo descargado en el
#    teléfono no llega automáticamente al servidor.
# 2. En la terminal del VPS como root, ejecuta:
# 
#    ```bash
#    bash /root/GhostHWID_instalar.sh
#    ```
# 
#    El instalador verifica Ubuntu 22.04 y puerto 8081 libre. Instala
#    `python3-paramiko` desde los repositorios configurados de Ubuntu, crea el
#    usuario de servicio `ghosthwid` sin login, y habilita el servicio systemd.
#    No reemplaza una instalación previa: se detiene si encuentra sus rutas.
# 3. Abre el menú:
# 
#    ```bash
#    ghosthwid
#    ```
# 
# 4. Elige **1 Registrar HWID**, pega tu HWID completo, incluyendo la h si aparece, y escribe un nombre de
#    prueba, los días y la cuota en GB. Usa tu propia cuenta como primer ensayo.
#    El plazo empieza al registrar el cliente, no en su primera conexión.
#    No se registra automáticamente ningún HWID durante la instalación.
# 
# La base de datos y la clave SSH están en `/var/lib/ghosthwid`, accesible solo por
# root y el usuario de servicio. El programa está en `/opt/ghosthwid`.
# 
# ## Prueba en HTTP Custom
# 
# Antes de exportar un archivo común, prueba manualmente con tu teléfono:
# 
# 1. Guarda una copia de tu configuración actual desde la aplicación.
# 2. Usa el mismo dominio o IP real de tu VPS, cambiando el puerto a **8081**.
# 3. Para comprobar la autenticación, el usuario y la contraseña serán ambos el
#    HWID exacto que acabas de registrar. No uses las cuentas de Kira para este
#    nuevo servicio.
# 4. Conserva el modo de SSH con payload; usa un payload sencillo como el de abajo.
#    Desactiva SSL para esta primera prueba, porque este puerto no ofrece TLS
#    externo (el propio SSH sí cifra la conexión).
# 5. Conecta y comprueba navegación. Si falla, comparte el LOG de la app ocultando
#    los datos privados. No cambies el puerto de administración 22.
# 
# Ejemplo de payload, reemplazando `TU_DOMINIO` por tu dominio/IP:
# 
# ```text
# GET / HTTP/1.1[crlf]Host: TU_DOMINIO[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
# ```
# 
# Es un ejemplo para alcanzar un servicio de tu VPS por una conexión a Internet
# que permita ese puerto. No garantiza que una red móvil permita conectar con él.
# Si existe firewall del VPS o del proveedor, debe permitir TCP 8081. El instalador
# no altera esas reglas automáticamente.
# 
# Después de validar el acceso manual, activa **Login con HWID** al guardar/exportar
# la configuración en HTTP Custom, si tu versión lo ofrece. Ese es el perfil común
# que se reparte. No actives un bloqueo del archivo a un único HWID si quieres
# entregarlo a todos: la autorización individual en este diseño vive en el servicio.
# El archivo nativo `.hc` se exporta desde la app; este paquete no contiene un `.hc`
# ya generado ni un archivo `.hwid` para importar.
# 
# ## Consumo y Telegram dentro de HTTP Custom
# 
# **No se garantiza una pantalla de saldo en vivo dentro de la aplicación.**
# El servidor ofrece el contacto en su banner SSH y el saldo en una sesión de
# texto si el cliente la solicita. Cómo y dónde lo muestra HTTP Custom depende de
# la versión y sus opciones. Un banner de autenticación se envía antes de conocer
# el usuario y no puede contener un saldo individual fiable en este diseño.
# Se debe probar la visualización con tu app; la pantalla del administrador sí
# consulta el consumo acumulado real que registra este servicio.
# 
# No se modifica la interfaz, el pie de pantalla ni el código de HTTP Custom.
# La inclusión del contacto en un banner no garantiza un botón o enlace pulsable.
# 
# ## Qué significan los GB
# 
# - **1 GB = 1.000.000.000 bytes**. Cuota = subida + bajada.
# - Se cuentan los bytes recibidos en los canales TCP para reenviarlos: subida
#   desde el cliente y bajada desde el destino. Se incluyen aunque después falle
#   su entrega al otro extremo; no es una factura de bytes efectivamente recibidos.
# - No se cuenta la sobrecarga de IP/TCP/SSH ni la de los mensajes del menú.
#   No coincidirá necesariamente con la factura de transferencia del VPS ni con
#   el indicador de tráfico de la aplicación.
# - En un paquete que cruza el límite, solo se carga hasta el saldo disponible;
#   el resto se descarta y se cierra la conexión. Los contadores no superan la cuota.
# - `0` significa sin límite, no cero bytes disponibles.
# - Renovar días **no** reinicia el consumo. Para iniciar un período con saldo
#   nuevo, usa explícitamente **Reiniciar consumo**, además de renovar si procede.
# - Cambiar la cuota cambia el tope total, no suma GB automáticamente al saldo.
# - Los contadores persisten entre reinicios normales. No se promete protección
#   frente a pérdida de disco, manipulación por root o fallos del almacenamiento.
# 
# ## UDP y límites de esta versión
# 
# El servicio admite canales TCP hacia destinos públicos y, en loopback,
# exclusivamente los puertos badvpn-udpgw observados: 7100, 7200, 7300 y 7302.
# Esto permite probar UDP encapsulado a través de badvpn si tu cliente lo usa.
# No reemplaza ni administra el protocolo independiente UDP Custom.
# El tráfico SSH que encapsula badvpn cuenta para la cuota; su sobrecarga interna
# también forma parte de esos bytes.
# 
# No permite shell del sistema, SFTP, acceso a redes privadas del VPS ni conexiones
# a servicios locales arbitrarios. No se incorporan límites de velocidad, bots,
# panel web ni integración automática de las cuentas existentes de Kira.
# 
# No es una prueba criptográfica del dispositivo: si alguien copia el HWID puede
# intentar autenticarse con él; solo se permite una conexión simultánea. Quien
# conozca ese dato podría ocupar el único acceso del cliente. El HWID no sustituye
# credenciales secretas independientes en un sistema de autenticación más fuerte.
# 
# El servidor usa hilos y SQLite. Hay topes de 100 conexiones totales y 64 canales
# por conexión; no son una garantía de capacidad. No se ha hecho una prueba de
# carga en tu VPS de dos núcleos. Empieza con un teléfono; usa pocos clientes de
# prueba y mide CPU, memoria y estabilidad antes de ampliarlo.
# 
# ## Consultas y recuperación
# 
# Menú:
# 
# ```bash
# ghosthwid
# ```
# 
# Estado y registro del servicio:
# 
# ```bash
# systemctl status ghosthwid --no-pager
# journalctl -u ghosthwid -n 40 --no-pager
# ```
# 
# Apagar la prueba conservando sus datos:
# 
# ```bash
# systemctl disable --now ghosthwid
# ```
# 
# Volver a iniciarla:
# 
# ```bash
# systemctl enable --now ghosthwid
# ```
# 
# Estos comandos solo afectan al servicio nuevo. No reinician Kira ni OpenSSH.
# 
# Para revisar el código sin instalarlo (en el VPS como root):
# 
# ```bash
# bash /root/GhostHWID_instalar.sh --extract /root/ghosthwid_revision
# ```
# 
# El ZIP contiene el código legible, los tests y esta guía. La instalación real
# con systemd, la versión de Paramiko de Ubuntu y la app Android están pendientes
# de prueba en tu entorno. Las pruebas incluidas usan Paramiko 5.1.0 en el entorno
# de desarrollo, no una instalación remota en tu servidor.

# Ghost HWID 0.1.1 — verificacion local
# 
# Python: 3.12.14
# Paramiko: 5.1.0
# 
# 14 pruebas de integracion: OK
# - HWID y entradas invalidas
# - Formatos nuevos h+31 y h+32 hex: autenticacion real y rechazo de duplicado
# - Concurrencia: un ganador en ocho intentos simultaneos
# - Contadores de subida y bajada con TCP echo y cierre parcial
# - Suspension de una conexion activa
# - Vencimiento y renovacion
# - Peticion HTTP 101 seguida de autenticacion SSH
# - Rechazo de un segundo acceso y reconexion tras desconectar
# - Rechazo de destinos privados y metadatos
# - Cobro atomico sin superar la cuota
# - Corte por cuota y persistencia de contadores
# - Listener TCP real, clave SSH persistente y bloqueo de segunda instancia
# - Mensaje de consumo y contacto; sin ejecucion de comandos del cliente
# - Dos cuentas distintas conectadas simultaneamente
# 
# Instalador: sintaxis Bash verificada; extraccion sin instalacion verificada.
# Pendiente: instalacion en Ubuntu 22.04 con systemd y paquete python3-paramiko
# de Ubuntu, cliente HTTP Custom Android real, firewall, badvpn y prueba de carga.
# No se ha accedido ni se ha instalado nada en el VPS del usuario.
# 
# Actualizador: conversion exacta de la version anterior, idempotencia y rechazo de codigo inesperado: OK.
