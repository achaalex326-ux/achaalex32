#!/usr/bin/env python3
"""Route GET /hwid on Kira's existing port 80 bridge to Ghost HWID.

Requires a dedicated systemd unit running the observed ws_server.py directly.
Backs up that script; restarts that unit only; rolls back on a failed probe.
No firewall changes, account changes, or OpenSSH restarts.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import time

SCRIPT = Path('/usr/local/bin/ws_server.py')
STATE = Path('/var/lib/ghosthwid-route')
MARKER = '# GHOSTHWID_PORT80_BEGIN'
BLOCK = '''    # GHOSTHWID_PORT80_BEGIN
    _gh_first = pedido.split(b"\\n", 1)[0].split()
    if len(_gh_first) >= 2 and _gh_first[0].upper() in (b"GET", b"POST", b"HEAD"):
        _gh_path = _gh_first[1].partition(b"?")[0]
        if _gh_path == b"/hwid":
            return ('127.0.0.1', 8081)
    # GHOSTHWID_PORT80_END
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def root_owned(path):
    return path.stat().st_uid == 0


def patched(source):
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'destino']
    if len(functions) != 1 or [a.arg for a in functions[0].args.args] != ['pedido']:
        raise ValueError('No se encontro la funcion destino(pedido) esperada. No se cambia el puente.')
    if MARKER in source:
        if BLOCK not in source:
            raise ValueError('Hay una integracion previa diferente. No se sobrescribe.')
        return source
    if source.count('def destino(pedido):\n') != 1:
        raise ValueError('La estructura del puente es diferente. No se modifica.')
    if '/hwid' in source:
        raise ValueError('El puente ya contiene una ruta /hwid distinta. Necesita revision.')
    if not any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id == 'TARGET'
               for n in ast.walk(functions[0])):
        raise ValueError('No se reconoce el destino original de Kira. No se modifica.')
    result = source.replace('def destino(pedido):\n', 'def destino(pedido):\n' + BLOCK, 1)
    compile(result, str(SCRIPT), 'exec')
    return result


def run(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=25, check=check)


def dedicated_unit(properties):
    """Accept a direct Python command, never a general Kira/login/shell unit."""
    match = re.search(r'argv\[\]=(.*?);', properties)
    if not match:
        return False
    try:
        args = shlex.split(match[1].strip())
    except ValueError:
        return False
    if not args or not re.fullmatch(r'python(?:3(?:\.\d+)?)?', Path(args[0]).name):
        return False
    args = args[1:]
    if args and args[0] in ('-u', '-B'):
        args = args[1:]
    return len(args) == 1 and args[0] == str(SCRIPT)


def find_unit(requested=None):
    candidates = set()
    if requested:
        if not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', requested):
            raise ValueError('Nombre de servicio no valido.')
        candidates.add(requested)
    else:
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if os.fsencode(SCRIPT) not in args:
                    continue
                for line in (proc / 'cgroup').read_text().splitlines():
                    for component in line.split(':', 2)[-1].split('/'):
                        if component.endswith('.service'):
                            candidates.add(component)
            except (OSError, ProcessLookupError):
                pass
    verified = []
    for name in sorted(candidates):
        if name in ('ssh.service', 'ghosthwid.service') or name.startswith('ssh@'):
            continue
        props = run(['systemctl', 'show', name, '--property=ExecStart', '--value'], check=False)
        if props.returncode == 0 and dedicated_unit(props.stdout):
            verified.append(name)
    if len(verified) != 1:
        found = ', '.join(sorted(candidates)) or 'ninguno'
        raise ValueError('No pude identificar un servicio exclusivo del puente WebSocket. '
                         'No se modifico nada. Servicios asociados: ' + found + '. '
                         'Comparte este mensaje para indicar el reinicio correcto.')
    return verified[0]


def ssh_key(sock):
    import paramiko
    transport = paramiko.Transport(sock)
    transport.banner_timeout = 6
    try:
        transport.start_client(timeout=8)
        return transport.get_remote_server_key().asbytes()
    finally:
        transport.close()
        sock.close()


def gateway_key():
    return ssh_key(socket.create_connection(('127.0.0.1', 8081), timeout=5))


def route_key():
    s = socket.create_connection(('127.0.0.1', 80), timeout=5)
    s.settimeout(8)
    try:
        key = base64.b64encode(b'ghosthwid-test-01')
        s.sendall(b'GET /hwid HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
                  b'Connection: Upgrade\r\nSec-WebSocket-Key: ' + key +
                  b'\r\nSec-WebSocket-Version: 13\r\n\r\n')
        header = bytearray()
        while not header.endswith(b'\r\n\r\n'):
            data = s.recv(1)
            if not data or len(header) >= 16384:
                raise ValueError('El puerto 80 no devolvio una cabecera HTTP valida.')
            header.extend(data)
        if not bytes(header).split(b'\r\n', 1)[0].startswith(b'HTTP/1.1 101 '):
            raise ValueError('El puente del puerto 80 no devolvio la respuesta 101 esperada.')
        return ssh_key(s)
    except BaseException:
        s.close()
        raise


def verify_route(expected):
    last = None
    for _ in range(3):
        try:
            if route_key() != expected:
                raise ValueError('La ruta /hwid no llega al servicio Ghost HWID.')
            return
        except (OSError, EOFError, ValueError) as exc:
            last = exc
            time.sleep(0.3)
    raise ValueError('Fallo la comprobacion del puerto 80: ' + str(last))


def atomic_write(path, data, info):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.ghost-route-', delete=False) as f:
            temporary = Path(f.name)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.chown(temporary, info.st_uid, info.st_gid)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def rollback():
    record = json.loads((STATE / 'current.json').read_text())
    current = SCRIPT.read_bytes()
    if digest(current) != record['patched_sha256']:
        raise ValueError('El puente cambio despues de integrar la ruta. No se sobrescribe.')
    backup = STATE / record['backup']
    data = backup.read_bytes()
    if digest(data) != record['original_sha256']:
        raise ValueError('La copia de seguridad no coincide. No se modifica el puente.')
    unit = find_unit(record['unit'])
    atomic_write(SCRIPT, data, SCRIPT.stat())
    run(['systemctl', 'restart', unit])
    run(['systemctl', 'is-active', '--quiet', unit])
    (STATE / 'current.json').unlink()
    print('Ruta /hwid retirada; restaurado el puente anterior. Clientes y consumo conservados.')


def main():
    parser = argparse.ArgumentParser(description='Integrar Ghost HWID en el puerto 80 de Kira.')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--restore', action='store_true')
    parser.add_argument('--unit', help='Servicio systemd exclusivo del puente, si no se detecta automaticamente.')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Ejecuta el integrador como root.')
    os.umask(0o077)
    if args.restore:
        rollback()
        return
    if SCRIPT.is_symlink() or not SCRIPT.is_file():
        raise ValueError('No se encontro el archivo normal /usr/local/bin/ws_server.py.')
    before = SCRIPT.read_bytes()
    after = patched(before.decode()).encode()
    unit = find_unit(args.unit)
    run(['systemctl', 'is-active', '--quiet', 'ghosthwid.service'])
    expected = gateway_key()
    print('Puente identificado:', unit)
    print('Servicio Ghost HWID en 127.0.0.1:8081: responde SSH.')
    if args.check:
        print('Revision completada. No se modifico ni reinicio nada.')
        return
    if after == before:
        verify_route(expected)
        print('La ruta /hwid ya funciona por el puerto 80.')
        return
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or not root_owned(STATE):
        raise ValueError('El directorio de respaldo no pertenece a root. No se modifica nada.')
    if (STATE / 'current.json').exists():
        raise ValueError('Existe un respaldo de otra integracion. Necesita revision.')
    name = 'ws_server.py.' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.bak'
    backup = STATE / name
    backup.write_bytes(before)
    record = {'backup': name, 'unit': unit, 'original_sha256': digest(before), 'patched_sha256': digest(after)}
    (STATE / 'current.json').write_text(json.dumps(record, indent=2))
    info = SCRIPT.stat()
    print('Se reinicia solo el puente del puerto 80; sus conexiones actuales se interrumpiran.')
    try:
        atomic_write(SCRIPT, after, info)
        run(['systemctl', 'restart', unit])
        run(['systemctl', 'is-active', '--quiet', unit])
        verify_route(expected)
    except BaseException:
        atomic_write(SCRIPT, before, info)
        restarted = run(['systemctl', 'restart', unit], check=False)
        healthy = run(['systemctl', 'is-active', '--quiet', unit], check=False)
        if restarted.returncode == 0 and healthy.returncode == 0:
            (STATE / 'current.json').unlink(missing_ok=True)
            print('La prueba fallo; el archivo anterior fue restaurado y el puente esta activo.')
        else:
            print('El archivo anterior fue restaurado, pero hay que revisar el servicio:', unit)
        raise
    print('LISTO: puerto 80 + payload GET /hwid -> Ghost HWID.')
    print('Las demas rutas conservan su destino anterior; las cuentas no fueron modificadas.')
    print('Respaldo:', backup)
    print('Para revertir: python3 /root/GhostHWID_puerto80.py --restore')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('No se completo la integracion: ' + str(error))
