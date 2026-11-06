#!/usr/bin/env python3
"""Fix only Ghost HWID's known old validation. Does not edit Kira or its DB."""
import datetime
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

OLD_PATTERN = 'r"[0-9a-fA-F]{32}"'
NEW_PATTERN = 'r"(?:[0-9a-fA-F]{32}|h[0-9a-fA-F]{31,32})"'
OLD_ERROR = 'El HWID debe tener exactamente 32 caracteres hexadecimales.'
NEW_ERROR = 'HWID no valido: copia el ID del dispositivo completo, incluida la h si aparece. No uses el ID de acceso HC2-.'
OLD_PROMPT = 'HWID completo (32 caracteres): '
NEW_PROMPT = 'HWID completo (incluye la h si aparece): '


def patched(text):
    changes = [(OLD_PATTERN, NEW_PATTERN), (OLD_ERROR, NEW_ERROR),
               (OLD_PROMPT, NEW_PROMPT)]
    if all(new in text and old not in text for old, new in changes):
        return text
    if any(text.count(old) != 1 for old, new in changes):
        raise ValueError('El archivo no coincide con la version esperada. No se modifico.')
    for old, new in changes:
        text = text.replace(old, new, 1)
    text = text.replace('Ghost HWID 0.1:', 'Ghost HWID 0.1.1:')
    text = text.replace('Ghost HWID 0.1 —', 'Ghost HWID 0.1.1 —')
    compile(text, 'ghosthwid.py', 'exec')
    return text


def main():
    if os.geteuid() != 0:
        raise SystemExit('Ejecuta esta actualizacion como root.')
    target = Path('/opt/ghosthwid/ghosthwid.py')
    if target.is_symlink() or not target.is_file():
        raise SystemExit('No se encontro una instalacion normal de Ghost HWID. No se cambio nada.')
    before = target.read_text()
    after = patched(before)
    if after == before:
        print('El formato nuevo ya esta habilitado. Abre el menu con: ghosthwid')
        return
    backup = target.with_name('ghosthwid.py.bak-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    shutil.copy2(target, backup)
    info = target.stat()
    temporary = None
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'ghosthwid.service']).returncode == 0
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, prefix='.hwid-update-', delete=False) as f:
            temporary = Path(f.name)
            f.write(after)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.chown(temporary, info.st_uid, info.st_gid)
        os.replace(temporary, target)
        temporary = None
        if active:
            subprocess.run(['systemctl', 'restart', 'ghosthwid.service'], check=True)
            subprocess.run(['systemctl', 'is-active', '--quiet', 'ghosthwid.service'], check=True)
    except Exception:
        shutil.copy2(backup, target)
        if active:
            subprocess.run(['systemctl', 'restart', 'ghosthwid.service'], check=False)
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print('Actualizado: acepta HWID antiguo y nuevo con h. Se conservaron clientes, dias y consumo.')
    print('Copia de seguridad:', backup)
    print('Abre el menu con: ghosthwid')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('No se completo la actualizacion: ' + str(error))
