# SPDX-License-Identifier: LGPL-2.1-or-later
"""Round-trip Wine's reported C volume into its existing, prefix-local C mapping."""
import os
from pathlib import Path
import subprocess
import uuid


def decode_volume(data):
    if len(data) > 256:
        raise ValueError('Oversized C volume query')
    text = data.decode('ascii')
    lines = text.splitlines()
    header = 'NNDSK_C_VOLUME_V1 '
    if len(lines) != 1 or not lines[0].startswith(header):
        raise ValueError('Malformed C volume query')
    volume = lines[0][len(header):]
    if len(volume) != 49 or not volume.startswith('\\\\?\\Volume{') or not volume.endswith('}\\'):
        raise ValueError('Not an absolute volume GUID')
    guid = volume[11:47]
    if str(uuid.UUID(guid)) != guid.lower():
        raise ValueError('Noncanonical volume GUID')
    return 'volume{' + guid.lower() + '}'


def install_alias(prefix, name):
    # Do not adopt a custom C drive or a redirected dosdevices directory. This
    # creates one additional name for exactly the C volume that Wine reported.
    prefix = Path(prefix).resolve(strict=True)
    devices = prefix / 'dosdevices'
    drive = prefix / 'drive_c'
    mapping = devices / 'c:'
    if devices.is_symlink() or not devices.is_dir() or drive.is_symlink() or not drive.is_dir():
        raise RuntimeError('C volume requires normal prefix-local drive_c/dosdevices directories')
    if not mapping.is_symlink() or mapping.resolve(strict=True) != drive:
        raise RuntimeError('C volume mapping is not the prefix-local drive_c')
    # Validate the name independently of the native producer, even in tests.
    if not name.startswith('volume{') or not name.endswith('}') or len(name) != 44:
        raise ValueError('Invalid C alias name')
    if str(uuid.UUID(name[7:-1])) != name[7:-1]:
        raise ValueError('Invalid C alias GUID')
    alias = devices / name
    try:
        os.symlink('../drive_c', alias, target_is_directory=True)
    except FileExistsError:
        pass
    if not alias.is_symlink() or alias.resolve(strict=True) != drive or mapping.resolve(strict=True) != drive:
        raise RuntimeError('Existing/conflicting C volume alias preserved; refusing to overwrite it')
    return alias


def ensure_c_volume_alias(env, wine, helper, log):
    prefix = env.get('WINEPREFIX')
    if not prefix or not Path(prefix).is_absolute():
        raise RuntimeError('C volume query requires an explicit absolute WINEPREFIX')
    completed = subprocess.run([wine, helper], env=env, stdout=subprocess.PIPE,
                               stderr=log, timeout=30, check=True)
    return install_alias(prefix, decode_volume(completed.stdout))
