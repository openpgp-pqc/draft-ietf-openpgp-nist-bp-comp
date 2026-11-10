#!/usr/bin/env python3
"""Check KEM metadata using hashlib and Python cryptography AES key unwrap.

Parses only the fixed public test-vector packet layout, deliberately failing on
other layouts. Sequoia performs the full packet and signature verification.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap


def packets(path):
    lines = path.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('-----BEGIN '))
    start = lines.index('', start) + 1
    data = base64.b64decode(''.join(line for line in lines[start:]
                                  if line and not line.startswith(('=', '-----'))), validate=True)
    offset = 0
    while offset < len(data):
        header = data[offset]
        assert header & 0xC0 == 0xC0, 'expected new-format packet header'
        tag = header & 63
        size = data[offset + 1]
        offset += 2
        if size == 255:
            size = int.from_bytes(data[offset:offset + 4], 'big')
            offset += 4
        elif size >= 224:
            # The encrypted payload may use partial lengths; it is not parsed here.
            assert tag == 18, 'unexpected partial packet'
            return
        elif size >= 192:
            size = (size - 192) * 256 + data[offset] + 192
            offset += 1
        assert offset + size <= len(data), 'truncated packet'
        yield tag, data[offset:offset + size]
        offset += size


def check(directory, primary, sub, point_length, share_length, mlkem_ct_length):
    metadata = json.loads((directory / f'metadata-alg{primary}.json').read_text())
    names = {37: 'MLKEM768_ECDH_NISTP384', 38: 'MLKEM1024_ECDH_NISTP521',
             39: 'MLKEM768_ECDH_BrainpoolP384', 40: 'MLKEM1024_ECDH_BrainpoolP512'}
    assert metadata['pkAlgorithm'] == names[sub], 'metadata algorithm mismatch'
    public = [body for tag, body in packets(directory / f'pubkey-primary{primary}-sub{sub}.asc')
              if tag == 14]
    assert len(public) == 1, 'expected one public subkey'
    public = public[0]
    assert public[0] == 6 and public[5] == sub, 'wrong public subkey'
    assert int.from_bytes(public[6:10], 'big') == len(public) - 10
    fingerprint = hashlib.sha256(b'\x9b' + len(public).to_bytes(4, 'big') + public).hexdigest().upper()
    assert fingerprint == metadata['recipient'], 'metadata recipient mismatch'
    pkesks = [body for tag, body in packets(directory / f'encrypted-alg{sub}_signed-alg{primary}.asc')
              if tag == 1]
    assert len(pkesks) == 1, 'expected one PKESK'
    pkesk = pkesks[0]
    assert pkesk[:3] == bytes([6, 33, 6]), 'wrong PKESK header'
    assert pkesk[3:35].hex().upper() == fingerprint and pkesk[35] == sub
    ciphertext = pkesk[36:36 + point_length]
    wrapped_offset = 36 + point_length + mlkem_ct_length
    assert pkesk[wrapped_offset] == 40 and len(pkesk) == wrapped_offset + 41
    wrapped = pkesk[wrapped_offset + 1:]
    mlkem = bytes.fromhex(metadata['mlkemKeyShare'])
    ecdh = bytes.fromhex(metadata['ecdhKeyShare'])
    assert len(mlkem) == 32 and len(ecdh) == share_length, 'wrong share length'
    kek = hashlib.sha3_256(mlkem + ecdh + ciphertext + public[10:10 + point_length]
                          + bytes([sub]) + b'OpenPGPCompositeKDFv1\x15').digest()
    assert kek.hex().upper() == metadata['multiKeyCombine'], 'combiner mismatch'
    session = aes_key_unwrap(kek, wrapped)
    assert len(session) == 32 and session.hex().upper() == metadata['sessionKey'], 'unwrap mismatch'
    print(f'suite {primary}/{sub}: recipient, share lengths, SHA3 combiner, AES unwrap OK')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vector_dir', type=Path)
    args = parser.parse_args()
    for suite in [(41, 37, 97, 48, 1088), (42, 38, 133, 66, 1568),
                  (43, 39, 97, 48, 1088), (44, 40, 129, 64, 1568)]:
        check(args.vector_dir, *suite)


if __name__ == '__main__':
    main()
