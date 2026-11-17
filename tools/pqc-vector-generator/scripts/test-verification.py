#!/usr/bin/env python3
"""Regression checks for the vector verifier: pass the built generator path."""
import base64
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

GENERATOR = str(Path(sys.argv.pop(1)).resolve())
ROOT = Path(__file__).resolve().parents[3]
DRAFT = ROOT / 'draft-ietf-openpgp-nist-bp-comp.md'


def certificate_packets(path):
    """Read complete new-format packets from these fixed armored certificates."""
    lines = path.read_text().splitlines()
    start = lines.index('') + 1
    data = base64.b64decode(''.join(line for line in lines[start:]
                                   if not line.startswith(('=', '-----'))), validate=True)
    result = []
    offset = 0
    while offset < len(data):
        start = offset
        header, length = data[offset:offset + 2]
        assert header & 0xc0 == 0xc0
        offset += 2
        if 192 <= length < 224:
            length = (length - 192) * 256 + data[offset] + 192
            offset += 1
        elif length == 255:
            length = int.from_bytes(data[offset:offset + 4], 'big')
            offset += 4
        else:
            assert length < 192, 'partial lengths not used in these certificates'
        offset += length
        assert offset <= len(data)
        result.append((header & 63, data[start:offset]))
    return result


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='pqc-verify-test-')
        self.addCleanup(self.work.cleanup)
        self.directory = Path(self.work.name) / 'vectors'
        shutil.copytree(ROOT / 'test-vectors', self.directory)
        self.draft = Path(self.work.name) / 'draft.md'
        self.text = DRAFT.read_text()
        self.draft.write_text(self.text)

    def verify(self, expected_error=None):
        result = subprocess.run([GENERATOR, 'verify', '--output', str(self.directory),
                                 '--draft', str(self.draft)], capture_output=True, text=True)
        if expected_error is None:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected_error, result.stderr)

    def test_published_set(self):
        self.verify()

    def test_weak_certificate_self_signatures(self):
        fixtures = Path(__file__).with_name('fixtures')
        for kind in ['pubkey', 'seckey']:
            name = f'{kind}-primary41-sub37.asc'
            path = self.directory / name
            original = path.read_bytes()
            with self.subTest(kind=kind):
                shutil.copyfile(fixtures / ('weak-' + name), path)
                self.verify('certificate signature digest below 384 bits')
            path.write_bytes(original)

    def test_certificate_digest_statements(self):
        pattern = r'All self-signatures use (SHA2-384|SHA3-512) as their hash algorithm\.'
        matches = list(re.finditer(pattern, self.text))
        self.assertEqual([m.group(1) for m in matches],
                         ['SHA2-384', 'SHA3-512', 'SHA2-384', 'SHA3-512'])
        for occurrence, match in enumerate(matches):
            for digest in [None, 'SHA3-256',
                           'SHA3-512' if match.group(1) == 'SHA2-384' else 'SHA2-384']:
                replacement = ('' if digest is None else
                               f'All self-signatures use {digest} as their hash algorithm.')
                with self.subTest(suite=occurrence + 41, replacement=replacement):
                    self.draft.write_text(self.text[:match.start()] + replacement +
                                          self.text[match.end():])
                    self.verify('certificate digest statement missing or incorrect')

    def test_refresh_preserves_keys_and_existing_messages(self):
        originals = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        packets = {p.name: certificate_packets(p) for p in self.directory.glob('*key-*.asc')}
        result = subprocess.run([GENERATOR, 'generate-keys', '--suite', '41',
            '--suite', '42', '--suite', '43', '--suite', '44',
            '--output', str(self.directory), '--force', '--reuse-keys'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, original in originals.items():
            path = self.directory / name
            if name in packets:
                # Every non-signature packet, including complete secret key
                # packets, must survive the refresh exactly.
                self.assertEqual([p for p in packets[name] if p[0] != 2],
                                 [p for p in certificate_packets(path) if p[0] != 2])
            else:
                self.assertEqual(path.read_bytes(), original, name)
        # Draft fingerprints and pre-existing message signatures must still verify.
        self.verify()

    def test_message_generation_for_all_suites(self):
        # Exercise the SignatureBuilder/one-pass serialization path for both
        # hash families. Fresh encryption invalidates the copied metadata.
        for path in self.directory.glob('metadata-alg*.json'):
            path.unlink()
        for command in ['generate-message', 'verify']:
            arguments = [GENERATOR, command, '--output', str(self.directory)]
            if command == 'generate-message':
                arguments.append('--force')
            result = subprocess.run(arguments, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_digest_statement_is_required_in_its_own_section(self):
        for number in range(1, 5):
            marker = f'### Transferable Secret Key {{#test-vector-{number}-sec}}'
            before, section = self.text.split(marker, 1)
            end = section.find('\n## Sample ')
            if end == -1:
                end = section.index('\n# Acknowledgments')
            section, after = section[:end], section[end:]
            digest = 'SHA2-384' if number in (1, 3) else 'SHA3-512'
            statement = f'The signature uses {digest} as its hash algorithm.'
            self.assertEqual(section.count(statement), 2)
            for occurrence in range(2):
                for replacement in ['', statement.replace(digest, 'SHA2-256')]:
                    with self.subTest(suite=number + 40, occurrence=occurrence, replacement=replacement):
                        parts = section.split(statement)
                        altered = (parts[0] + replacement + parts[1] + statement + parts[2]
                                   if occurrence == 0 else
                                   parts[0] + statement + parts[1] + replacement + parts[2])
                        self.draft.write_text(before + marker + altered + after)
                        self.verify('digest statement missing or incorrect')

    def test_draft_fingerprints_and_kem_values(self):
        for primary in range(41, 45):
            metadata = json.loads((self.directory / f'metadata-alg{primary}.json').read_text())
            for field in ['recipient', 'mlkemKeyShare', 'ecdhKeyShare', 'multiKeyCombine', 'sessionKey']:
                with self.subTest(suite=primary, field=field):
                    value = metadata[field]
                    self.assertIn(value, self.text)
                    replacement = ('0' if value[0] != '0' else '1') + value[1:]
                    self.draft.write_text(self.text.replace(value, replacement))
                    self.verify('mismatch')

    def test_primary_fingerprints(self):
        values = re.findall(r'The primary key has the fingerprint\n`([0-9A-F]+)`', self.text)
        self.assertEqual(len(values), 4)
        for value in values:
            with self.subTest(fingerprint=value):
                replacement = ('0' if value[0] != '0' else '1') + value[1:]
                self.draft.write_text(self.text.replace(value, replacement))
                self.verify('primary key fingerprint mismatch')

    def test_metadata_session_key(self):
        path = self.directory / 'metadata-alg41.json'
        metadata = json.loads(path.read_text())
        metadata['sessionKey'] = '00' * 32
        path.write_text(json.dumps(metadata))
        self.verify('metadata session key mismatch')

    def test_metadata_share(self):
        path = self.directory / 'metadata-alg41.json'
        metadata = json.loads(path.read_text())
        metadata['mlkemKeyShare'] = '00' * 32
        path.write_text(json.dumps(metadata))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('check-metadata.py')),
                                 str(self.directory)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('combiner mismatch', result.stderr)

    def test_payload_newline(self):
        (self.directory / 'Testing.txt').write_bytes(b'Testing')
        self.verify('wrong test payload')


if __name__ == '__main__':
    unittest.main()
