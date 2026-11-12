#!/usr/bin/env python3
"""Regression checks for the vector verifier: pass the built generator path."""
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
        statement = 'All self-signatures use SHA3-512 as their hash algorithm.'
        self.assertEqual(self.text.count(statement), 4)
        parts = self.text.split(statement)
        for occurrence in range(4):
            for replacement in ['', statement.replace('SHA3-512', 'SHA3-256')]:
                with self.subTest(suite=occurrence + 41, replacement=replacement):
                    altered = parts[0]
                    for index, part in enumerate(parts[1:]):
                        altered += (replacement if index == occurrence else statement) + part
                    self.draft.write_text(altered)
                    self.verify('certificate digest statement missing or incorrect')

    def test_refresh_preserves_keys_and_existing_messages(self):
        result = subprocess.run([GENERATOR, 'generate-keys', '--suite', '42',
            '--suite', '44', '--output', str(self.directory), '--force', '--reuse-keys'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
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
