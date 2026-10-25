"""Portable note-create names must be rejected before durable journal writes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from v3_package_helpers import inherited_env, install


class NoteCreateInvalidNameTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='beyin-invalid-note-name-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        self.vault, self.state, home = root / 'vault', root / 'state', root / 'home'
        self.vault.mkdir()
        home.mkdir()
        self.env = inherited_env(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'appdata'),
                                 LOCALAPPDATA=str(home / 'localappdata'), BEYIN_V3_NO_SPAWN='1',
                                 PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8')
        installed = install(self.vault, self.state, self.env)
        self.assertEqual(installed.returncode, 0, installed.stderr.decode('utf-8', errors='replace'))

    def command(self, *args, payload=None):
        return subprocess.run([sys.executable, str(self.vault / 'beyin.py'), *args, '--json'],
                              cwd=self.vault, env=self.env, capture_output=True, timeout=60,
                              input=json.dumps(payload).encode('utf-8') if payload is not None else None)

    def succeeded(self, *args, payload=None):
        done = self.command(*args, payload=payload)
        self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', errors='replace'))
        return json.loads(done.stdout.decode('utf-8'))

    def refused(self, source, message):
        done = self.command('note-create', payload={'source': source, 'text': 'Synthetic calibration note.',
                                                  'metadata': {'id': 'synthetic-invalid'}})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(list((self.state / 'markdown-journal').iterdir()), [],
                         'invalid note-create must not leave a durable journal intent')
        error = json.loads(done.stderr.decode('utf-8'))
        self.assertEqual(error['error'], 'ValueError')
        self.assertIn(message, error['message'])
        self.assertEqual(self.succeeded('sync')['status'], 'succeeded')
        self.succeeded('context', 'Synthetic calibration')

    def test_alternate_data_stream_name_is_rejected_before_journaling(self):
        self.refused('knowledge/a.md:akis.md', 'use a vault-relative Markdown path')

    def test_device_names_are_rejected_before_journaling(self):
        for name in ('CON.md', 'nul.md', 'COM1.md', 'LPT9.md', 'AUX/note.md'):
            with self.subTest(name=name):
                self.refused('knowledge/' + name, 'device paths are not sources')

    def test_trailing_dots_and_spaces_are_rejected_before_journaling(self):
        for name in ('nokta.', 'nokta./note.md', 'bosluk /note.md'):
            with self.subTest(name=name):
                self.refused('knowledge/' + name, 'only visible vault-relative sources are supported')

    def test_valid_note_create_and_edit_still_work(self):
        source = 'knowledge/calibration.md'
        created = self.succeeded('note-create', payload={'source': source, 'text': 'Synthetic calibration note.',
                                                        'metadata': {'id': 'synthetic-valid'}})
        self.assertEqual(created['status'], 'succeeded')
        path = self.vault / source
        raw = path.read_bytes()
        edited = self.succeeded('note-edit', '--file', '-', payload={
            'source': source, 'expected_sha256': hashlib.sha256(raw).hexdigest(),
            'edits': [{'old': 'Synthetic calibration note.', 'new': 'Synthetic calibration updated.'}]})
        self.assertEqual(edited['status'], 'written')
        self.assertIn(b'Synthetic calibration updated.', path.read_bytes())
        self.assertEqual(list((self.state / 'markdown-journal').iterdir()), [])
        self.assertEqual(self.succeeded('sync')['status'], 'succeeded')
        self.succeeded('context', 'Synthetic calibration')


if __name__ == '__main__':
    unittest.main()
