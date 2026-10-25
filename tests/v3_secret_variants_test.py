"""Synthetic secret representations; offline writes and advisor preflight only."""
import base64
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest

from v3_package_helpers import inherited_env, install

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'template/.claude/scripts'))
from beyin_v3_jev import _safe
from beyin_v3_preferences import save
from beyin_v3_secrets import redact
from beyin_v3_sync import SyncEngine

KEY = 'sk-' + 'A' * 40
ENCODED = base64.b64encode(KEY.encode()).decode('ascii')


class SecretVariantsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='beyin-secret-variants-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.vault = root / 'vault'
        self.vault.mkdir()
        self.state = root / 'state'
        self.engine = SyncEngine(self.vault, self.state)
        save(self.vault, {'secret_filter': True})

    def assert_masked_note(self, number, value, *secrets):
        text = 'Before (' + value + ') after.'
        result = self.engine.note_create(f'notes/variant-{number}.md', text)
        self.assertGreaterEqual(result['redacted'], 1)
        stored = (self.vault / result['source']).read_text(encoding='utf-8')
        self.assertNotIn(value, stored)
        for secret in secrets:
            self.assertNotIn(secret, stored)
        self.assertIn('Before ([REDACTED]) after.', stored)

    def test_unicode_variants_mask_the_original_span_on_note_create(self):
        for number, character in enumerate(('\u200b', '\u200c', '\u200d', '\u2060',
                                             '\ufeff', '\u200e', '\u202e', '\u2066')):
            with self.subTest(character=ascii(character)):
                self.assert_masked_note(number, 'sk-' + character + 'A' * 40)
        self.assert_masked_note('interspersed', '\u200b'.join(KEY))
        clean = 'Before\u200b (' + KEY + ') after\u2060.'
        self.assertEqual(redact(clean, self.state), ('Before\u200b ([REDACTED]) after\u2060.', 1))

    def test_base64_representations_are_deliberately_unsupported(self):
        """Like the filter docstring, encoded secrets are not decoded or masked."""
        values = (ENCODED, 'c2st' + 'QUFB' * 13 + 'QQ==',
                  base64.b64encode(('sk-\u200b' + 'A' * 40).encode()).decode('ascii'),
                  base64.b64encode(('Before ' + KEY + ' after').encode()).decode('ascii'),
                  base64.b64encode(('sk-' + 'A' * 26).encode()).decode('ascii'),
                  base64.b64encode(b'\xff ' + KEY.encode() + b' \xfe').decode('ascii'),
                  base64.b64encode(('AKIA' + 'Q' * 16).encode()).decode('ascii'),
                  base64.b64encode(('sk-' + 'A' * 20).encode()).decode('ascii'),
                  base64.b64encode(('AKIA' + 'Q' * 16 + '|' + KEY).encode()).decode('ascii'),
                  'k=' + ENCODED, 'path/' + ENCODED)
        for number, value in enumerate(values):
            with self.subTest(number=number):
                self.assertEqual(redact(value, self.state), (value, 0))
                self.assertIsNone(_safe(self.engine.store, {'statement': value}))
                result = self.engine.note_create(f'notes/base64-{number}.md', value)
                self.assertEqual(result['redacted'], 0)
                self.assertIn(value, (self.vault / result['source']).read_text(encoding='utf-8'))

    def test_short_normalized_custom_literals_retain_only_raw_matches(self):
        self.state.mkdir(parents=True, exist_ok=True)
        clean = 'Bu not tamamen zararsiz bir metin; anahtar yok.'
        for literal in ('\ufeff\ufeff\ufeffa', '\ufeff' * 4, '\u200bab\u200b', 'a\u2060bc'):
            with self.subTest(literal=ascii(literal)):
                (self.state / 'secret-patterns.txt').write_text(literal + '\n', encoding='utf-8')
                self.assertEqual(redact(literal, self.state), ('[REDACTED]', 1))
                with self.assertRaisesRegex(ValueError, '^advisor_sensitive_input$'):
                    _safe(self.engine.store, {'statement': literal})
                self.assertEqual(redact(clean, self.state), (clean, 0))
                self.assertIsNone(_safe(self.engine.store, {'statement': clean}))

    def test_placeholder_normalized_custom_literals_retain_only_raw_matches(self):
        self.state.mkdir(parents=True, exist_ok=True)
        for literal, clean in (('[RE\u200bDACTED]', 'Already [REDACTED].'),
                               ('prefix[RE\u200bDACTED]suffix', 'Already prefix[REDACTED]suffix.')):
            with self.subTest(literal=ascii(literal)):
                (self.state / 'secret-patterns.txt').write_text(literal + '\n', encoding='utf-8')
                self.assertEqual(redact(clean, self.state), (clean, 0))
                self.assertIsNone(_safe(self.engine.store, {'statement': clean}))
                self.assertEqual(redact(literal, self.state), ('[REDACTED]', 1))
                with self.assertRaisesRegex(ValueError, '^advisor_sensitive_input$'):
                    _safe(self.engine.store, {'statement': literal})

    def test_safe_custom_literal_normalization_preserves_surrounding_format(self):
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / 'secret-patterns.txt').write_text('my-\u200bsecret\n', encoding='utf-8')
        for value in ('my-secret', 'my-\u200bsecret', 'my-\u2060secret'):
            with self.subTest(value=ascii(value)):
                self.assertEqual(redact('Before\u200b (' + value + ') after\u2060.', self.state),
                                 ('Before\u200b ([REDACTED]) after\u2060.', 1))
                with self.assertRaisesRegex(ValueError, '^advisor_sensitive_input$'):
                    _safe(self.engine.store, {'statement': value})

    def test_jev_rejects_variants_in_nested_values_and_keys(self):
        for value in (KEY, 'sk-\u200b' + 'A' * 40):
            for payload in ({'cards': [{'statement': value}]}, {value: 'ordinary text'}):
                with self.subTest(value=value[:8], payload=type(payload).__name__):
                    with self.assertRaisesRegex(ValueError, '^advisor_sensitive_input$'):
                        _safe(self.engine.store, payload)

    def test_plain_and_code_block_counts_stay_exact(self):
        for number, text in enumerate((KEY, '```\n' + KEY + '\n```',
                                        KEY + '\n```\n' + KEY + '\n```')):
            with self.subTest(number=number):
                expected = 2 if number == 2 else 1
                self.assertEqual(redact(text, self.state), (text.replace(KEY, '[REDACTED]'), expected))
                result = self.engine.note_create(f'notes/plain-{number}.md', text)
                self.assertEqual(result['redacted'], expected)

    def test_nonsecrets_invalid_short_base64_and_split_lines_stay_unchanged(self):
        blob = base64.b64encode(random.Random(7).randbytes(60)).decode('ascii')
        short_clean = base64.b64encode(random.Random(8).randbytes(18)).decode('ascii')
        invalid = ENCODED[:-1] + '=' * 3
        for number, text in enumerate(('Ordinary project notes.', blob, short_clean, invalid,
                                       ENCODED.rstrip('='), 'sk-' + 'A' * 10 + '\n' + 'A' * 30)):
            with self.subTest(number=number):
                self.assertEqual(redact(text, self.state), (text, 0))
                result = self.engine.note_create(f'notes/clean-{number}.md', text)
                self.assertEqual(result['redacted'], 0)
                self.assertIn(text, (self.vault / result['source']).read_text(encoding='utf-8'))
                self.assertIsNone(_safe(self.engine.store, {'statement': text}))

    def test_large_plain_and_encoded_inputs_have_a_loose_time_guard(self):
        plain = ('Ordinary project notes; no credentials here. ' * 7000)[:260 * 1024]
        encoded = base64.b64encode(random.Random(9).randbytes(204288)).decode('ascii')
        for name, text in (('plain', plain), ('encoded', encoded)):
            with self.subTest(name=name):
                started = time.monotonic()
                self.assertEqual(redact(text, self.state), (text, 0))
                self.assertLess(time.monotonic() - started, 4.0)

    def test_invalid_base64_slash_run_has_no_candidate_scanning_cost(self):
        text = 'A/' * 32000 + '==='
        started = time.monotonic()
        self.assertEqual(redact(text, self.state), (text, 0))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_installed_cli_masks_unicode_and_leaves_base64_unsupported(self):
        home = Path(self.tmp.name) / 'home'
        home.mkdir()
        env = inherited_env(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'appdata'),
                            LOCALAPPDATA=str(home / 'localappdata'), BEYIN_V3_NO_SPAWN='1',
                            PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8')
        installed = install(self.vault, self.state, env)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for number, (value, expected) in enumerate((('sk-\u200b' + 'A' * 40, 1), (ENCODED, 0))):
            with self.subTest(number=number):
                done = subprocess.run([sys.executable, str(self.vault / 'beyin.py'), 'note-create', '--json'],
                                      input=json.dumps({'source': f'notes/cli-{number}.md', 'text': value}).encode(),
                                      cwd=self.vault, env=env, capture_output=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', errors='replace'))
                result = json.loads(done.stdout)
                self.assertEqual(result['redacted'], expected)
                stored = (self.vault / result['source']).read_text(encoding='utf-8')
                if expected:
                    self.assertNotIn(value, stored)
                    self.assertIn('[REDACTED]', stored)
                else:
                    self.assertIn(value, stored)
                    self.assertNotIn('[REDACTED]', stored)


if __name__ == '__main__':
    unittest.main()
