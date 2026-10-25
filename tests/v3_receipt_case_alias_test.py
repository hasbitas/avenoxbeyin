"""Receipt ref case aliases obey the existing privacy/trust gate, including old rows."""
from datetime import date
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from v3_package_helpers import inherited_env, install

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'template/.claude/scripts'))

from beyin_v3_projections import _hidden_ref_sources, latest_receipts, recent_receipts


class ReceiptCaseAliasTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE records(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE markdown_sources(id TEXT PRIMARY KEY, source TEXT NOT NULL);
            CREATE TABLE receipts(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        ''')

    def record(self, source, **metadata):
        self.db.execute('INSERT INTO records VALUES (?,?)',
                        (source, json.dumps({'source': source, **metadata})))
        self.db.execute('INSERT INTO markdown_sources VALUES (?,?)', (source, source))

    def test_private_and_untrusted_aliases_use_unicode_casefold(self):
        source = 'knowledge/Özel-öğüşç-İ-ı-ß.md'
        alias = 'KNOWLEDGE/öZEL-ÖĞÜŞÇ-i\u0307-ı-SS.MD'
        self.assertEqual(source.casefold(), alias.casefold())
        for metadata in ({'visibility': 'private'}, {'trust': 'untrusted'}, {'trusted': False},
                         {'status': 'untrusted'}, {'kind': 'untrusted'}):
            with self.subTest(metadata=metadata):
                self.db.execute('DELETE FROM records')
                self.db.execute('DELETE FROM markdown_sources')
                self.record(source, **metadata)
                self.assertEqual(_hidden_ref_sources(self.db, [source, alias]), {source, alias})

    def test_internal_and_public_aliases_stay_visible(self):
        for name, metadata in (('default', {}), ('internal', {'visibility': 'internal'}),
                               ('public', {'visibility': 'public'})):
            source = 'knowledge/' + name + '.md'
            self.record(source, **metadata)
            with self.subTest(name=name):
                self.assertEqual(_hidden_ref_sources(self.db, [source, source.upper()]), set())
        self.assertEqual(_hidden_ref_sources(self.db, ['knowledge/missing.md']), set())

    def test_existing_receipt_alias_is_hidden_without_sync_or_rewrite(self):
        with tempfile.TemporaryDirectory(prefix='v3-receipt-case-reader-') as temp:
            vault = Path(temp)
            (vault / 'receipts').mkdir()
            (vault / 'knowledge').mkdir()
            (vault / 'knowledge/ozel.md').write_text('Synthetic private note.\n', encoding='utf-8')
            self.record('knowledge/ozel.md', visibility='private')
            event = {'event_id': 'old-case-alias', 'summary': 'Synthetic private receipt.',
                     'created_at': '2026-10-25T12:00:00Z', 'refs': ['KNOWLEDGE/OZEL.MD']}
            payload = json.dumps(event)
            self.db.execute('INSERT INTO receipts VALUES (?,?)', (event['event_id'], payload))
            source = 'receipts/' + hashlib.sha256(event['event_id'].encode()).hexdigest() + '.md'
            (vault / source).write_text(event['summary'], encoding='utf-8')
            with self.subTest(reader='latest_receipts'):
                self.assertEqual(list(latest_receipts(self.db, vault)), [])
            with self.subTest(reader='recent_receipts'):
                item, = recent_receipts(self.db, vault=vault, today=date(2026, 10, 25))['items']
                self.assertEqual(item['refs'], [])
                self.assertEqual(item['refs_withheld'], {'private': 1, 'missing': 0})
            self.assertEqual(self.db.execute('SELECT payload FROM receipts').fetchone()[0], payload)

    def test_large_ref_batch_only_withholds_private_aliases(self):
        refs, hidden = [], set()
        for number in range(505):
            source = 'knowledge/note-%d.md' % number
            private = number % 2 == 0
            self.record(source, visibility='private' if private else 'internal')
            refs.append(source.upper())
            if private:
                hidden.add(source.upper())
        self.assertEqual(_hidden_ref_sources(self.db, refs), hidden)


RECEIPT_READER = '''import json, sqlite3, sys
from pathlib import Path
vault, state = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(vault / '.claude/scripts'))
from beyin_v3_projections import latest_receipts, recent_receipts
db = sqlite3.connect((state / 'memory.sqlite3').resolve().as_uri() + '?mode=ro', uri=True)
try:
    latest = [event['summary'] for _, event in latest_receipts(db, vault)]
    # Keyed by the summary each receipt was written with: recap shows a placeholder for one with a private ref.
    import hashlib
    written = {'receipts/' + hashlib.sha256(event['event_id'].encode()).hexdigest() + '.md': event['summary']
               for event in (json.loads(payload) for (payload,) in db.execute('SELECT payload FROM receipts'))}
    recap = {written[item['source']]: [item['refs'], item.get('refs_withheld')]
             for item in recent_receipts(db, vault=vault)['items']}
    refs = {ident: json.loads(payload)['refs'] for ident, payload in db.execute('SELECT id, payload FROM receipts')}
finally:
    db.close()
print(json.dumps({'latest': latest, 'recap': recap, 'refs': refs}))
'''


@unittest.skipUnless(sys.platform == 'win32', 'CLI case aliases require a case-insensitive filesystem')
class InstalledReceiptCaseAliasTest(unittest.TestCase):
    OPEN = 'Synthetic open case alias outcome.'
    PRIVATE = 'Synthetic private exact ref outcome.'
    ALIAS = 'Synthetic private case alias outcome.'

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix='v3-receipt-case-install-')
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        cls.vault, cls.state, home = root / 'vault', root / 'state', root / 'home'
        cls.vault.mkdir()
        home.mkdir()
        cls.env = inherited_env(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'appdata'),
                                LOCALAPPDATA=str(home / 'localappdata'), BEYIN_V3_NO_SPAWN='1',
                                BEYIN_UPDATES_OFF='1', BEYIN_JEV_DISABLE='1',
                                PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8')
        for name, visibility in (('ozel', 'private'), ('genel', 'internal')):
            path = cls.vault / ('knowledge/' + name + '.md')
            path.parent.mkdir(exist_ok=True)
            path.write_text('---\nvisibility: ' + visibility + '\n---\nSynthetic note.\n', encoding='utf-8')
        installed = install(cls.vault, cls.state, cls.env)
        assert installed.returncode == 0, installed.stderr.decode('utf-8', errors='replace')
        command = [sys.executable, str(cls.vault / 'beyin.py')]
        for arguments in (['sync'],
                          ['receipt', '--event-id', 'open-alias', '--summary', cls.OPEN, '--ref', 'KNOWLEDGE/GENEL.MD'],
                          ['receipt', '--event-id', 'private-exact', '--summary', cls.PRIVATE, '--ref', 'knowledge/ozel.md'],
                          ['receipt', '--event-id', 'private-alias', '--summary', cls.ALIAS, '--ref', 'KNOWLEDGE/OZEL.MD']):
            done = subprocess.run(command + arguments + ['--json'], cwd=cls.vault, env=cls.env,
                                  capture_output=True, timeout=30)
            assert done.returncode == 0, done.stderr.decode('utf-8', errors='replace')

    def read_receipts(self):
        done = subprocess.run([sys.executable, '-c', RECEIPT_READER, str(self.vault), str(self.state)],
                              cwd=self.vault, env=self.env, capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', errors='replace'))
        return json.loads(done.stdout.decode('utf-8'))

    def test_latest_receipts_withholds_both_private_spellings(self):
        result = self.read_receipts()
        self.assertEqual(result['refs']['private-alias'], ['KNOWLEDGE/OZEL.MD'])
        self.assertEqual(result['latest'], [self.OPEN])

    def test_recent_receipts_counts_both_private_refs_and_keeps_public_alias(self):
        recap = self.read_receipts()['recap']
        for summary in (self.PRIVATE, self.ALIAS):
            with self.subTest(summary=summary):
                self.assertEqual(recap[summary], [[], {'private': 1, 'missing': 0}])
        self.assertEqual(recap[self.OPEN], [['KNOWLEDGE/GENEL.MD'], None])

    def test_real_session_start_withholds_both_private_summaries(self):
        done = subprocess.run([sys.executable, str(self.vault / '.claude/scripts/beyin_v3_hook.py'),
                               '--vault', str(self.vault), '--state', str(self.state), '--harness', 'claude'],
                              cwd=self.vault, env=self.env,
                              input=json.dumps({'hook_event_name': 'SessionStart', 'session_id': 'synthetic-case-alias',
                                                'prompt': 'Synthetic note'}).encode('utf-8'),
                              capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', errors='replace'))
        opening = done.stdout.decode('utf-8')
        self.assertNotIn(self.PRIVATE, opening)
        self.assertNotIn(self.ALIAS, opening)
        self.assertIn(self.OPEN, opening)


if __name__ == '__main__':
    unittest.main()
