"""Opt-in local secret redaction for user-authored V3 write commands.

Known patterns and custom literals are scanned in plain text (including code
blocks), ignoring Unicode Cf format characters while redacting the original span.
Valid standard base64 pieces large enough to contain the shortest built-in secret
and no larger than 64 KiB are decoded once as UTF-8 and scanned the same way; every
secret counts and any secret masks the whole encoded piece. Arbitrary binary blobs
are not secrets. Padding is required: unpadded base64, nested encodings, base64url
and line-split representations are not decoded or joined.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import base64
import binascii
import re
import sqlite3
import unicodedata


BUILTIN_PATTERNS = (
    re.compile(r"(?i)(?<=[?&])(?:api[_ -]?key|access[_ -]?token|token|secret|password|passwd)=[^&\s]{8,}"),
    re.compile(r"""(?i)(?<![a-zA-Z0-9_])(?:\\{0,8}["\']?(?:api[_ -]?key|access[_ -]?token|token|secret|password|passwd)\\{0,8}["\']?)\s*[:=]\s*(?:\\{0,8}["\']\S{8,}\\{0,8}["\']|[^"\'\s,;][^\s,;]{7,})"""),
    re.compile(r"(?<=://)[^/\s?#:]*:[^/\s?#]*(?=@[^/\s?#@]+)"),
    re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    # Hugging Face access token: hf_ plus exactly 34 letters or digits. A fixed length
    # keeps identifiers such as hf_TransformersAutoModelLoader out.
    re.compile(r"\bhf_[A-Za-z0-9]{34}(?![A-Za-z0-9])"),
    # The key alphabet includes - and _, so only a key character may not follow; a period
    # or dash before the key, or a sentence-ending period after it, still redacts.
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    # Provider formats with a fixed, distinctive prefix. Stripe keys use underscores,
    # so the dashed sk- pattern above never sees them (#151).
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,255}\b"),
    re.compile(r"\bxox[abeoprs]-[0-9]+-[A-Za-z0-9-]{8,255}\b"),
    re.compile(r"\bxapp-[0-9]+-[A-Za-z0-9-]{8,255}\b"),
    re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-]|\.[A-Za-z0-9_-])"),
    # A JWT header is base64url JSON, so it always opens with eyJ; three dot-separated
    # base64url segments are required (five for an encrypted JWE). Plain base64
    # (images, blobs) has no dots.
    re.compile(r"(?<![A-Za-z0-9_.-])eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){2}(?:\.[A-Za-z0-9_-]+){0,2}(?![A-Za-z0-9_-])"),
    # Discord bot token: base64 of a numeric user id (so it starts with M, N or O),
    # a 6 character timestamp and an HMAC of at least 27 characters. Like SendGrid it
    # must stand alone: a segment of a longer dotted name is not a token.
    re.compile(r"(?<![A-Za-z0-9_.-])[MNO][A-Za-z0-9_-]{22,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-]|\.[A-Za-z0-9_-])"),
)


def _custom_literals(state):
    """Load bounded literal values, not executable regular expressions."""
    path = Path(state) / 'secret-patterns.txt'
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError('secret-patterns.txt must be a regular file no larger than 64 KiB')
    values = []
    for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith('#'):
            continue
        if len(value) < 4 or len(value) > 1000 or value == '[REDACTED]':
            raise ValueError(f'invalid secret literal at line {number}')
        values.append(value)
        if len(values) > 100:
            raise ValueError('secret-patterns.txt supports at most 100 literals')
    return values


SHORTEST_BUILTIN_SECRET = 20
BASE64_MIN_CHARS = 4 * ((SHORTEST_BUILTIN_SECRET + 2) // 3)
BASE64_MAX_CHARS = 64 * 1024
BASE64_PIECE = re.compile(
    rf'(?<![A-Za-z0-9+])[A-Za-z0-9+/]{{{BASE64_MIN_CHARS - 2},}}={{0,2}}(?![A-Za-z0-9+/=])')


def _without_format(text):
    return ''.join(character for character in text if unicodedata.category(character) != 'Cf')


def _sub_normalized(pattern, text, positions, replacement):
    parts, mapped, spans = [], [], []
    end, count = 0, 0
    for match in pattern.finditer(text):
        value = replacement(match)
        if value is None:
            continue
        parts.append(text[end:match.start()])
        mapped.extend(positions[end:match.start()])
        parts.append(value)
        mapped.extend([positions[match.start()]] * len(value))
        spans.append((positions[match.start()], positions[match.end() - 1] + 1, value))
        end = match.end()
        count += 1
    parts.append(text[end:])
    mapped.extend(positions[end:])
    return ''.join(parts), mapped, spans, count


def _restore_original(text, spans):
    merged = []
    for start, stop, value in sorted(spans):
        if merged and start < merged[-1][1]:
            previous = merged[-1]
            merged[-1] = (previous[0], max(stop, previous[1]), previous[2])
        else:
            merged.append((start, stop, value))
    parts, end = [], 0
    for start, stop, value in merged:
        parts.extend((text[end:start], value))
        end = stop
    parts.append(text[end:])
    return ''.join(parts)


def _redact(text, literals, scan_base64):
    literal_patterns = []
    for literal in literals:
        literal = _without_format(literal)
        if len(literal) >= 4:
            literal_patterns.append(re.compile(re.escape(literal)))
    patterns = BUILTIN_PATTERNS + tuple(literal_patterns)
    encoded_count = 0

    def encoded_secret(match):
        nonlocal encoded_count
        piece = match.group()
        starts = (0, piece.rfind('/') + 1) if '/' in piece else (0,)
        for start in dict.fromkeys(starts):
            candidate = piece[start:]
            if not BASE64_MIN_CHARS <= len(candidate) <= BASE64_MAX_CHARS or len(candidate) % 4:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True).decode('utf-8', errors='replace')
            except binascii.Error:
                continue
            _, matches = _redact_plain(decoded, literals)
            if matches:
                encoded_count += matches
                return piece[:start] + '[REDACTED]'
        return None

    if not any(unicodedata.category(character) == 'Cf' for character in text):
        result, count = text, 0
        for pattern in patterns:
            result, matches = pattern.subn('[REDACTED]', result)
            count += matches
        if scan_base64:
            result, _ = BASE64_PIECE.subn(lambda match: encoded_secret(match) or match.group(), result)
        return result, count + encoded_count

    positions = [index for index, character in enumerate(text)
                 if unicodedata.category(character) != 'Cf']
    normalized = ''.join(text[index] for index in positions)
    spans, count = [], 0
    for pattern in patterns:
        normalized, positions, found, matches = _sub_normalized(
            pattern, normalized, positions, lambda match: '[REDACTED]')
        spans.extend(found)
        count += matches
    if scan_base64:
        normalized, positions, found, _ = _sub_normalized(
            BASE64_PIECE, normalized, positions, encoded_secret)
        spans.extend(found)
    return _restore_original(text, spans), count + encoded_count


def _redact_plain(text, literals):
    return _redact(text, literals, False)


def redact(text, state):
    if not isinstance(text, str):
        raise ValueError('secret filter input must be text')
    return _redact(text, _custom_literals(state), True)


def record(state, count):
    """Persist only aggregate counts outside the vault; never persist matches."""
    if type(count) is not int or count < 0:
        raise ValueError('redaction count must be a nonnegative integer')
    state = Path(state)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state / 'secret-filter.sqlite3'
    if path.is_symlink():
        raise ValueError('secret filter health database must not be a symlink')
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY CHECK(id=1), total INTEGER NOT NULL, last_count INTEGER NOT NULL, last_at TEXT)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT total FROM health WHERE id=1').fetchone()
        total = (row[0] if row else 0) + count
        db.execute('INSERT OR REPLACE INTO health VALUES (1,?,?,?)',
                   (total, count, datetime.now(timezone.utc).isoformat()))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return {'total': total, 'last_count': count}


def health(state):
    path = Path(state) / 'secret-filter.sqlite3'
    if not path.exists():
        return {'total': 0, 'last_count': 0, 'last_at': None}
    if path.is_symlink() or not path.is_file():
        raise ValueError('secret filter health database must be a regular file')
    with closing(sqlite3.connect(path, timeout=2)) as db:
        row = db.execute('SELECT total,last_count,last_at FROM health WHERE id=1').fetchone()
    return ({'total': row[0], 'last_count': row[1], 'last_at': row[2]}
            if row else {'total': 0, 'last_count': 0, 'last_at': None})
