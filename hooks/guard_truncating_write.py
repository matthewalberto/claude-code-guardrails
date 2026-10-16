# -*- coding: utf-8 -*-
r"""Claude Code PreToolUse hook: refuse an open-for-write that would truncate an existing file.

Why it exists
-------------
`open(path, "w")` truncates the file AT OPEN, before any of the new content exists. If anything
fails after that (an encode error, an exception while building the text), the file is left
empty. The agent did exactly this, more than once, to large tracked files: a script inserting
ONE entry into a big Markdown file opened it with "w", then hit `UnicodeEncodeError: surrogates
not allowed` on an emoji, and the file was 0 bytes. It was recovered from git only because it
happened to be committed.

A written rule already prescribed the fix (Edit tool for in-place changes, append mode for
appends, temp file plus atomic replace for rewrites). It kept failing anyway, because it asks for
vigilance about WRITE MECHANICS at the exact moment you're thinking about CONTENT. Pinning the
rule harder doesn't fix a rule that has to be recalled at the wrong moment, so this hook removes
the opportunity. It also fails silently: the traceback reads like a failed edit, and the tell is
a grep returning nothing one command later.

A later incident went straight past the first version of this hook: the truncating open sat
INSIDE a .py file written with the Write tool and then run, and the path was computed
(`os.path.join(ROOT, rel)`), not a string literal. So there are two routes.

What it blocks
--------------
ROUTE 1 (Bash or PowerShell command): an open-for-write whose target ALREADY EXISTS on disk.
  * open(P, "w"), io.open(P, "w", ...), open(P, mode="w"), and "wb", "w+"
  * codecs.open(P, "w")
  * a shell truncating redirect `> P` (but NOT the appending `>> P`)
  * PowerShell `Out-File -FilePath P` without -Append, and `Set-Content P`

Creating a NEW file is allowed: there's nothing to destroy. A redirect inside a heredoc BODY is
data, not a command, and is ignored (`cat > file <<EOF` is still caught: that redirect sits on
the opener line). Known gap: `bash <<'EOF' ... echo hi > f ... EOF` executes its body and is
allowed. That shape is rare, and documenting a redirect in a heredoc is common.

ROUTE 2 (Write tool, .py files only): the content of a script that's about to be run.
  * A SURROGATE-PAIR ESCAPE such as "\ud83d\udd34". In Python 3 source that's two lone
    surrogates, not an emoji, and no codec can encode it. Always a bug. Write the literal emoji
    or "\U0001F534". (JavaScript is exempt: there a surrogate pair is an ordinary escape.)
  * A READ-MODIFY-WRITE SCRIPT WITH NO ATOMIC REPLACE: the same path expression is both read
    and opened for writing, and the script never calls os.replace, os.rename or shutil.move.
    A pure generator (writes, never reads its target) is left alone. Requiring the SAME path
    on both sides matters: a looser "reads something and writes something" check flagged about
    half of a real scripts folder, and a guard that refuses half your scripts gets bypassed.

The way through
---------------
  * In-place change to an existing file: use the Edit tool. It can't truncate.
  * Append: `cat >> file` or open(P, "a").
  * Genuine full rewrite: build and encode the bytes first, write to a TEMP path, then
    os.replace(tmp, target). It's atomic, and a failed encode destroys nothing.
  * Deliberate last resort: put the token `truncating-write-ok` in the command (route 1) or
    anywhere in the file being written, for example a comment (route 2).

Contract: reads the hook JSON on stdin, writes a PreToolUse permissionDecision on stdout, always
exits 0. Fails OPEN: an internal error allows the call, so a bug here can never wedge the agent.

Wiring (settings.json, hooks.PreToolUse). Route 2 only fires if `Write` is in the matcher:
    { "matcher": "Bash|PowerShell|Write",
      "hooks": [ { "type": "command", "command": "python /path/to/guard_truncating_write.py", "timeout": 15 } ] }

Test: python guard_truncating_write.py --selftest
"""

import json
import os
import re
import sys

BYPASS = "truncating-write-ok"

# open(PATH, "w") / io.open / codecs.open: captures the path literal and the mode.
PY_OPEN = re.compile(
    r"""(?:\bio\.|\bcodecs\.)?\bopen\s*\(\s*(?:r|rb|b|u|f)?(['"])(?P<path>[^'"]+)\1\s*,\s*"""
    r"""(?:mode\s*=\s*)?(['"])(?P<mode>w[b+]?|w)\3""",
    re.I,
)

# Shell truncating redirect: `> path` but never `>> path`; skips fd dups (2>&1).
# The quoted alternatives matter: the bare form stops at whitespace, so without them any path
# containing a space (common on Windows) would slip through.
SH_REDIR = re.compile(
    r"""(?<![>\d])>\s*(?:"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|(?P<bare>[^\s;|&><]+))"""
)

PS_OUTFILE = re.compile(r"\b(?:Out-File|Set-Content)\b(?P<rest>[^;|\n]*)", re.I)
PS_PATH = re.compile(r"(?:-(?:FilePath|Path)\s+)?['\"]?(?P<path>[A-Za-z]:[^'\"\s]+|[^'\"\s-][^'\"\s]*)")

HEREDOC_OPEN = re.compile(r"<<(-?)\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))")


def _exists(path):
    """True only if the literal path resolves to an existing FILE we could destroy."""
    p = path.strip().strip("'\"")
    if not p or p.startswith("-"):
        return False
    if p.lower() in ("/dev/null", "nul", "$null", "con"):
        return False
    if "$" in p or "%" in p or "`" in p:
        return False          # unexpanded variable: can't resolve, don't guess
    try:
        return os.path.isfile(p)
    except Exception:
        return False


def _heredoc_body_lines(command):
    """Line indices that sit INSIDE a heredoc body. A body is data being written, not a command."""
    lines = command.split("\n")
    inside = set()
    i = 0
    while i < len(lines):
        m = HEREDOC_OPEN.search(lines[i])
        if not m:
            i += 1
            continue
        delim = m.group(2) or m.group(3) or m.group(4)
        j = i + 1
        while j < len(lines) and lines[j].strip() != delim:
            inside.add(j)
            j += 1
        i = j + 1
    return inside


def find_offenders(command):
    """Route 1: (kind, path, fragment) for each open-for-write against an existing file."""
    hits = []

    for m in PY_OPEN.finditer(command):
        path = m.group("path")
        if _exists(path):
            hits.append(("python", path, m.group(0)[:70]))

    body_lines = _heredoc_body_lines(command)
    for m in SH_REDIR.finditer(command):
        if command.count("\n", 0, m.start()) in body_lines:
            continue                      # inside a heredoc body: data, not a command
        path = m.group("dq") or m.group("sq") or m.group("bare")
        if path and _exists(path):
            hits.append(("shell", path, ("> " + path)[:70]))

    for m in PS_OUTFILE.finditer(command):
        rest = m.group("rest")
        if re.search(r"-Append\b", rest, re.I):
            continue
        pm = PS_PATH.search(rest)
        if pm and _exists(pm.group("path")):
            hits.append(("powershell", pm.group("path"), m.group(0)[:70]))

    return hits


# ---------------------------------------------------------------------------------------------
# ROUTE 2: the content of a .py file being written, which is about to be executed.
# ---------------------------------------------------------------------------------------------

# A HIGH surrogate escape in source: backslash-u-d8xx to backslash-u-dbxx.
SURROGATE = re.compile(r"\\u[dD][89abAB][0-9a-fA-F]{2}")

# Every open(...) with its first argument captured, so read and write targets can be compared.
# The path may contain one level of parentheses, which covers os.path.join(ROOT, rel), str(p).
PY_ANY_OPEN = re.compile(
    r"""(?:\bio\.|\bcodecs\.)?\bopen\s*\(\s*(?P<path>(?:[^()\n,]|\([^()\n]*\))*?)\s*"""
    r"""(?:,\s*(?:mode\s*=\s*)?(?P<q>['"])(?P<mode>[rwaxb+]{1,3})(?P=q))?\s*[,)]""",
)

# pathlib's truncating pair. The receiver is the path.
PY_PATHLIB = re.compile(r"(?P<path>[\w.\[\]\"'()]+)\.(?P<op>write_text|write_bytes|read_text|read_bytes)\s*\(")

# The atomic-replace remedy. Its presence anywhere in the file exempts the file: the predicate
# is "does this author know about atomic replacement", not a per-call proof.
PY_ATOMIC = re.compile(r"\bos\.replace\s*\(|\bshutil\.move\s*\(|\bos\.rename\s*\(", re.I)


def _norm(expr):
    """Collapse an argument expression so `os.path.join(ROOT, rel)` compares equal to itself."""
    return re.sub(r"\s+", "", expr or "").rstrip(",")


def _read_and_write_targets(content):
    """Return (read_exprs, write_exprs, first_write_match) as normalised text."""
    reads, writes, first_w = set(), set(), None
    for m in PY_ANY_OPEN.finditer(content):
        path, mode = _norm(m.group("path")), (m.group("mode") or "r").lower()
        if not path:
            continue
        if mode.startswith("w"):
            writes.add(path)
            first_w = first_w or m
        elif not mode.startswith("a"):        # append can't truncate
            reads.add(path)
    for m in PY_PATHLIB.finditer(content):
        path = _norm(m.group("path"))
        if m.group("op").startswith("write"):
            writes.add(path)
            first_w = first_w or m
        else:
            reads.add(path)
    return reads, writes, first_w


def find_content_offenders(file_path, content):
    """Route 2: (kind, label, detail) for each fault in a .py file being written."""
    if not (file_path or "").lower().endswith(".py"):
        return []
    hits = []

    m = SURROGATE.search(content)
    if m:
        line = next((l.strip()[:110] for l in content.split("\n") if m.group(0) in l), m.group(0))
        hits.append(("surrogate", m.group(0), line))

    if not PY_ATOMIC.search(content):
        reads, writes, first_w = _read_and_write_targets(content)
        both = sorted(reads & writes)
        if both and first_w is not None:
            frag = first_w.group(0)[:60]
            line = next((l.strip()[:110] for l in content.split("\n") if frag[:30] in l), frag)
            hits.append(("rmw", both[0], line))

    return hits


def command_reason(offenders):
    detail, seen = [], set()
    for kind, path, frag in offenders:
        if path in seen:
            continue
        seen.add(path)
        detail.append("  %-11s %s   <- %s" % (kind, frag, path))
    return (
        "BLOCKED: this opens an EXISTING file for writing, which truncates it at OPEN, before\n"
        "any of your content is written and before any encode error can fire.\n"
        + "\n".join(detail[:4])
        + "\n\nIf anything fails after the open, the file is left at 0 bytes, and the failure\n"
          "reads like an ordinary failed edit.\n\n"
          "Do this instead:\n"
          "  1. Changing an existing file? Use the Edit tool. It can't truncate.\n"
          "  2. Appending? `cat >> file` or open(path, 'a').\n"
          "  3. Genuine full rewrite? Build and encode the bytes first, write to a TEMP path,\n"
          "     verify it, then os.replace(tmp, target). Atomic, and nothing is destroyed if\n"
          "     the encode fails.\n\n"
          "Last resort, when a truncating rewrite is genuinely intended: include the token "
        + BYPASS + " in the command."
    )


def content_reason(offenders):
    parts = ["BLOCKED: this Python script is about to be RUN, and it has the shape that",
             "empties existing files.", ""]
    for kind, frag, line in offenders[:3]:
        if kind == "surrogate":
            parts.append("  SURROGATE ESCAPE  %s   <- %s" % (frag, line))
            parts.append("    In Python 3 source that's two LONE surrogates, not an emoji. No codec can")
            parts.append("    encode it, so the write raises UnicodeEncodeError, after open() has")
            parts.append("    already truncated the target. Use the literal emoji, or " + chr(92) + "U0001F534.")
        else:
            parts.append("  READ-MODIFY-WRITE, NO ATOMIC REPLACE  %s   <- %s" % (frag, line))
            parts.append("    This script reads a file and opens the same path for writing with no")
            parts.append("    os.replace() anywhere. open(p, 'w') truncates AT OPEN, before your")
            parts.append("    content exists and before any encode error can fire.")
    parts += [
        "",
        "Do this instead:",
        "  1. Changing an existing file? Use the Edit tool. It can't truncate.",
        "  2. Must script it? Build the text, write to a TEMP path, then os.replace(tmp, target).",
        "",
        "Last resort, when this is genuinely intended: put the token " + BYPASS + " in the file.",
    ]
    return "\n".join(parts)


def evaluate(tool, tool_input):
    """Return a deny reason, or None to allow. main() and the selftest both call this."""
    if tool == "Write":
        content = tool_input.get("content") or ""
        if BYPASS in content:
            return None
        offenders = find_content_offenders(tool_input.get("file_path") or "", content)
        return content_reason(offenders) if offenders else None
    command = tool_input.get("command") or ""
    if BYPASS in command:
        return None
    offenders = find_offenders(command)
    return command_reason(offenders) if offenders else None


def decide(reason=None):
    if reason:
        payload = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}}
    else:
        payload = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "allow"}}
    sys.stdout.write(json.dumps(payload))


def main():
    try:
        sys.stdin.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    raw = sys.stdin.read()
    if not raw.strip():
        return decide()
    payload = json.loads(raw)
    decide(evaluate(payload.get("tool_name") or "", payload.get("tool_input") or {}))


# ---------------------------------------------------------------------------------------------
# Self-test. Route 1 keys on os.path.isfile, so it builds a throwaway fixture directory with an
# existing file, a spaced path, and a name that doesn't exist yet. No hardcoded paths: a test
# pinned to a path that later disappears goes uniformly red and asserts nothing.
# ---------------------------------------------------------------------------------------------

SURROGATE_PATCH = (
    "import io, os\n"
    'RED = "' + chr(92) + 'ud83d' + chr(92) + 'udd34"\n'
    'txt = io.open(P, "r", encoding="utf-8").read()\n'
    'io.open(P, "w", encoding="utf-8").write(txt + RED)\n'
)

RMW_COMPUTED = (
    "import io, os\n"
    "def load(rel):\n"
    '    return io.open(os.path.join(ROOT, rel), "r", encoding="utf-8").read()\n'
    "def save(rel, txt):\n"
    '    io.open(os.path.join(ROOT, rel), "w", encoding="utf-8").write(txt)\n'
)

RMW_ATOMIC = (
    "import io, os\n"
    "def load(rel):\n"
    '    return io.open(os.path.join(ROOT, rel), "r", encoding="utf-8").read()\n'
    "def save(rel, txt):\n"
    "    p = os.path.join(ROOT, rel)\n"
    '    with io.open(p + ".tmp", "w", encoding="utf-8") as f:\n'
    "        f.write(txt)\n"
    "    os.replace(p + '.tmp', p)\n"
)

GENERATOR = (
    "import io\n"
    'io.open("out.json", "w", encoding="utf-8").write(json.dumps(rows))\n'
)

WRITE_CASES = [
    (True,  "patch.py", SURROGATE_PATCH, "surrogate escape in .py source"),
    (True,  "records.py", RMW_COMPUTED, "read-modify-write, computed path, no os.replace"),
    (False, "records.py", RMW_ATOMIC, "read-modify-write WITH temp + os.replace"),
    (False, "build.py", GENERATOR, "pure generator: writes, never reads"),
    (False, "patch.js", SURROGATE_PATCH, ".js: a surrogate pair is legal source there"),
    (False, "patch.py", SURROGATE_PATCH + "# " + BYPASS + "\n", "explicit bypass in the file"),
    (False, "notes.md", SURROGATE_PATCH, "not a script at all"),
    (False, "patch.py", 'RED = "' + chr(92) + 'U0001F534"\nprint(RED)\n', "the correct non-BMP escape"),
]


def command_cases(existing, new, spaced):
    return [
        # (expect_block, command, why, needs_spacefree_fixture)
        (True,  'python -c "io.open(r\'%s\', \'w\').write(s)"' % existing, "io.open w on an existing file", False),
        (True,  'python -c "open(\'%s\', \'w\')"' % existing, "plain open w", False),
        (True,  'echo hi > %s' % existing, "shell truncating redirect", True),
        (True,  'python -c "open(\'%s\', mode=\'wb\')"' % existing, "wb via mode kwarg", False),
        (True,  'echo hi > "%s"' % spaced, "spaced path, double-quoted redirect", False),
        (True,  "echo hi > '%s'" % spaced, "spaced path, single-quoted redirect", False),
        (True,  'python -c "open(r\'%s\', \'w\')"' % spaced, "spaced path, python open", False),
        (True,  "cat > %s <<'EOF'\nnew content\nEOF" % existing, "heredoc OPENER with a truncating redirect", True),
        (True,  'Set-Content -Path "%s" -Value x' % existing, "PowerShell Set-Content", False),
        (False, 'cat >> %s' % existing, "APPEND to the same file", True),
        (False, 'python -c "open(\'%s\', \'a\')"' % existing, "open for append", False),
        (False, 'python -c "open(\'%s\', \'r\')"' % existing, "open for read", False),
        (False, 'echo hi > %s' % new, "create a NEW file: nothing to destroy", True),
        (False, 'grep -n x %s > /dev/null' % existing, "/dev/null", True),
        (False, 'npm run check:all 2>&1', "fd dup, not a redirect to a file", False),
        (False, 'Out-File -FilePath "%s" -Append' % existing, "PowerShell Out-File -Append", False),
        (False, 'python -c "io.open(r\'%s\',\'w\')"  # %s' % (existing, BYPASS), "explicit bypass", False),
        # An UNQUOTED spaced path isn't one word to a real shell either, so the file in question
        # is never the redirect target. Denying it would invent a write the shell won't perform.
        (False, 'echo hi > %s' % spaced, "spaced path unquoted: the shell splits it too", False),
        (False, 'cat >> "%s"' % spaced, "spaced path, quoted APPEND", False),
        (False, "cat >> notes.md <<'EOF'\nrun it as: npm run check > %s\nEOF" % existing,
         "heredoc BODY quoting a redirect: data, not a command", True),
    ]


def selftest():
    import shutil
    import tempfile
    fix = tempfile.mkdtemp(prefix="gtw-")
    failures = checks = skipped = 0
    try:
        existing = os.path.join(fix, "existing.md")
        new = os.path.join(fix, "brand-new-file.txt")
        spaced_dir = os.path.join(fix, "With Space")
        spaced = os.path.join(spaced_dir, "existing.md")
        os.makedirs(spaced_dir)
        for p in (existing, spaced):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("# a file with something in it to destroy\n")
        fix_has_space = any(c.isspace() for c in fix)

        print("-- route 1: commands --")
        for expect_block, cmd, why, needs_plain in command_cases(existing, new, spaced):
            if needs_plain and fix_has_space:
                skipped += 1
                print("%-6s %-6s %s (temp dir contains a space)" % ("skip", "", why))
                continue
            got = evaluate("Bash", {"command": cmd}) is not None
            ok = got == expect_block
            checks += 1
            failures += not ok
            print("%-6s %-6s %s" % ("ok" if ok else "FAIL", "BLOCK" if expect_block else "allow", why))

        print("-- route 2: .py content written with the Write tool --")
        for expect_block, fp, content, why in WRITE_CASES:
            got = evaluate("Write", {"file_path": fp, "content": content}) is not None
            ok = got == expect_block
            checks += 1
            failures += not ok
            print("%-6s %-6s %s" % ("ok" if ok else "FAIL", "BLOCK" if expect_block else "allow", why))
    finally:
        shutil.rmtree(fix, ignore_errors=True)
    print("\n%d checks, %d failure(s)%s" % (checks, failures,
                                            (", %d skipped" % skipped) if skipped else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        main()
    except Exception as exc:  # fail OPEN, never wedge the agent
        sys.stderr.write("guard_truncating_write: internal error, allowing (%s)\n" % exc)
        decide()
    sys.exit(0)
