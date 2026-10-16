# -*- coding: utf-8 -*-
r"""Claude Code PreToolUse hook: refuse a WRITE that is gated behind a `cd` in the same && chain.

Why it exists
-------------
`cd some/dir && cat >> log.md <<'EOF' ... EOF` fails silently. If the `cd` resolves against the
wrong directory, `&&` short-circuits and the append never runs. Nothing says so. The heredoc body
is consumed as if it had been written, and a following `echo ok` prints ok. A `git commit` on the
next line isn't part of the chain, so it still runs and commits a change set with the file
missing, under a message describing work it doesn't carry.

The agent hit this three times in one session, the third time after the lesson had been written
down. The environment guidance already said "don't prefix commands with cd". It didn't help,
because `cd X && write` reads as addressing a file, not as a conditional. A mistake that repeats
after it's written down needs a mechanical fix, so this hook removes the opportunity.

A failed `cd` isn't a loud error. It's a silent no-op on the write while the turn still looks
successful, which is why it's worth a guard.

What it blocks
--------------
A command that BOTH (a) contains a `cd ... &&` chain and (b) later in that chain writes with
`>>` or `>` (including a heredoc opener) into a RELATIVE path.

Deliberately narrow, because a guard that fires on ordinary work gets bypassed by reflex:
  * `cd x && ls`, `cd x && npm test`, `cd x && git status`: no write.
  * `cd x && cat >> /abs/path`, or a `$VAR` or `~` rooted path: the target doesn't depend on cwd.
  * A write with no `cd` at all: that's the recommended shape.
  * `cd x; cat >> y` with a semicolon: a failed cd doesn't skip the write there, so the
    silent-drop failure can't happen.

The way through
---------------
Use an ABSOLUTE path for the redirect target and drop the `cd`:

    cat >> /abs/path/to/log.md <<'EOF'
    ...
    EOF

When a command must run in another directory, don't gate a write on it: `git -C <dir> ...`,
`npm --prefix <dir> ...`. As a deliberate last resort, put the token `cd-redirect-ok` in the
command.

Contract: reads the hook JSON on stdin, writes a PreToolUse permissionDecision on stdout, always
exits 0. Fails OPEN: an internal error allows the command, so a bug here can never wedge the
agent's shell.

Wiring (settings.json, hooks.PreToolUse):
    { "matcher": "Bash",
      "hooks": [ { "type": "command", "command": "python /path/to/guard_cd_chained_redirect.py", "timeout": 15 } ] }

Test: python guard_cd_chained_redirect.py --selftest
"""
import json
import re
import sys

BYPASS = "cd-redirect-ok"

# A `cd` chained with && to something after it. `cd x; ...` is excluded on purpose: a semicolon
# doesn't short-circuit, so the silent-skip failure can't arise.
CD_CHAIN = re.compile(r"(?:^|[;&|]|\n)\s*cd\s+[^\n;&|]+&&")

# A write redirect, or a heredoc opener, whose target is RELATIVE. An absolute or
# variable-rooted target is exempt: it doesn't depend on the cwd.
REDIRECT = re.compile(r"(?:^|\s)(>>?)\s*(?!/|~|\$|[A-Za-z]:[\\/])([^\s;&|<>()]+)")


def strip_quoted(cmd):
    """Blank out single and double quoted runs so a `>` inside a string isn't counted.

    It deliberately doesn't parse heredoc bodies: the opener we care about sits on the line
    before the body. Over-parsing a shell in a regex is how a guard starts lying.
    """
    out = []
    quote = None
    for ch in cmd:
        if quote:
            out.append(" " if ch != quote else ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def find_offenders(command):
    """Return [(cd_fragment, redirect_target)] when a relative write is gated behind a cd."""
    scrubbed = strip_quoted(command)
    cd_hit = CD_CHAIN.search(scrubbed)
    if not cd_hit:
        return []
    # Only look at what comes AFTER the cd chain. A redirect before it isn't gated by it.
    tail = scrubbed[cd_hit.end():]
    hits = []
    for m in REDIRECT.finditer(tail):
        target = m.group(2)
        # `2>&1`, `>&2` and friends are fd plumbing, not a file write.
        if target.startswith("&") or target.isdigit():
            continue
        hits.append((cd_hit.group(0).strip(), target))
    return hits


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
    data = json.loads(raw)
    if data.get("tool_name") != "Bash":
        return decide()
    command = (data.get("tool_input") or {}).get("command", "") or ""
    if BYPASS in command:
        return decide()
    hits = find_offenders(command)
    if not hits:
        return decide()
    cd_frag, target = hits[0]
    decide(
        "BLOCKED: this gates a WRITE behind a `cd` in the same && chain, which fails\n"
        "SILENTLY when the cd doesn't resolve where you expect.\n\n"
        "  %s ... >> %s\n\n"
        "What goes wrong:\n"
        "  1. The `cd` fails, `&&` short-circuits, and THE WRITE NEVER RUNS. The heredoc body\n"
        "     is swallowed by the shell as if it had been written.\n"
        "  2. Nothing reports it. A following `echo ok` prints ok, and a `git commit` on the\n"
        "     next line isn't part of the chain, so it still runs and commits without your file.\n\n"
        "Do this instead: absolute path, no cd.\n"
        "  cat >> /abs/path/to/file.md <<'EOF'\n"
        "  ...\n"
        "  EOF\n"
        "When a command must run elsewhere, don't gate a write on it: `git -C <dir> ...`,\n"
        "`npm --prefix <dir> ...`.\n\n"
        "Last resort, when you've verified the cd can't fail: include the token %s."
        % (cd_frag, target, BYPASS)
    )


# (expect_block, command, why)
CASES = [
    # --- must BLOCK ---
    (True, "cd docs/notes && cat >> log.md <<'EOF'\nx\nEOF", "append to a log behind a cd"),
    (True, "cd ../.. && cat >> docs/notes/log.md <<'E'\nx\nE", "cd that can land one level short"),
    (True, "cd site && npm run build && echo done > build.log", "a relative write later in the chain"),
    (True, "cd x && printf 'a' >> notes.txt", "printf redirect"),
    (True, "cd tools && python gen.py > out.json", "single `>` truncating write"),
    # --- must ALLOW: no write, so the short-circuit is harmless ---
    (False, "cd docs/notes && ls", "no write at all"),
    (False, "cd site && npm run check:all", "a gate, no redirect"),
    (False, "cd x && git status --short", "read-only"),
    # --- must ALLOW: the write doesn't depend on the cwd ---
    (False, "cd x && cat >> /home/user/project/log.md <<'E'\nx\nE", "absolute target"),
    (False, "cd x && echo hi > $LOGFILE", "variable-rooted target"),
    (False, "cd x && echo hi > ~/notes.txt", "home-rooted target"),
    # --- must ALLOW: the recommended shapes ---
    (False, "cat >> /abs/path/log.md <<'E'\nx\nE", "absolute append, no cd"),
    (False, "git -C /srv/repo add -A && git -C /srv/repo commit -q -m x", "no cd, no relative write"),
    (False, "npm run deploy > deploy.log 2>&1; echo \"EXIT=$?\" >> deploy.log", "no cd chain"),
    # --- must ALLOW: a semicolon doesn't short-circuit ---
    (False, "cd x; cat >> log.md <<'E'\nx\nE", "`;` runs the write regardless"),
    # --- must ALLOW: fd plumbing isn't a file write ---
    (False, "cd x && npm test 2>&1", "2>&1 is fd plumbing"),
    # --- must ALLOW: a `>` inside quotes is text ---
    (False, "cd x && echo 'a > b' && ls", "redirect character inside a quoted string"),
    # --- the deliberate bypass ---
    (False, "cd x && cat >> log.md <<'E'\nx\nE  # " + BYPASS, "the last-resort bypass"),
]


def selftest():
    failures = 0
    for expect_block, command, why in CASES:
        got = bool(find_offenders(command)) and BYPASS not in command
        ok = (got == expect_block)
        failures += not ok
        print("%-6s %-6s %s" % ("ok" if ok else "FAIL", "BLOCK" if expect_block else "allow", why))
    print("\n%d checks, %d failure(s)" % (len(CASES), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        main()
    except Exception as exc:  # fail OPEN, never wedge the agent's shell
        sys.stderr.write("guard_cd_chained_redirect: internal error, allowing (%s)\n" % exc)
        decide()
    sys.exit(0)
