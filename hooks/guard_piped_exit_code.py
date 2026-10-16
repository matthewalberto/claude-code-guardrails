# -*- coding: utf-8 -*-
r"""Claude Code PreToolUse hook: refuse to pipe a gate, test or deploy command into a filter.

Why it exists
-------------
`npm run deploy | tail -60` looks like output hygiene. It isn't. Two things go wrong:

  * The pipeline's exit code is the FILTER's, which is almost always 0. A failed test suite or
    a deploy that stopped halfway reports success, and the agent writes up a success.
  * `tail` buffers until EOF, so a backgrounded run leaves an empty log for the whole run. That
    reads as "still running" rather than "nothing to see yet".

There was a written rule about this, loaded into every session. The agent broke it anyway, more
than once, including reporting a failing gate suite as passing. At the moment of typing, a pipe
to `tail` doesn't feel like a decision about exit codes, so the rule never gets consulted. A
mistake that repeats after it's written down needs a mechanical fix, so this hook removes the
opportunity instead of restating the rule.

What it blocks
--------------
A pipeline whose LEFT side is a command whose success is the point (a gate, a test suite, a
smoke test, a deploy, a push) feeding a filter that swallows the exit code (`tail`, `head`,
`grep`, `less`, `more`, `cat`, `sort`, `uniq`, `wc`).

Deliberately narrow. `ls | head`, `git log | head`, `grep -rn x | head` and other read-only
inspection are none of its business. A guard that fires on those gets bypassed by reflex.

It allows a pipeline that recovers the status (`set -o pipefail`, `PIPESTATUS`), because
blocking the right answer teaches people to route around the guard.

The way through
---------------
    npm run deploy > deploy.log 2>&1; echo "EXIT=$?" >> deploy.log

Then read the file. `tail -20 deploy.log` against a FILE isn't a pipeline, so it's allowed, and
it works while the command is still running. As a deliberate last resort, put the token
`piped-exit-ok` (or `piped-exit-code-ok`) in the command.

Contract: reads the hook JSON on stdin, writes a PreToolUse permissionDecision on stdout, always
exits 0. Fails OPEN: an internal error allows the command, so a bug here can never wedge the
agent's shell.

Wiring (settings.json, hooks.PreToolUse):
    { "matcher": "Bash",
      "hooks": [ { "type": "command", "command": "python /path/to/guard_piped_exit_code.py", "timeout": 15 } ] }

Test: python guard_piped_exit_code.py --selftest
"""

import json
import re
import sys

BYPASS = "piped-exit-ok"
# A second spelling is accepted because agents reached for it by instinct. A bypass token
# nobody can remember is a guard that gets worked around some other way.
BYPASS_ALT = "piped-exit-code-ok"

# Filters that swallow the left side's exit status. `tee` is left out on purpose: it keeps the
# output, and it's the usual sanctioned workaround.
SWALLOWERS = r"(?:tail|head|less|more|cat|sort|uniq|wc|fgrep|egrep|grep)"

# Constructs that genuinely RECOVER the left side's status.
RECOVERS_STATUS = re.compile(r"pipefail|PIPESTATUS", re.IGNORECASE)

# A command whose EXIT CODE is the point. Narrow by design.
LOADBEARING = [
    # npm/yarn/pnpm scripts that gate: deploy, check, test, smoke, lint, build, verify
    re.compile(r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?[\w:-]*"
               r"(?:deploy|check|test|smoke|gate|verif|lint|build|control|deploy:force)[\w:-]*"),
    # a node/python script that is itself a gate
    re.compile(r"\bnode\s+[^|]*\b(?:check|smoke|guard|verify|test|control)[\w.-]*\.(?:c?js|mjs)"),
    re.compile(r"\bpython[0-9.]*\s+[^|]*\b(?:check|guard|verify|test)[\w.-]*\.py"),
    re.compile(r"\b(?:pytest|jest|vitest|mocha)\b"),
    # the outward-facing ones
    re.compile(r"\bwrangler\b[^|]*\bdeploy\b"),
    re.compile(r"\bgit\s+push\b"),
]


def segments(command):
    """Split a command into pipeline stages, ignoring pipes inside quotes and `||`.

    A naive split on "|" cuts inside `grep 'a|b'`, which is how a guard starts firing on things
    it was never about.
    """
    out, cur, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            cur.append(ch)
            if ch == quote and command[i - 1] != "\\":
                quote = None
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch == "|":
            # `||` is a control operator, not a pipe. It doesn't swallow anything.
            if i + 1 < len(command) and command[i + 1] == "|":
                cur.append("||")
                i += 2
                continue
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur))
    return out


def strip_quoted(s):
    """Blank out quoted spans so quoted text is never read as a command.

    Without this, `grep -rn 'npm run deploy' . | head` would be blocked: the search pattern
    matches LOADBEARING even though nothing is being deployed. Characters become spaces rather
    than being removed, so word boundaries survive.
    """
    out, quote = [], None
    for ch in s:
        if quote:
            out.append(" " if ch != quote else ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def find_offenders(command):
    """Return a list of (left, right) pipeline pairs that lose a load-bearing exit code."""
    hits = []
    if RECOVERS_STATUS.search(command):
        return hits
    # `|&` is bash for `2>&1 |`: the same pipe.
    command = command.replace("|&", "|")
    # Each statement separately: `a; b | head` must not implicate `a`.
    for stmt in re.split(r";|&&|\n", command):
        segs = segments(stmt)
        if len(segs) < 2:
            continue
        for idx in range(len(segs) - 1):
            left, right = segs[idx].strip(), segs[idx + 1].strip()
            if not re.match(r"^" + SWALLOWERS + r"\b", right):
                continue
            if any(p.search(strip_quoted(left)) for p in LOADBEARING):
                hits.append((left[:90], right[:40]))
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
    if BYPASS in command or BYPASS_ALT in command:
        return decide()
    hits = find_offenders(command)
    if not hits:
        return decide()
    left, right = hits[0]
    decide(
        "BLOCKED: this pipes a command whose EXIT CODE you will report into `%s`, which\n"
        "swallows it and buffers the output until the process ends.\n\n"
        "  %s | %s\n\n"
        "Two things go wrong:\n"
        "  1. The pipeline's exit code is the FILTER's, effectively always 0, so a FAILED gate\n"
        "     or deploy reports success.\n"
        "  2. Nothing is readable until it finishes. A backgrounded run leaves an empty log,\n"
        "     which reads as 'still running' rather than 'buffered'.\n\n"
        "Do this instead:\n"
        "  <cmd> > out.log 2>&1; echo \"EXIT=$?\" >> out.log\n"
        "then `tail -20 out.log`. Reading a FILE isn't a pipeline, is allowed, and works\n"
        "while the command is still running. `set -o pipefail` is also accepted.\n\n"
        "Last resort, when the exit code genuinely doesn't matter: include the token %s."
        % (right.split()[0], left, right, BYPASS)
    )


CASES = [
    # --- must BLOCK: the shapes that actually happened, and their close relatives ---
    (True,  "npm run deploy 2>&1 | tail -60", "a deploy whose exit 0 was really tail's"),
    (True,  "python scripts/check-entities.py |& head -20", "`|&` is bash for `2>&1 |`"),
    (True,  "npm run deploy | tail -60", "a deploy that reported a failed chain as 0"),
    (True,  "npm run check:all 2>&1 | grep -iE 'FAIL'", "a gate suite reported as passing"),
    (True,  "npm run smoke:portal | tail -5", "a smoke suite's verdict"),
    (True,  "cd x && npm test | head -20", "a test run behind a cd"),
    (True,  "node scripts/check-entities.js | tail -3", "a gate script by name"),
    (True,  "node scripts/smoke-lineage.cjs 2>&1 | grep PASSED", "a smoke script by name"),
    (True,  "pytest | tail", "a bare test runner"),
    (True,  "wrangler pages deploy public --project-name x | tail -5", "the outward action itself"),
    (True,  "python scripts/check-index-size.py | head -2", "a check script"),
    # --- must ALLOW: the right answers ---
    (False, "set -o pipefail; npm run deploy 2>&1 | tail -60", "pipefail recovers the status"),
    (False, "npm run deploy 2>&1 | tail -60  # piped-exit-code-ok", "the alternate bypass spelling"),
    (False, "grep -rn 'npm run deploy' . | head", "the gating text is data inside a quoted pattern"),
    # --- must ALLOW: ordinary inspection, and the sanctioned way through ---
    (False, "ls -la | head -20", "listing a directory"),
    (False, "git log --oneline -20 | head -5", "reading history"),
    (False, "grep -rn 'foo' . | head -30", "a search"),
    (False, "cat deploy.log | tail -40", "reading a LOG is the recommended replacement"),
    (False, "tail -20 deploy.log", "no pipeline at all"),
    (False, "npm run deploy > deploy.log 2>&1; echo \"EXIT=$?\" >> deploy.log",
     "the shape this guard steers people to"),
    (False, "npm run map | head -5", "a report script, not a gate"),
    (False, "echo 'a|b' | grep a", "a pipe inside quotes must not be miscounted"),
    (False, "npm run check:all || echo failed", "`||` is a control operator, not a pipe"),
    (False, "npm run deploy > out.log 2>&1; tail -5 out.log", "run, then read the file"),
    (False, "npm run deploy | tail -5  # " + BYPASS, "the deliberate last-resort bypass"),
]


def selftest():
    failures = 0
    for expect_block, command, why in CASES:
        # Mirror main() exactly: a selftest that models the decision differently from the code
        # under test checks the wrong thing.
        got = (bool(find_offenders(command))
               and BYPASS not in command and BYPASS_ALT not in command)
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
        sys.stderr.write("guard_piped_exit_code: internal error, allowing (%s)\n" % exc)
        decide()
    sys.exit(0)
