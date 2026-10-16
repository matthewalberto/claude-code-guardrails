# -*- coding: utf-8 -*-
r"""Claude Code PreToolUse hook: refuse a `git commit -m` whose message argument is multi-line.

Why it exists
-------------
A written runbook already said: write the commit message to a file and use
`git commit -F <file>`, never a multi-line `-m` in either the Bash or the PowerShell tool. It said
so because the shape had already failed twice:

  * A PowerShell `@'...'@` here-string sent through the Bash tool was committed LITERALLY, the
    raw here-string syntax inside the commit message. It needed an --amend.
  * A backtick-laden here-string in the PowerShell tool reached git as MULTIPLE ARGS and failed
    with `fatal: cannot do a partial commit during a merge`, which reads like a staging problem
    and sends you hunting the wrong bug.

It failed a third time in a session that had just finished quoting that rule. A here-string
broke on the double quotes inside it and git got the body as pathspecs:
`error: pathspec 'ANY' did not match any file(s) known to git`. Each time the error names the
wrong thing. Three strikes on a written rule means it needs a mechanism instead.

What it blocks
--------------
  1. `git commit -m` (or `--message`) whose quoted argument CONTAINS A NEWLINE, in either tool.
  2. `git commit -m @'...` or `-m @"...`: a PowerShell here-string, multi-line by construction.
  3. PowerShell tool only: a DOUBLE-quoted -m argument containing a backtick. Backtick is
     PowerShell's escape character, so it's eaten before git sees it. Single-quoted PowerShell
     strings are literal and are left alone.

What it must not block (a guard that blocks ordinary commands gets bypassed):
  * `git commit -m "one line"`.
  * A multi-line COMMAND carrying a single-line -m (a try/finally block, say). The check reads
    the ARGUMENT, never the command.
  * `git commit -F msg.txt`, `git commit --amend --no-edit`.
  * A `-m` belonging to a LATER command (`git commit -F f && foo -m x`): scanning stops at the
    first unquoted ; | & or newline after `commit`.

The way through
---------------
Write the message with the Write tool, then `git commit -F <that file>`. As a deliberate last
resort, put the token `commit-message-shape-ok` in the command.

Contract: reads the hook JSON on stdin, writes a PreToolUse permissionDecision on stdout, always
exits 0. Fails OPEN: an internal error allows the command, so a bug here can never wedge the
agent's shell.

Wiring (settings.json, hooks.PreToolUse):
    { "matcher": "Bash|PowerShell",
      "hooks": [ { "type": "command", "command": "python /path/to/guard_commit_message_shape.py", "timeout": 15 } ] }

Test: python guard_commit_message_shape.py --selftest
"""

import json
import re
import sys

# `git`, any global flags (-C <path>, --no-pager, ...), then the `commit` subcommand.
GIT_COMMIT = re.compile(r"\bgit\b(?:\s+(?:-[A-Za-z]\s+\S+|--?[A-Za-z][^\s]*))*\s+commit\b")

# A -m / --message flag at a token boundary. --message=<msg> is handled separately.
MSG_FLAG = re.compile(r"(?:^|\s)(-m|--message)(?=\s)")
MSG_EQ = re.compile(r"(?:^|\s)--message=")

# End of the git-commit command: an unquoted separator.
SEPARATORS = ";|&\n"

BYPASS = "commit-message-shape-ok"


def read_quoted(command, i):
    """command[i] is an opening quote. Return (body, index_after_closing_quote).

    Inside double quotes a backslash-escaped quote doesn't close the string; inside single
    quotes nothing escapes. If the quote is never closed, return (body_to_end, len): the caller
    then sees no newline in a truncated body and allows, which is the safe direction.
    """
    quote = command[i]
    j = i + 1
    while j < len(command):
        c = command[j]
        if quote == '"' and c == "\\" and j + 1 < len(command):
            j += 2
            continue
        if c == quote:
            return command[i + 1:j], j + 1
        j += 1
    return command[i + 1:], len(command)


def message_args(command):
    """Yield (form, body) for every -m/--message argument of a `git commit` in `command`.

    form is 'quoted...' (body is the message) or 'herestring' (body is what follows @' or @").
    """
    for m in GIT_COMMIT.finditer(command):
        i = m.end()
        n = len(command)
        while i < n:
            c = command[i]
            if c in SEPARATORS:
                break                                  # this git commit is over
            if c in "'\"":
                _, i = read_quoted(command, i)          # step over an unrelated quoted arg
                continue
            eq = MSG_EQ.match(command, i) or (MSG_EQ.match(command, i - 1) if i else None)
            flag = MSG_FLAG.match(command, i) or (MSG_FLAG.match(command, i - 1) if i else None)
            if eq:
                j = eq.end()
                if j < n and command[j] in "'\"":
                    body, i = read_quoted(command, j)
                    yield "quoted", body
                    continue
                i = eq.end()
                continue
            if flag:
                j = flag.end()
                while j < n and command[j] in " \t":
                    j += 1
                if j + 1 < n and command[j] == "@" and command[j + 1] in "'\"":
                    yield "herestring", command[j:j + 60]
                    i = j + 2
                    continue
                if j < n and command[j] in "'\"":
                    body, i = read_quoted(command, j)
                    yield "quoted" + ("-double" if command[j] == '"' else "-single"), body
                    continue
                i = j
                continue
            i += 1


def find_offenders(command, tool_name):
    """Return (why, excerpt) for each bad message argument."""
    out = []
    for form, body in message_args(command):
        if form == "herestring":
            out.append(("a PowerShell here-string passed to -m", body.split("\n")[0][:80]))
        elif "\n" in body:
            out.append(("a -m argument spanning %d lines" % (body.count("\n") + 1),
                        body.split("\n")[0][:80]))
        elif form == "quoted-double" and tool_name == "PowerShell" and "`" in body:
            out.append(("a backtick inside a DOUBLE-quoted -m in the PowerShell tool "
                        "(backtick is PowerShell's escape character)", body[:80]))
    return out


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
    command = (payload.get("tool_input") or {}).get("command") or ""
    tool_name = payload.get("tool_name") or ""
    if BYPASS in command:
        return decide()

    offenders = find_offenders(command, tool_name)
    if not offenders:
        return decide()

    detail = []
    for why, excerpt in offenders[:3]:
        detail.append("  %s\n    starts: %s" % (why, excerpt))

    decide(
        "BLOCKED: this is a multi-line `git commit -m`, which doesn't survive the shell.\n"
        + "\n".join(detail)
        + "\n\nThis shape fails with MISLEADING errors:\n"
          "  * a here-string committed LITERALLY (needs --amend)\n"
          "  * the message reaching git as several args: 'fatal: cannot do a partial commit\n"
          "    during a merge', which reads like a staging bug\n"
          "  * the message reaching git as pathspecs: \"error: pathspec 'ANY' did not match\n"
          "    any file(s) known to git\"\n\n"
          "Do this instead:\n"
          "  1. Write the message with the Write tool, to a scratch file.\n"
          "  2. git commit -F <that file>\n\n"
          "A single-line -m is fine and isn't blocked. Last resort: include the token "
        + BYPASS + " in the command."
    )


NL = chr(10)
BT = chr(96)      # backtick, built functionally
Q = chr(39)

# (should_block, tool, command, why)
CASES = [
    # --- must BLOCK ---
    (True, "PowerShell",
     "git -C $repo commit -m @" + Q + NL + "line one" + NL + "line two" + NL + Q + "@",
     "a PowerShell here-string passed to -m"),
    (True, "Bash", 'git commit -m "subject' + NL + NL + 'body line"',
     "a plain multi-line -m in the Bash tool"),
    (True, "Bash", "git commit -m " + Q + "subject" + NL + "body" + Q,
     "single-quoted multi-line -m"),
    (True, "Bash", 'git -C "/srv/repo" commit --message="subject' + NL + 'body"',
     "--message= form with a newline"),
    (True, "PowerShell", 'git commit -m "fix the ' + BT + 'foo' + BT + ' helper"',
     "backtick in a double-quoted -m under PowerShell"),
    # --- must ALLOW (the half that keeps the guard usable) ---
    (False, "Bash", 'git commit -m "one clean line"', "the common case"),
    (False, "PowerShell", 'git commit -m "fix the thing"', "common case under PowerShell"),
    (False, "PowerShell", "git commit -m " + Q + "fix the " + BT + "foo" + BT + " helper" + Q,
     "backticks are LITERAL in a single-quoted PowerShell string"),
    (False, "Bash", 'git commit -m "fix the ' + BT + 'foo' + BT + ' helper"',
     "backticks under Bash aren't this failure mode"),
    (False, "PowerShell",
     "$lock = Get-Lock" + NL + "try {" + NL
     + '  git -C $repo commit -m "one line"' + NL + "} finally { Release-Lock $lock }",
     "a MULTI-LINE COMMAND with a single-line -m"),
    (False, "Bash", "git commit -F /tmp/msg.txt", "the prescribed form"),
    (False, "Bash", "git commit --amend --no-edit", "no -m at all"),
    (False, "Bash", "git commit -F f.txt && echo done -m x",
     "a -m belonging to a LATER command isn't attributed to the commit"),
    (False, "Bash", "git status --short", "not a commit"),
    (False, "Bash", 'git commit -m "subject" ' + BYPASS, "the deliberate bypass"),
]


def selftest():
    failures = 0
    for expect_block, tool, command, why in CASES:
        got = bool(find_offenders(command, tool)) and BYPASS not in command
        ok = (got == expect_block)
        failures += not ok
        print("%-6s %-6s %-6s %s" % ("ok" if ok else "FAIL", tool[:6],
                                     "BLOCK" if expect_block else "allow", why))
    print("\n%d checks, %d failure(s)" % (len(CASES), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        main()
    except Exception as exc:  # fail OPEN, never wedge the agent's shell
        sys.stderr.write("guard_commit_message_shape: internal error, allowing (%s)\n" % exc)
        decide()
    sys.exit(0)
