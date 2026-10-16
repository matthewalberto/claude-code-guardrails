# -*- coding: utf-8 -*-
r"""Claude Code PreToolUse hook: refuse a shell command that would PRINT a credential file's contents.

Why it exists
-------------
My agents run with real credentials on the machine (API keys in the Claude Code settings file, .env
files, service-account JSON). A written rule said "never grep or cat a secrets file to check whether a
key exists; those tools can't answer yes or no without printing the value". The agent broke that rule
anyway, more than once, because `grep KEY file` reads as an existence check, not as a decision about
what gets printed. The rule was never consulted at the moment of typing.

A mistake that repeats after it is written down needs a mechanical fix, not more instructions. This hook
is that fix: it runs before every Bash tool call and denies the ones that would put a secret into the
transcript, with a message that shows the safe way to ask the same question.

What it blocks
--------------
A content-printing command (grep/rg/cat/type/head/tail/sed/awk/findstr/Get-Content/Select-String and
friends) aimed at a file that holds credentials (~/.claude/settings.json, .env, .dev.vars, keys/*,
*.pem, service-account and credentials JSON) when its output would reach the transcript: it is the last
stage of the pipeline, or is followed only by display filters (head, tail, cut, sed, ...).

Deliberately narrow. It allows:
  * grep -c / -q / -l / -L (count, quiet, list files: value-free by construction);
  * a pipeline ending in a real transformer (wc, python, node, jq), which may print only a boolean;
  * .env.example and other templates, ls, wc, stat, git, or a script that reads the file itself.

Escape hatch: include the token `secret-print-ok` in the command.

Contract: reads the hook JSON on stdin, writes a PreToolUse permissionDecision on stdout, always exits 0.
Fails OPEN: an internal error allows the command, so a bug here can never wedge the agent's shell.

Wiring (settings.json, hooks.PreToolUse):
    { "matcher": "Bash",
      "hooks": [ { "type": "command", "command": "python /path/to/guard_secret_print.py", "timeout": 15 } ] }

Test: python guard_secret_print.py --selftest
"""

import json
import re
import sys

BYPASS = "secret-print-ok"

# Commands that print file content to stdout.
PRINTERS = {"grep", "egrep", "fgrep", "rg", "ag", "cat", "type", "head", "tail", "sed", "awk",
            "findstr", "get-content", "gc", "select-string", "sls", "more", "less", "nl", "bat", "tac"}
GREP_FAMILY = {"grep", "egrep", "fgrep", "rg", "ag", "select-string", "sls", "findstr"}

# Flags that make a grep-family command's output value-free: count, quiet, list files.
QUIET_FLAG = re.compile(r"^(?:-[A-Za-z]*[cqlL][A-Za-z]*|--count|--quiet|--silent|--files-with-matches|"
                        r"--files-without-match|-quiet|-list)$", re.IGNORECASE)

# Later pipeline stages that still put the (filtered) content in front of the reader.
DISPLAY_FILTERS = {"head", "tail", "cut", "sed", "awk", "tr", "sort", "uniq", "cat", "less", "more",
                   "nl", "tee", "grep", "egrep", "fgrep", "rg", "select-string", "sls", "out-string",
                   "select-object", "format-list", "format-table", "fl", "ft"}

# Paths that hold credentials. `.env.example`, `.env.sample` and `.env.template` are templates.
SECRET_PATH = re.compile(
    r"(?:"
    r"\.claude[/\\]+settings(?:\.local)?\.json"
    r"|\.claude\.json"
    r"|(?:^|[/\\\s\"'=])\.env(?![.\w-]*(?:example|sample|template))(?:\.[\w-]+)?(?=$|[\s\"'|;&])"
    r"|\.dev\.vars"
    r"|(?:^|[/\\\s\"'])keys[/\\]+[\w.-]+"
    r"|[\w.-]*(?:service[-_]?account|credentials?|client[-_]?secret)[\w.-]*\.json"
    r"|[\w.-]+\.pem"
    r")",
    re.IGNORECASE)


def segments(command):
    """Split a command into pipeline stages, ignoring pipes inside quotes and `||`."""
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


def tokens(seg):
    return re.findall(r"\"[^\"]*\"|'[^']*'|\S+", seg)


def cmd_name(seg):
    """First real word of a stage: skips VAR=x prefixes, `sudo`, and a directory prefix."""
    for tok in tokens(seg):
        t = tok.strip("\"'")
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in ("sudo", "time", "command", "&", "$(", "("):
            continue
        return re.split(r"[/\\]", t)[-1].lower()
    return ""


def is_quiet_grep(seg):
    return cmd_name(seg) in GREP_FAMILY and any(QUIET_FLAG.match(t.strip("\"'")) for t in tokens(seg)[1:])


def find_offenders(command):
    """Return (printer_stage, path_match) pairs whose output would reach the transcript."""
    hits = []
    command = command.replace("|&", "|")
    for stmt in re.split(r";|&&|\n", command):
        segs = segments(stmt)
        for idx, seg in enumerate(segs):
            if cmd_name(seg) not in PRINTERS or is_quiet_grep(seg):
                continue
            m = SECRET_PATH.search(seg)
            if not m:
                continue
            later = segs[idx + 1:]
            # Output reaches the reader only if every later stage is a display filter...
            if any(cmd_name(s) and cmd_name(s) not in DISPLAY_FILTERS for s in later):
                continue
            # ...and none of them is a grep in count or quiet mode.
            if any(is_quiet_grep(s) for s in later):
                continue
            hits.append((seg.strip()[:90], m.group(0).strip()))
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
    stage, path = hits[0]
    decide(
        "BLOCKED: this prints the CONTENTS of a file that holds credentials into the transcript.\n\n"
        "  %s\n  (matched: %s)\n\n"
        "`grep KEY file` reads as an existence check, but grep, cat, head, sed and friends cannot say\n"
        "yes or no without also returning the value. A value that reaches the transcript has to be rotated.\n\n"
        "Ask a question whose answer cannot contain the secret:\n"
        "  grep -c \"KEY_NAME\" <file>          -> 0 or 1 (count, no line printed)\n"
        "  grep -q \"KEY_NAME\" <file> && echo present\n"
        "  list the key NAMES only, with a script that never prints a value\n\n"
        "Last resort, when you are sure the output holds no secret: include the token %s."
        % (stage, path, BYPASS)
    )


CASES = [
    # --- must BLOCK: the shapes that actually happened, and their close relatives ---
    (True,  "grep -n \"API_KEY_PROVIDER\" -r ~/.claude/settings.json | cut -c1-60", "presence check piped to cut"),
    (True,  "grep -i mailer ~/.claude/settings.json", "presence check that prints matching lines"),
    (True,  "grep KEY /home/me/.claude/settings.json | head -2", "a display filter after the grep"),
    (True,  "cat ~/.claude/settings.json", "the whole settings file"),
    (True,  "type %USERPROFILE%\\.claude\\settings.json", "cmd's cat"),
    (True,  "Get-Content $env:USERPROFILE\\.claude\\settings.json", "PowerShell's cat"),
    (True,  "sed -n 1,5p tools/mail/.env", "a .env by sed"),
    (True,  "head -3 .dev.vars", "the wrangler local secrets file"),
    (True,  "cat keys/drive-oauth.json", "a key file under keys/"),
    (True,  "cat service-account-prod.json | head -5", "a service-account key"),
    # --- must ALLOW: the value-free ways through, and ordinary inspection ---
    (False, "grep -c \"API_KEY_PROVIDER\" ~/.claude/settings.json", "count mode: 0 or 1, no line printed"),
    (False, "grep -q API_KEY ~/.claude/settings.json && echo present", "quiet mode"),
    (False, "grep -l API_KEY ~/.claude/settings.json", "list-files mode prints the path, not the line"),
    (False, "grep -rn \"settings\" .claude/commands", "a directory of command files, not the settings file"),
    (False, "cat .env.example", "a template holds no secret"),
    (False, "cat README.md | head -5", "an ordinary file"),
    (False, "ls -la ~/.claude/settings.json", "listing, not reading"),
    (False, "wc -l ~/.claude/settings.json", "a line count"),
    (False, "node scripts/list-key-names.js ~/.claude/settings.json", "a script that reads the file itself"),
    (False, "cat ~/.claude/settings.json | python check_keys.py", "piped into a real transformer"),
    (False, "grep KEY ~/.claude/settings.json | wc -l", "a count of matching lines"),
    (False, "git diff -- docs/log.md", "unrelated"),
    (False, "grep -n KEY ~/.claude/settings.json  # " + BYPASS, "the deliberate last-resort bypass"),
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
        sys.stderr.write("guard_secret_print: internal error, allowing (%s)\n" % exc)
        decide()
    sys.exit(0)
