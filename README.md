# claude-code-guardrails

Small [Claude Code](https://docs.claude.com/en/docs/claude-code) `PreToolUse` hooks that block mistakes a coding agent kept repeating. Each hook is one Python file with no dependencies, and each one carries its own self-test.

## Why it matters

- **The problem:** an agent that runs unattended will repeat a mistake its instructions already forbid, because the rule isn't front of mind at the moment it types the command. One printed API key has to be rotated. One hidden test failure ships a broken build.
- **What this saves:** each hook catches its mistake before the command runs, every time, and tells the agent the safe way to do the same thing. Nobody has to watch every session.
- **Where it came from:** every hook was built after the same mistake kept recurring in my own daily agent work, despite a written rule against it.

## Why hooks and not more rules

Every hook here started as a written rule. The rule was in the agent's instructions, sometimes loaded into every session, and the agent still broke it. Not because it ignored the rule, but because the rule never came to mind at the moment of typing. `npm test | tail` feels like tidying output, not like a decision about exit codes. `grep KEY settings.json` feels like an existence check, not like printing a secret.

A rule that has to be remembered at exactly the wrong moment won't get more reliable by being written louder. A hook runs before the tool call, every time, and doesn't need to be remembered. When it blocks, its message says what went wrong and shows the safe way to do the same thing, so the agent can recover in the same turn.

Each hook is deliberately narrow. A guard that fires on ordinary work gets bypassed by reflex, and then it protects nothing. That's why every self-test has two halves: the shapes that must be blocked, and the everyday commands that must still be allowed.

## The hooks

| Hook | Matcher | What it blocks |
|---|---|---|
| `guard_secret_print.py` | `Bash` | Printing a credential file (`.env`, `~/.claude/settings.json`, `*.pem`, service-account JSON) into the transcript. Allows `grep -c` and `grep -q`. |
| `guard_piped_exit_code.py` | `Bash` | Piping a test, gate or deploy command into `tail`, `head` or `grep`, which hides its exit code. Allows `set -o pipefail`. |
| `guard_cd_chained_redirect.py` | `Bash` | `cd dir && ... > relative/file`, where a failed `cd` silently skips the write. |
| `guard_heredoc_escapes.py` | `Bash` | Backslash escapes (`\n`, `\d`, Windows paths) inside a heredoc, `python -c`, `node -e` or `sed` script, where the shell mangles them. |
| `guard_commit_message_shape.py` | `Bash\|PowerShell` | A multi-line `git commit -m`, a PowerShell here-string passed to `-m`, or a backtick in a double-quoted PowerShell `-m`. |
| `guard_truncating_write.py` | `Bash\|PowerShell\|Write` | Opening an existing file with mode `"w"` (or `> file`, `Set-Content`), and Python scripts that read and rewrite the same file with no atomic replace. |

Each file's docstring tells the story of why it exists, what it deliberately doesn't block, and the way through.

## Install

Copy the `hooks/` folder somewhere stable, then add the hooks you want to `hooks.PreToolUse` in your Claude Code `settings.json` (user level is `~/.claude/settings.json`). Replace `/path/to/hooks` with the real folder. On Windows, forward slashes work in the path.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python /path/to/hooks/guard_secret_print.py", "timeout": 15 },
          { "type": "command", "command": "python /path/to/hooks/guard_piped_exit_code.py", "timeout": 15 },
          { "type": "command", "command": "python /path/to/hooks/guard_cd_chained_redirect.py", "timeout": 15 },
          { "type": "command", "command": "python /path/to/hooks/guard_heredoc_escapes.py", "timeout": 15 }
        ]
      },
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          { "type": "command", "command": "python /path/to/hooks/guard_commit_message_shape.py", "timeout": 15 }
        ]
      },
      {
        "matcher": "Bash|PowerShell|Write",
        "hooks": [
          { "type": "command", "command": "python /path/to/hooks/guard_truncating_write.py", "timeout": 15 }
        ]
      }
    ]
  }
}
```

You don't need all of them. Each one stands alone.

**Wire a hook only after its file exists at that path.** If the path is wrong, Python exits with code 2, and a `PreToolUse` hook that exits 2 blocks the tool call. A typo here would refuse every Bash command until you fix it. Run the self-test from the exact path first.

## Run the self-tests

One hook:

```
python hooks/guard_piped_exit_code.py --selftest
```

All of them (this is what CI runs):

```
python tests/run_all_selftests.py
```

Each self-test prints one line per case and exits nonzero if any case fails. The runner exits nonzero if any hook fails. Python 3.8 or newer, standard library only.

## Fail open, and the escape hatch

Every hook reads the hook JSON on stdin, writes a `permissionDecision` on stdout, and always exits 0. If a hook hits an internal error (bad JSON, an unexpected input shape, a bug), it allows the call. A guard that crashes must never wedge the agent's shell.

Every hook also has a bypass token, named in its docstring and in its deny message (for example `piped-exit-ok`). Putting the token in the command lets that one call through. It's meant as a deliberate last resort, and it's visible in the transcript, so you can see when it was used.

## License

MIT. See [LICENSE](LICENSE).

---

Built by [Matthew Alberto](https://github.com/matthewalberto). Need a version of this for your team or institution? Get in touch on [LinkedIn](https://www.linkedin.com/in/matthewalberto) or at [matthewalberto.com](https://matthewalberto.com).
