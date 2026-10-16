# -*- coding: utf-8 -*-
"""Run every hook's --selftest and exit nonzero if any of them fails.

Usage: python tests/run_all_selftests.py
"""

import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = sorted(glob.glob(os.path.join(ROOT, "hooks", "guard_*.py")))


def main():
    if not HOOKS:
        print("no hooks found under %s" % os.path.join(ROOT, "hooks"))
        return 1
    failed = []
    for hook in HOOKS:
        name = os.path.basename(hook)
        result = subprocess.run([sys.executable, "-I", hook, "--selftest"],
                                capture_output=True, text=True)
        summary = (result.stdout.strip().splitlines() or ["(no output)"])[-1]
        status = "PASS" if result.returncode == 0 else "FAIL"
        print("%-4s %-32s %s" % (status, name, summary))
        if result.returncode != 0:
            failed.append(name)
            sys.stdout.write(result.stdout)
            sys.stdout.write(result.stderr)
    print("\n%d hook(s), %d failed" % (len(HOOKS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
