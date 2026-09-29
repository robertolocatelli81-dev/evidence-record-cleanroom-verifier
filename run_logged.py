#!/usr/bin/env python3
"""run_logged.py — run a command and write a HEADED log: command, cwd, interpreter, date (from the
system clock), exit code, then the full stdout+stderr. Usage:
    python3 run_logged.py <logfile> -- <cmd> [args...]
"""
import datetime
import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print(__doc__)
        return 2
    log, cmd = sys.argv[1], sys.argv[3:]
    started = datetime.datetime.now(datetime.timezone.utc).astimezone()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ended = datetime.datetime.now(datetime.timezone.utc).astimezone()
    interp = subprocess.run([cmd[0], "--version"], capture_output=True, text=True).stdout.strip() if os.path.basename(cmd[0]).startswith("python") else ""
    # paths are shown relative to the repository root: published logs must carry no machine-specific paths
    shown = [os.path.basename(cmd[0])] + [os.path.relpath(a) if os.path.exists(a) else a for a in cmd[1:]]
    head = [
        "=== run_logged header ===",
        f"cmd      : {' '.join(shown)}",
        "cwd      : . (repository root)",
        f"interp   : {interp}  (wrapper sys.version: {sys.version.split()[0]})",
        f"started  : {started.isoformat(timespec='seconds')}",
        f"ended    : {ended.isoformat(timespec='seconds')}",
        f"exit     : {proc.returncode}",
        "=== stdout ===",
    ]
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(head) + "\n" + proc.stdout + "=== stderr ===\n" + proc.stderr)
    sys.stdout.write("\n".join(head) + "\n" + proc.stdout + proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
