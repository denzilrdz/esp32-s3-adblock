"""PlatformIO pre-script: writes fw_build.h with FW_BUILD, the short git commit of
the build (GET /api/health "build"), "+dirty" when tracked files are modified.

The header lives in the build directory (not tracked), is rewritten only when the
value changes, and only main.cpp includes it: a new commit recompiles one file, not
the whole firmware (a -D flag would). Without git (a source tarball) it is "unknown".
"""

import os
import subprocess

Import("env")  # noqa: F821  (provided by PlatformIO/SCons)


def git(*args):
    try:
        return subprocess.run(
            ["git", *args],
            cwd=env.subst("$PROJECT_DIR"),  # noqa: F821
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def build_id():
    commit = git("rev-parse", "--short=7", "HEAD")
    if not commit or not all(c in "0123456789abcdef" for c in commit):
        return "unknown"
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return commit + ("+dirty" if dirty else "")


out_dir = os.path.join(env.subst("$BUILD_DIR"), "fw_build")  # noqa: F821
os.makedirs(out_dir, exist_ok=True)
path = os.path.join(out_dir, "fw_build.h")
text = '#pragma once\n#define FW_BUILD "%s"\n' % build_id()
try:
    with open(path, encoding="utf-8") as f:
        current = f.read()
except OSError:
    current = ""
if current != text:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
env.Append(CPPPATH=[out_dir])  # noqa: F821
