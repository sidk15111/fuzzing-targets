#!/usr/bin/env python3
"""Works out which projects a change touches, from a git diff.

Executes nothing from the change: it only reads the list of changed paths
and checks which directories contain a project.yaml. That is why it is safe
to run first, before anything else, on an untrusted PR.

A "project" is the nearest directory, below projects/, that contains a
project.yaml -- at any depth, so flat (projects/foo) and nested
(projects/org/foo) layouts are treated identically.

Outputs (printed, and written to $GITHUB_OUTPUT when that is set):
  projects  JSON list of touched project directories
  orphans   JSON list of added/modified files under projects/ that belong
            to no project. Deleted files are never orphans.

Usage:
  detect_projects.py --base <sha>                  diff <sha>..HEAD
  detect_projects.py --base ""                     no base known -> HEAD~1..HEAD
  detect_projects.py --override projects/org/foo   skip the diff entirely
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

PROJECTS_DIR = "projects"
# Files that legitimately live directly under projects/ without being part
# of any project.
ORPHAN_ALLOWLIST = {"projects/.gitkeep", "projects/README.md"}
# A git ref we are willing to hand to `git diff`: a hex sha, or HEAD~N.
# Anything else (e.g. something starting with "-") could be read by git as
# an option rather than a revision.
SAFE_REV = re.compile(r"^([0-9a-fA-F]{4,64}|HEAD(~[0-9]+)?)$")


def fail(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def git_paths(root: Path, *args: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True
        ).stdout
    except subprocess.CalledProcessError as e:
        fail(f"git {' '.join(args[:3])} ... failed: {e.stderr.decode(errors='replace').strip()}")
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def find_project(path: str, root: Path):
    """Walk up from a changed path to the nearest directory holding a
    project.yaml, stopping before projects/ itself: a project.yaml sitting
    directly in projects/ would claim every file beneath it and make the
    orphan rule meaningless, so it is not allowed to count."""
    d = PurePosixPath(path).parent
    while d.parts and d.parts[0] == PROJECTS_DIR and str(d) != PROJECTS_DIR:
        if (root / d / "project.yaml").is_file():
            return str(d)
        d = d.parent
    return None


def detect(root: Path, base: str, head: str):
    if not base or set(base) == {"0"}:  # empty, or git's all-zeros "no previous commit"
        base = f"{head}~1"
    for rev in (base, head):
        if not SAFE_REV.match(rev):
            fail(f"refusing to use {rev!r} as a git revision")

    diff = ["diff", "--name-only", "-z", "--no-renames", base, head]
    changed = git_paths(root, *diff, "--", PROJECTS_DIR)
    deleted = set(git_paths(root, *diff[:2], "--diff-filter=D", *diff[2:], "--", PROJECTS_DIR))

    projects, orphans = set(), []
    for path in changed:
        proj = find_project(path, root)
        if proj:
            projects.add(proj)  # includes deletions inside a surviving project
        elif path not in deleted and path not in ORPHAN_ALLOWLIST:
            orphans.append(path)
    return sorted(projects), sorted(orphans)


def from_override(root: Path, raw: str):
    p = PurePosixPath(raw.strip().strip("/"))
    if p.parts[:1] != (PROJECTS_DIR,) or len(p.parts) < 2 or ".." in p.parts:
        fail(f"override {raw!r} must be a project directory below {PROJECTS_DIR}/")
    if not (root / p / "project.yaml").is_file():
        fail(f"override {raw!r}: no project.yaml in that directory")
    return [str(p)], []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="", help="base revision; empty means HEAD~1")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--override", default="", help="build exactly this project, skip the diff")
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    args = ap.parse_args()

    if args.override.strip():
        projects, orphans = from_override(args.root, args.override)
        print(f"Manual override: {projects[0]}")
    else:
        projects, orphans = detect(args.root, args.base, args.head)
        print(f"Affected project(s): {projects or 'none'}")
        if orphans:
            print(f"Files under {PROJECTS_DIR}/ that belong to no project: {orphans!r}")

    if args.github_output:
        with open(args.github_output, "a") as f:
            f.write(f"projects={json.dumps(projects)}\n")
            f.write(f"orphans={json.dumps(orphans)}\n")
    else:
        print(json.dumps({"projects": projects, "orphans": orphans}))


if __name__ == "__main__":
    main()
