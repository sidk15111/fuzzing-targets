#!/usr/bin/env python3
"""Validates submissions under a fuzzing-targets checkout's projects/ tree.

Deliberately does not execute anything a submitter wrote (no Dockerfile,
no build.sh) -- it only inspects file presence and project.yaml content,
which is why it is safe to run automatically on every PR before any human
has reviewed the submission.

Two modes:
  whole tree (default)   every project under --projects-root. This is the
                         "is main healthy?" question, for scheduled runs.
  scoped (--only-json)   only the listed projects. This is the "is THIS
                         change valid?" question, for PRs and merges.
                         `--only-json '[]'` means "validate nothing" (but
                         --orphans-json is still checked).

In both modes project names are checked for uniqueness against EVERY
project, because a new project can collide with one the change didn't touch.
A project the change didn't touch whose project.yaml is unreadable is
skipped by that check, not blamed on this change.

Usage:
  validate_submission.py --projects-root projects
  validate_submission.py --projects-root projects \\
      --only-json '["projects/acme/foo"]' --orphans-json '[]'

Exits 0 on success. Exits 1 and prints every problem found (not just the
first) otherwise, so it can all be fixed in one pass.
"""
import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: this script requires PyYAML (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

REQUIRED_FIELDS = {
    "name": str,
    "language": str,
    "main_repo": str,
    "fuzzing_engines": list,
    "sanitizers": list,
    "fuzz_targets": list,
    # "maintainers": list,  # optional for now
}
NAME_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REQUIRED_SIBLING_FILES = ["Dockerfile", "build.sh"]
# Project directory paths flow into shell commands later -- including over
# SSH on the build bot -- so anything outside a conservative character set
# is rejected here rather than trusted downstream.
PROJECT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
DICT_ENTRY_PATTERN = re.compile(r'^([A-Za-z0-9_]+=)?".*"$')


def fatal(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_json_list(flag: str, raw):
    """None / empty string -> None (flag not given). Otherwise a list of str."""
    if raw is None or raw.strip() == "":
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as e:
        fatal(f"{flag} is not valid JSON: {e}")
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        fatal(f"{flag} must be a JSON list of strings")
    return value


def find_projects(projects_root: Path) -> list[Path]:
    """Every directory containing a project.yaml, at any depth -- depth-agnostic
    so flat (projects/foo/) and nested (projects/org/foo/) are found alike."""
    return sorted({p.parent for p in projects_root.rglob("project.yaml")})


def build_name_index(projects_root: Path) -> dict[str, list[Path]]:
    """name -> every project directory claiming it, across the WHOLE tree."""
    index: dict[str, list[Path]] = {}
    for yaml_path in sorted(projects_root.rglob("project.yaml")):
        try:
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue  # reported when THAT project is validated, not here
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            index.setdefault(data["name"], []).append(yaml_path.parent)
    return index


def resolve_scoped(projects_root: Path, only: list[str]):
    errors, dirs = [], []
    root_resolved = projects_root.resolve()
    for raw in only:
        try:
            rel = Path(raw).resolve().relative_to(root_resolved)
        except ValueError:
            errors.append(f"{raw!r}: not inside {projects_root}")
            continue
        d = projects_root / rel
        if not (d / "project.yaml").is_file():
            errors.append(f"{raw!r}: no project.yaml in that directory")
            continue
        dirs.append(d)
    return sorted(set(dirs)), errors


def validate_dict_file(dict_path: Path) -> list[str]:
    """Each non-comment, non-blank line must look like libFuzzer's dictionary
    format: "token" or name="token". Doesn't validate escape sequences inside
    the string -- just catches the common mistake of a bare, unquoted line."""
    errors = []
    with open(dict_path) as f:
        for lineno, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not DICT_ENTRY_PATTERN.match(stripped):
                errors.append(
                    f"{dict_path}:{lineno}: not a valid dictionary entry "
                    f'(expected "token" or name="token"): {stripped!r}'
                )
    return errors


def validate_project(
    project_dir: Path,
    projects_root: Path,
    name_index: dict[str, list[Path]],
    scoped: bool,
) -> list[str]:
    errors = []
    rel = project_dir.relative_to(projects_root)

    if rel == Path("."):
        return [
            f"{project_dir}/project.yaml: a project.yaml directly inside projects/ "
            f"is not allowed -- it would claim every project beneath it"
        ]

    rel_path = rel.as_posix()
    if not PROJECT_PATH_PATTERN.match(rel_path):
        errors.append(
            f"{project_dir}: directory path {rel_path!r} contains characters "
            f"outside [A-Za-z0-9._-] -- rejected because project paths are "
            f"passed to shell commands downstream"
        )
    yaml_path = project_dir / "project.yaml"

    for sibling in REQUIRED_SIBLING_FILES:
        if not (project_dir / sibling).is_file():
            errors.append(f"{project_dir}: missing required file '{sibling}'")

    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        errors.append(f"{yaml_path}: not valid YAML ({e})")
        return errors

    if not isinstance(data, dict):
        errors.append(f"{yaml_path}: top level must be a mapping, see templates/project.yaml")
        return errors

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in data:
            errors.append(f"{yaml_path}: missing required field '{field}'")
        elif not isinstance(data[field], expected_type):
            errors.append(
                f"{yaml_path}: field '{field}' must be a {expected_type.__name__}, "
                f"got {type(data[field]).__name__}"
            )
        elif expected_type is list and len(data[field]) == 0:
            errors.append(f"{yaml_path}: field '{field}' must not be empty")

    name = data.get("name")
    if isinstance(name, str):
        if not NAME_PATTERN.match(name):
            errors.append(
                f"{yaml_path}: 'name: {name}' -- must be lowercase letters, "
                f"digits, and hyphens only"
            )
        else:
            owners = name_index.get(name, [])
            others = [p for p in owners if p != project_dir]
            # Whole-tree mode sees every collision from both sides; report it
            # once, against the later project. Scoped mode always reports it
            # against the project this change touched.
            if others and (scoped or project_dir != min(owners)):
                errors.append(
                    f"{yaml_path}: 'name: {name}' is also claimed by "
                    f"{', '.join(str(p) for p in others)} -- names must be unique "
                    f"across the whole repo regardless of folder path"
                )

    # Seed folders and .dict files only matter if they match a declared fuzz
    # target: otherwise they are never attached to anything build.sh produces,
    # and nothing else would ever notice.
    fuzz_targets = data.get("fuzz_targets")
    if isinstance(fuzz_targets, list):
        declared = set(fuzz_targets)
        seeds_dir = project_dir / "seeds"
        if seeds_dir.is_dir():
            for seed_subdir in sorted(seeds_dir.iterdir()):
                if seed_subdir.is_dir() and seed_subdir.name not in declared:
                    errors.append(
                        f"{seed_subdir}: seed directory name doesn't match any "
                        f"entry in this project's fuzz_targets ({sorted(declared)}) "
                        f"-- these seeds will never be zipped into any fuzzer's "
                        f"build output"
                    )
        for dict_file in sorted(project_dir.glob("*.dict")):
            if dict_file.stem not in declared:
                errors.append(
                    f"{dict_file}: dictionary name doesn't match any entry "
                    f"in this project's fuzz_targets ({sorted(declared)}) "
                    f"-- it will never be attached to any fuzzer's build output"
                )
            errors.extend(validate_dict_file(dict_file))

    return errors


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--projects-root", type=Path, required=True)
    parser.add_argument("--only-json", default=None,
                        help="JSON list of project dirs to validate; omit/empty = whole tree")
    parser.add_argument("--orphans-json", default=None,
                        help="JSON list of files under projects/ that belong to no project")
    args = parser.parse_args()

    root = args.projects_root
    if not root.is_dir():
        fatal(f"{root} does not exist or is not a directory")

    only = parse_json_list("--only-json", args.only_json)
    orphans = parse_json_list("--orphans-json", args.orphans_json) or []

    all_errors: list[str] = []
    name_index = build_name_index(root)

    if only is None:
        projects, scoped = find_projects(root), False
    else:
        projects, scope_errors = resolve_scoped(root, only)
        all_errors.extend(scope_errors)
        scoped = True

    for project_dir in projects:
        all_errors.extend(validate_project(project_dir, root, name_index, scoped))

    for path in orphans:
        all_errors.append(
            f"{path}: a file under projects/ that belongs to no project -- it needs "
            f"a project.yaml in its own folder or a parent folder (below projects/)"
        )

    if all_errors:
        print(f"Validation failed -- {len(all_errors)} issue(s) found:\n", file=sys.stderr)
        for err in all_errors:
            # One error per line, so a hostile filename can't start a fresh
            # line of its own (e.g. with a GitHub "::" workflow command).
            print("  - " + err.replace("\r", "\\r").replace("\n", "\\n"), file=sys.stderr)
        sys.exit(1)

    mode = "scoped" if scoped else "whole tree"
    if not projects:
        print(f"Nothing to validate ({mode}).")
    else:
        print(f"{len(projects)} project(s) passed validation ({mode}):")
        for project_dir in projects:
            print(f"  - {project_dir}")


if __name__ == "__main__":
    main()
