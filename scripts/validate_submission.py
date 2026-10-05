#!/usr/bin/env python3
"""Validates every project under a fuzzing-targets checkout's projects/ tree.

Deliberately does not execute anything a submitter wrote (no Dockerfile,
no build.sh) -- this only inspects file presence and project.yaml content,
which is why it's safe to run automatically and unattended on every PR,
before any human has reviewed the submission.

Usage:
    python3 validate_submission.py --projects-root /path/to/fuzzing-targets/projects

Exits 0 and prints a summary if everything passes. Exits 1 and prints
every problem found (not just the first) otherwise, so a submitter or
reviewer can fix everything in one pass rather than one-error-at-a-time.
"""
import argparse
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


def find_projects(projects_root: Path) -> list[Path]:
    """Every directory containing a project.yaml, at any depth -- this is
    deliberately depth-agnostic so flat (projects/foo/) and nested
    (projects/org/foo/) submissions are discovered identically."""
    return sorted({p.parent for p in projects_root.rglob("project.yaml")})


DICT_ENTRY_PATTERN = re.compile(r'^([A-Za-z0-9_]+=)?".*"$')


def validate_dict_file(dict_path: Path) -> list[str]:
    """Checks each non-comment, non-blank line matches libFuzzer's own
    dictionary format: "token" or name="token". Doesn't fully validate
    escape sequences inside the string -- just catches the common
    mistake of a bare, unquoted line."""
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
    project_dir: Path, seen_names: dict[str, Path], projects_root: Path
) -> list[str]:
    errors = []

    rel_path = project_dir.relative_to(projects_root).as_posix()
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
        elif name in seen_names:
            errors.append(
                f"{yaml_path}: 'name: {name}' collides with the project at "
                f"{seen_names[name]} -- names must be unique across the whole "
                f"repo regardless of folder path"
            )
        else:
            seen_names[name] = project_dir

    # If seeds/ exists, every subdirectory under it should correspond to a
    # declared fuzz target -- catches a typo'd seed folder that would
    # otherwise silently never get zipped into any *_seed_corpus.zip and
    # never reach a fuzzer at all, with nothing else likely to notice.
    fuzz_targets = data.get("fuzz_targets")
    seeds_dir = project_dir / "seeds"
    if isinstance(fuzz_targets, list) and seeds_dir.is_dir():
        declared = set(fuzz_targets)
        for seed_subdir in seeds_dir.iterdir():
            if seed_subdir.is_dir() and seed_subdir.name not in declared:
                errors.append(
                    f"{seed_subdir}: seed directory name doesn't match any "
                    f"entry in this project's fuzz_targets ({sorted(declared)}) "
                    f"-- these seeds will never be zipped into any fuzzer's "
                    f"build output"
                )

    # Same reasoning, same mechanism, for .dict files -- a name that
    # doesn't match any declared fuzz target means it's dead weight,
    # never attached to anything build.sh actually produces. Also check
    # the file's own format, since a malformed dict is accepted silently
    # by libFuzzer at fuzz time (it just gets ignored) rather than erroring
    # -- this is the only point in the pipeline where a typo here would
    # ever surface at all.
    if isinstance(fuzz_targets, list):
        declared = set(fuzz_targets)
        for dict_file in sorted(project_dir.glob("*.dict")):
            if dict_file.stem not in declared:
                errors.append(
                    f"{dict_file}: dictionary name doesn't match any entry "
                    f"in this project's fuzz_targets ({sorted(declared)}) "
                    f"-- it will never be attached to any fuzzer's build "
                    f"output"
                )
            errors.extend(validate_dict_file(dict_file))

    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--projects-root",
        type=Path,
        required=True,
        help="Path to the projects/ directory of a fuzzing-targets checkout",
    )
    args = parser.parse_args()

    if not args.projects_root.is_dir():
        print(f"ERROR: {args.projects_root} does not exist or is not a directory", file=sys.stderr)
        sys.exit(1)

    projects = find_projects(args.projects_root)
    if not projects:
        print("No projects found -- nothing to validate.")
        return

    seen_names: dict[str, Path] = {}
    all_errors: list[str] = []
    for project_dir in projects:
        all_errors.extend(validate_project(project_dir, seen_names, args.projects_root))

    if all_errors:
        print(f"Validation failed -- {len(all_errors)} issue(s) found:\n", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print(f"All {len(projects)} project(s) passed validation:")
    for project_dir in projects:
        print(f"  - {project_dir}")


if __name__ == "__main__":
    main()
