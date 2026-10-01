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


def find_projects(projects_root: Path) -> list[Path]:
    """Every directory containing a project.yaml, at any depth -- this is
    deliberately depth-agnostic so flat (projects/foo/) and nested
    (projects/org/foo/) submissions are discovered identically."""
    return sorted({p.parent for p in projects_root.rglob("project.yaml")})


def validate_project(project_dir: Path, seen_names: dict[str, Path]) -> list[str]:
    errors = []
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
        all_errors.extend(validate_project(project_dir, seen_names))

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
