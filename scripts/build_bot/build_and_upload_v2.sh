#!/bin/bash
set -e

usage() {
  cat <<EOF
Usage: $0 --repo-url URL --project-path PATH --bucket GCS_BUCKET [options]

Required:
  --repo-url URL        Git URL of the fuzzing-targets monorepo
  --project-path PATH   Path within that repo to this project's folder,
                         e.g. projects/mosip/id-repository -- this is what
                         tells the script which submission to build, since
                         one repo now holds many projects
  --bucket GCS_BUCKET   Destination bucket, e.g. gs://my-fuzz-builds

Optional:
  --oss-fuzz-dir PATH   Existing oss-fuzz checkout
                         (default: /opt/build-tools/oss-fuzz)
  --workspace PATH      Where to clone/update the monorepo
                         (default: /opt/build-tools/fuzzing-targets)

Everything else -- project name, engines, sanitizers, which fuzz targets
to check_build -- comes from that project's own project.yaml. This script
never takes those as flags; Phase 2's validate_submission.py already
guarantees project.yaml has them by the time a submission reaches here.
EOF
  exit 1
}

OSS_FUZZ_DIR="/opt/build-tools/oss-fuzz"
WORKSPACE="/opt/build-tools/fuzzing-targets"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --project-path) PROJECT_PATH="$2"; shift 2 ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --oss-fuzz-dir) OSS_FUZZ_DIR="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "$REPO_URL" || -z "$PROJECT_PATH" || -z "$BUCKET" ]] && usage

if [ -d "$WORKSPACE/.git" ]; then
  git -C "$WORKSPACE" pull
else
  git clone "$REPO_URL" "$WORKSPACE"
fi

PROJECT_DIR="$WORKSPACE/$PROJECT_PATH"
[ -f "$PROJECT_DIR/project.yaml" ] || { echo "FATAL: no project.yaml at $PROJECT_DIR"; exit 1; }

# One python call reads name/engines/sanitizers/fuzz_targets at once and
# emits them as bash array assignments, rather than four separate parses.
eval "$(python3 - "$PROJECT_DIR/project.yaml" <<'PYEOF'
import sys, yaml, shlex
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
print(f"PROJECT={shlex.quote(data['name'])}")
print(f"ENGINES=({' '.join(shlex.quote(e) for e in data['fuzzing_engines'])})")
print(f"SANITIZERS=({' '.join(shlex.quote(s) for s in data['sanitizers'])})")
print(f"FUZZ_TARGETS=({' '.join(shlex.quote(t) for t in data['fuzz_targets'])})")
PYEOF
)"

# REVISION is a build timestamp, not a commit count -- see prior notes on
# why (upstream repos cloned inside a project's own Dockerfile are
# versioned independently of this monorepo's own history).
REVISION=$(date -u +%Y%m%d%H%M%S)
HARNESS_REPO_SHA=$(git -C "$WORKSPACE" rev-parse HEAD)

# Symlink just this project's own folder in -- not the whole monorepo --
# matching the flat projects/<name> layout infra/helper.py expects.
PROJECT_LINK="$OSS_FUZZ_DIR/projects/$PROJECT"
[ -e "$PROJECT_LINK" ] || ln -s "$PROJECT_DIR" "$PROJECT_LINK"

cd "$OSS_FUZZ_DIR"

for ENGINE in "${ENGINES[@]}"; do
  for SANITIZER in "${SANITIZERS[@]}"; do

    docker build --no-cache -t "gcr.io/oss-fuzz/$PROJECT" "projects/$PROJECT/"
    python3 infra/helper.py build_fuzzers --clean \
      --sanitizer "$SANITIZER" --engine "$ENGINE" "$PROJECT"

    # Gate before anything gets uploaded: every declared fuzz target has
    # to pass check_build, or this whole engine/sanitizer combo is a
    # failed build -- matches the "build, check_build all of them, only
    # then upload, or fail out and report" requirement from the start.
    for TARGET in "${FUZZ_TARGETS[@]}"; do
      echo "check_build: $PROJECT / $ENGINE-$SANITIZER / $TARGET"
      if ! python3 infra/helper.py check_build "$PROJECT" "$TARGET"; then
        echo "FAILED: $TARGET did not pass check_build -- not uploading $PROJECT/$ENGINE-$SANITIZER"
        echo "::error::$TARGET did not pass check_build ($PROJECT, $ENGINE-$SANITIZER)"
        exit 1
      fi
    done

    OUT_DIR="$OSS_FUZZ_DIR/build/out/$PROJECT"
    ZIP_NAME="${PROJECT}-${ENGINE}-${SANITIZER}-${REVISION}.zip"
    SRCMAP_NAME="${PROJECT}-${ENGINE}-${SANITIZER}-${REVISION}.srcmap.json"

    # Base srcmap entry: this monorepo's own commit. If the project's own
    # build.sh dropped a SRCMAP_EXTRA.json into $OUT (only needed for
    # projects that clone a third-party repo inside their own Dockerfile,
    # e.g. id-repository), merge it in via python for valid JSON rather
    # than string concatenation.
    python3 - "$OUT_DIR/SRCMAP_EXTRA.json" "/tmp/$SRCMAP_NAME" "$REPO_URL" "$HARNESS_REPO_SHA" <<'PYEOF'
import json, sys, os
extra_path, out_path, repo_url, sha = sys.argv[1:5]
srcmap = {"/src": {"type": "git", "url": repo_url, "rev": sha}}
if os.path.isfile(extra_path):
  with open(extra_path) as f:
    srcmap.update(json.load(f))
with open(out_path, "w") as f:
  json.dump(srcmap, f)
PYEOF

    (cd "$OUT_DIR" && zip -r "/tmp/$ZIP_NAME" .)
    gsutil cp "/tmp/$ZIP_NAME" "$BUCKET/$PROJECT/${ENGINE}-${SANITIZER}/$ZIP_NAME"
    gsutil cp "/tmp/$SRCMAP_NAME" "$BUCKET/$PROJECT/${ENGINE}-${SANITIZER}/$SRCMAP_NAME"
    rm "/tmp/$ZIP_NAME" "/tmp/$SRCMAP_NAME"
  done
done
