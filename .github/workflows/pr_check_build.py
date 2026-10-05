name: PR check_build

# Builds a submission and check_build's every declared fuzz target BEFORE
# anyone approves it, so the approver has real evidence instead of reading
# a Dockerfile blind.
#
# This executes the submitter's Dockerfile and build.sh -- untrusted code.
# What makes that acceptable before approval is WHERE it runs: a throwaway
# GitHub-hosted runner holding nothing worth stealing. Keep it that way:
#   - no secrets referenced here
#   - no `id-token: write` (no GCP identity of any kind)
#   - never switch the trigger to `pull_request_target`
# The GCP side independently refuses tokens minted by PR runs (the WIF
# attribute-condition pins them to refs/heads/main), so this property is
# enforced by IAM, not just by this file staying unedited.
#
# No `paths:` filter on purpose: the check-build-gate job below must report
# on EVERY PR so it can be a required status check. A path-filtered
# workflow never reports on non-matching PRs, and a required check that
# never reports blocks them forever.
on:
  pull_request:

permissions:
  contents: read

jobs:
  detect:
    runs-on: ubuntu-latest
    outputs:
      projects: ${{ steps.detect.outputs.projects }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # need the base commit available to diff against

      - id: detect
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          # Same discovery contract as trigger_build.yml and
          # validate_submission.py: a project is "the nearest directory
          # containing a project.yaml", at any depth.
          CHANGED_FILES=$(git diff --name-only "$BASE_SHA" HEAD -- 'projects/**' || true)

          declare -A FOUND
          while IFS= read -r f; do
            [ -z "$f" ] && continue
            dir=$(dirname "$f")
            while [ "$dir" != "." ] && [ "$dir" != "/" ]; do
              if [ -f "$dir/project.yaml" ]; then
                FOUND["$dir"]=1
                break
              fi
              dir=$(dirname "$dir")
            done
          done <<< "$CHANGED_FILES"

          if [ ${#FOUND[@]} -eq 0 ]; then
            echo "No project touched by this PR -- nothing to check."
            echo "projects=[]" >> "$GITHUB_OUTPUT"
            exit 0
          fi

          JSON=$(printf '%s\n' "${!FOUND[@]}" | sort -u | jq -R . | jq -sc .)
          echo "Affected project(s): ${!FOUND[@]}"
          echo "projects=$JSON" >> "$GITHUB_OUTPUT"

  check:
    needs: detect
    if: needs.detect.outputs.projects != '[]'
    runs-on: ubuntu-latest
    timeout-minutes: 60  # bounds a hung or abusive build.sh
    strategy:
      fail-fast: false
      matrix:
        project_path: ${{ fromJson(needs.detect.outputs.projects) }}
    steps:
      - uses: actions/checkout@v4

      - name: Install PyYAML
        run: pip install pyyaml

      - name: Build and check_build every declared fuzz target
        env:
          # Via env, never inline ${{ }} in the script: this value is a
          # directory name the PR author fully controls.
          PROJECT_PATH: ${{ matrix.project_path }}
        run: |
          set -euo pipefail
          PROJECT_DIR="$GITHUB_WORKSPACE/$PROJECT_PATH"

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

          git clone --depth 1 https://github.com/google/oss-fuzz.git "$RUNNER_TEMP/oss-fuzz"
          ln -s "$PROJECT_DIR" "$RUNNER_TEMP/oss-fuzz/projects/$PROJECT"
          cd "$RUNNER_TEMP/oss-fuzz"

          # Same build + check_build core as build_and_upload.sh on the
          # bot, minus the upload.
          for ENGINE in "${ENGINES[@]}"; do
            for SANITIZER in "${SANITIZERS[@]}"; do
              docker build -t "gcr.io/oss-fuzz/$PROJECT" "projects/$PROJECT/"
              python3 infra/helper.py build_fuzzers --clean \
                --sanitizer "$SANITIZER" --engine "$ENGINE" "$PROJECT"

              for TARGET in "${FUZZ_TARGETS[@]}"; do
                echo "check_build: $PROJECT / $ENGINE-$SANITIZER / $TARGET"
                python3 infra/helper.py check_build "$PROJECT" "$TARGET"
              done
            done
          done

  # The single, stable-named job to mark as a required status check.
  # Matrix job names change with the project, so they can't be required
  # directly; this one always runs and always reports.
  check-build-gate:
    needs: [detect, check]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Fail if detection or any project's check_build failed
        env:
          DETECT_RESULT: ${{ needs.detect.result }}
          CHECK_RESULT: ${{ needs.check.result }}
        run: |
          echo "detect: $DETECT_RESULT / check: $CHECK_RESULT"
          if [ "$DETECT_RESULT" != "success" ]; then
            echo "::error::Project detection did not succeed"
            exit 1
          fi
          # "skipped" is fine: no project was touched by this PR.
          if [ "$CHECK_RESULT" = "failure" ] || [ "$CHECK_RESULT" = "cancelled" ]; then
            echo "::error::check_build failed for at least one project in this PR"
            exit 1
          fi
