

# fuzzing-targets

This repo holds fuzz target definitions for our ClusterFuzz deployment.
It contains **only** `projects/<name>/` folders — no build-bot scripts,
no automation, no oss-fuzz code. Everything downstream of a merge here
(building, checking, uploading) lives in a separate `fuzzing-infra` repo,
maintained by the platform/infra team.

## What a submission looks like

```
projects/<your-project>/          (flat, or nested e.g. projects/<org>/<name> --
                                    both work; see "Naming" below)
├── Dockerfile
├── build.sh
├── project.yaml
├── README.md                     (optional, but encouraged)
└── seeds/                        (optional)
    └── <FuzzerName>/
        └── <seed files>
```

- **Dockerfile** — `FROM gcr.io/oss-fuzz-base/base-builder-<language>`, then
  whatever setup your project needs. If you're fuzzing a project you don't
  own, `git clone` its upstream repo here as a build step — don't fork it
  or commit its source into this repo.
- **build.sh** — compiles your harness(es) against the cloned/built source
  and wraps each one so it can run under Jazzer/libFuzzer. See
  `projects/mosip/id-repository/` for a real, working example (JVM/Jazzer).
- **project.yaml** — see `templates/project.yaml` for the full schema and
  field-by-field explanation. The `name` field is the one thing every
  submission must get right and get unique — everything downstream (bucket
  paths, job names) keys off it, not off your folder path.

## Naming: flat vs. nested

Organize your own submission's folder however makes sense to you —
`projects/my-project/` and `projects/my-org/my-project/` are both fine and
both work identically with our tooling. What actually identifies your
project everywhere else (bucket paths, job names, the oss-fuzz `projects/`
symlink) is the `name:` field in your `project.yaml`, not your folder
path. That field does need to be globally unique across every submission
in this repo, regardless of where it lives.

## How to submit

1. Fork/branch this repo.
2. Add your `projects/<name>/` folder with the files above.
3. Open a PR.
4. An automated check validates your `project.yaml` and confirms
   `Dockerfile`/`build.sh` are present — this runs immediately and safely,
   without executing anything you submitted.
5. A maintainer reviews your Dockerfile/build.sh by hand before the actual
   build gets attempted — this step exists because a build.sh is
   effectively arbitrary shell/Docker instructions, and running that
   unattended before anyone's looked at it isn't something we do, no
   matter who's submitting.
6. Once approved and merged, your project gets built and `check_build`-ed
   on our build bot. If that fails, you'll see why on the PR/commit; if it
   passes, the build gets uploaded and is ready for a ClusterFuzz job to
   be pointed at it (a separate, still-manual step for now).

## Requirements checklist

- [ ] `project.yaml` present, valid, and matches `templates/project.yaml`
- [ ] `name` field present, unique, lowercase-letters/digits/hyphens only
- [ ] `Dockerfile` present
- [ ] `build.sh` present
- [ ] At least one fuzz harness that will actually get compiled by `build.sh`
- [ ] If fuzzing a third-party repo: cloned fresh in the Dockerfile, not
      forked or committed here
