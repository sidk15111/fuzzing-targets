# id-repository fuzzing integration

Jazzer targets against MOSIP's `id-repository`, laid out the same way
`vulnfuzz`/`vulnjava` are: this directory is its own small repo, meant to be
symlinked into a local OSS-Fuzz checkout as `projects/id-repository/`.

There are two groups of targets here, and they are not equal:

- **Main fuzzers** -- the real bug-hunting harnesses. All current work is
  focused on these. See the next section.
- **Smoke-test targets** -- five minimal harnesses that only prove the
  build/ClusterFuzz pipeline works for a Jazzer project. They are listed at
  the bottom of this file, are not expected to find bugs, and are not where
  new effort goes.

## Main fuzzers

| Harness | Entry point | How it runs | Faked | Status |
|---|---|---|---|---|
| `IdRepoControllerAddIdentityFuzzer` | `IdRepoController.addIdentity` (POST `/`) | Spring MVC standalone `MockMvc`: real Jackson binding, `IdRequestValidator`, controller, exception handler | service layer, audit, UIN checksum, kernel schema validation | written, not yet built or run |
| `IdRepoControllerUpdateIdentityFuzzer` | `IdRepoController.updateIdentity` (PATCH `/`) | same as above | same as above | written, not yet built or run |
| `IdRepoServiceUpdateIdentityFuzzer` | `IdRepoServiceImpl.updateIdentity` | plain objects, no web layer | repositories (fuzz-driven fakes) and other collaborators | planned |

All three are in module `id-repository-identity-service`. Only two of
id-repository's six Maven modules are built so far (`id-repository-core`,
`id-repository-identity-service`). `build.sh`'s `-pl` flag is the place to add
`id-repository-vid-service`, `credential-service`, etc. as harnesses are
written for them.

### Files

- `IdRepoControllerAddIdentityFuzzer.java`,
  `IdRepoControllerUpdateIdentityFuzzer.java` -- the fuzz targets (thin).
- `IdRepoFuzzSupport.java` -- shared wiring, faked I/O edges, crash oracle and
  start-up self-check. Not a fuzz target: its name deliberately does not end
  in `Fuzzer`, so it is never wrapped or listed in `project.yaml`.
- `<Name>.dict` and `seeds/<Name>/` -- dictionary and seed corpus per target.
  Seeds are valid (and a few deliberately-rejected) request bodies built from
  MOSIP's own test data.
- `fixtures/identity-mapping.json` -- MOSIP's identity-mapping file, copied
  from their test resources and loaded as a classpath resource.

### Design notes

- **Structured input, not raw strings.** The fuzz input is the HTTP JSON body,
  seeded from real valid requests, so the fuzzer spends its time past the
  parser instead of in its reject path.
- **Mock only at I/O edges.** Parsing, validation and request handling stay
  real; only the service layer, auditing and external validators are faked. A
  harness that mocks the thing it targets fuzzes nothing.
- **No Spring application context.** Standalone `MockMvc` gives real JSON
  deserialization, request binding and exception handling without booting a
  context, a config server or a database. Mockito mocks use `stubOnly()` so
  they do not record invocations and exhaust the heap over millions of runs.
- **Crash detection.** `IdRepoExceptionHandler` catches every `Exception` and
  turns it into an HTTP 200 response, so a bug in the request path would be
  invisible to the fuzzer. The harness reads the exception the handler
  resolved and rethrows it unless it is one MOSIP raises on purpose
  (`IdRepoAppException` and subclasses, `IdRepoAppUncheckedException`, JSON
  parse errors, Spring MVC client errors). Anything else (NPE,
  ClassCastException, ...) is a finding, reported with its original stack
  trace.
- **Start-up work happens in `fuzzerInitialize()`, not lazily.** Building the
  MockMvc is slow (Spring MVC, Mockito, Jazzer instrumenting hundreds of newly
  loaded classes). Jazzer runs `fuzzerInitialize()` before libFuzzer's first
  unit, so it is not charged against libFuzzer's 25-second per-unit timeout.
  Done lazily it would be, and on a slower machine (the build bot, the
  ClusterFuzz bots) the very first input times out.
- **Start-up self-check.** On start, each harness sends one known-valid
  request and fails loudly if it does not reach the faked service. A
  mis-wired harness would otherwise look like a healthy fuzzer that simply
  finds nothing.
- **Seeds must not crash.** A seed that triggers a finding makes libFuzzer
  stop at corpus replay on every run. Reproduce findings from the crash
  artifacts, don't commit them as seeds.
- **Not covered by this first set:** the proxy service, draft service,
  biometric extraction, auth-type status, the real database layer, calls to
  other services, and Spring Security (authorization is not fuzzed).
  `requesttime` is checked against a deliberately widened window, because
  seeds are static files.

### Naming convention

New harnesses are named `<Surface><Operation>Fuzzer`
(e.g. `IdRepoControllerAddIdentityFuzzer`).

- The name must end in `Fuzzer` (required by `FUZZER_NAME_REGEX`, see below).
- It must be unique within this project: the ClusterFuzz corpus is keyed by
  fuzz target name.
- A dictionary, if any, is `<Name>.dict` at the project root; seeds go in
  `seeds/<Name>/` (`build.sh` zips every seeds directory that has a matching
  harness).
- List every harness in `fuzz_targets` in `project.yaml`.
- Existing smoke-test harnesses keep their current names.

## Local testing

Same flow as vulnjava:

```bash
ln -s /path/to/id-repository-fuzzing $OSS_FUZZ_DIR/projects/id-repository
cd $OSS_FUZZ_DIR
python3 infra/helper.py build_image id-repository
python3 infra/helper.py build_fuzzers --sanitizer=address id-repository
python3 infra/helper.py check_build id-repository <FuzzerName>
python3 infra/helper.py run_fuzzer id-repository <FuzzerName>
```

Repeat `check_build`/`run_fuzzer` per target name.

## Before this goes anywhere near the real ClusterFuzz job

Whatever job you create for this (e.g. `libfuzzer_asan_idrepo`) needs
`FUZZER_NAME_REGEX = .*Fuzzer$` set at the job level -- the same fix already
applied to `libfuzzer_asan_vulnjava`. Without it, bot-side fuzz-target
discovery greps for the C symbol `LLVMFuzzerTestOneInput`, which no Jazzer
wrapper script ever contains, and the job will silently never run anything.

## Why there's a `git clone` instead of a `COPY`

vulnjava/vulnfuzz are ours, so their Dockerfiles `COPY` the source in
directly from this same repo. id-repository is MOSIP's; we don't fork it or
commit anything into it -- the Dockerfile just clones it fresh at
image-build time, unpinned, so every rebuild tracks current master. This
repo (Dockerfile, build.sh, the `*Fuzzer.java` files and their support
files) is the only thing that's "ours" and lives under our own version
control.

## Why we don't touch id-repository's own per-service Dockerfiles

Each of id-repository's five runnable services ships its own Dockerfile
(`id-repository-identity-service/Dockerfile`, etc.). Those build the
*production* container: they start `FROM` a MOSIP-maintained JRE-only image,
`ADD` an already-built jar, and on container start download a couple of
extra jars from an artifactory and boot the full Spring Boot app against a
Spring Cloud Config server and a real Postgres. None of that runs here. Our
harnesses call the target classes' methods directly, in-process, inside the
Jazzer-instrumented JVM -- no Spring application context boots, no port
opens, no config server or Postgres is ever contacted. We only need the
plain `.jar` that `mvn package` produces, several build phases before that
Dockerfile would even be relevant.

---

## Smoke-test targets (pipeline verification only -- not the focus)

These five were the first batch. Their job was to prove that the whole path
works for a Jazzer project: clone MOSIP, build with Maven, `check_build`, and
run under ClusterFuzz. They target small utility methods with little
branching -- thin wrappers over JDK hashing, validators with a handful of
branches, and a lookup against a mock that always returns "not found" -- so
they are **not expected to find bugs**, and no new work should go into them.

Once the real ClusterFuzz job has been confirmed running them, they are
candidates for retirement (each target takes a share of fuzzing time).

| Harness | Module | Method under test | Mocking |
|---|---|---|---|
| `HashFuzzer` | id-repository-core | `IdRepoSecurityManager.hash(byte[])` | none |
| `HashWithSaltFuzzer` | id-repository-core | `IdRepoSecurityManager.hashwithSalt(byte[], byte[])` | none |
| `ValidateTypeFuzzer` | id-repository-identity-service | `IdRequestValidator.validateType(String)` | none |
| `ValidateIdTypeFuzzer` | id-repository-identity-service | `IdRequestValidator.validateIdType(String)` | none |
| `RetrieveIdentityFuzzer` | id-repository-identity-service | `IdRepoServiceImpl.retrieveIdentity(...)` | Mockito (`UinRepo`) |

`ValidateTypeFuzzer` and `ValidateIdTypeFuzzer` also ship a `.dict` file and a
seed corpus; the other three have neither.
