# id-repository fuzzing integration

Five Jazzer targets against MOSIP's `id-repository`, laid out the same way
`vulnfuzz`/`vulnjava` are: this directory is its own small repo, meant to be
symlinked into a local OSS-Fuzz checkout as `projects/id-repository/`.

## Targets in this first batch

| Harness | Module | Method under test | Mocking |
|---|---|---|---|
| `HashFuzzer` | id-repository-core | `IdRepoSecurityManager.hash(byte[])` | none |
| `HashWithSaltFuzzer` | id-repository-core | `IdRepoSecurityManager.hashwithSalt(byte[], byte[])` | none |
| `ValidateTypeFuzzer` | id-repository-identity-service | `IdRequestValidator.validateType(String)` | none |
| `ValidateIdTypeFuzzer` | id-repository-identity-service | `IdRequestValidator.validateIdType(String)` | none |
| `RetrieveIdentityFuzzer` | id-repository-identity-service | `IdRepoServiceImpl.retrieveIdentity(...)` | Mockito (`UinRepo`) |

Only two of id-repository's six Maven modules are touched so far
(`id-repository-core`, `id-repository-identity-service`). `build.sh`'s `-pl`
flag is the place to add `id-repository-vid-service`, `credential-service`,
etc. as you write harnesses for them.

## Local testing

Same flow as vulnjava:

```bash
ln -s /path/to/id-repository-fuzzing $OSS_FUZZ_DIR/projects/id-repository
cd $OSS_FUZZ_DIR
python3 infra/helper.py build_image id-repository
python3 infra/helper.py build_fuzzers --sanitizer=address id-repository
python3 infra/helper.py check_build id-repository HashFuzzer
python3 infra/helper.py run_fuzzer id-repository HashFuzzer
```

Repeat `check_build`/`run_fuzzer` per target name for the other four.

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
repo (Dockerfile, build.sh, the five `*Fuzzer.java` files) is the only thing
that's "ours" and lives under our own version control.

## Why we don't touch id-repository's own per-service Dockerfiles

Each of id-repository's five runnable services ships its own Dockerfile
(`id-repository-identity-service/Dockerfile`, etc.). Those build the
*production* container: they start `FROM` a MOSIP-maintained JRE-only image,
`ADD` an already-built jar, and on container start download a couple of
extra jars from an artifactory and boot the full Spring Boot app against a
Spring Cloud Config server and a real Postgres. None of that runs here. Our
harnesses call the target classes' methods directly, in-process, inside the
Jazzer-instrumented JVM -- no Spring context boots, no port opens, no config
server or Postgres is ever contacted. We only need the plain `.jar` that
`mvn package` produces, several build phases before that Dockerfile would
even be relevant.
