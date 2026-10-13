# id-repository fuzzing integration

Jazzer targets against MOSIP's `id-repository`, laid out the same way
`vulnfuzz`/`vulnjava` are: this directory is its own small repo, meant to be
symlinked into a local OSS-Fuzz checkout as `projects/id-repository/`.

The targets here are the controller-level harnesses described below. The five
original smoke-test harnesses that proved the pipeline have been retired.

## Main fuzzers

| Harness | Entry point | How it runs | Faked | Status |
|---|---|---|---|---|
| `IdRepoControllerAddIdentityFuzzer` | `IdRepoController.addIdentity` (POST `/`) | Spring MVC standalone `MockMvc`: real Jackson binding, `IdRequestValidator`, controller, exception handler | service layer, audit, UIN checksum, kernel schema validation | running on ClusterFuzz; known issue filtered (see Known issues) |
| `IdRepoControllerUpdateIdentityFuzzer` | `IdRepoController.updateIdentity` (PATCH `/`) | same as above | same as above | running on ClusterFuzz; known issue filtered (see Known issues) |
| `IdRepoServiceUpdateIdentityFuzzer` | `IdRepoServiceImpl.updateIdentity` | plain objects, no web layer; the real service runs | every repository (the stored record comes from the fuzz input), object store, CBEFF, anonymous-profile helper | written, not yet built or run |

All three are in module `id-repository-identity-service`. Only two of
id-repository's six Maven modules are built so far (`id-repository-core`,
`id-repository-identity-service`). `build.sh`'s `-pl` flag is the place to add
`id-repository-vid-service`, `credential-service`, etc. as harnesses are
written for them.

### Files

- `IdRepoControllerAddIdentityFuzzer.java`,
  `IdRepoControllerUpdateIdentityFuzzer.java` -- the fuzz targets (thin).
- `IdRepoServiceUpdateIdentityFuzzer.java` and `IdRepoServiceFuzzSupport.java` --
  the service-level harness and its wiring (see "Service-level harness").
- `IdRepoKnownIssues.java` -- registry of known, already-reported bugs that both
  harnesses skip (see "Known issues").
- `IdRepoFuzzSupport.java` -- shared wiring, faked I/O edges, crash oracle and
  start-up self-check for the controller harnesses. Not a fuzz target: its name deliberately does not end
  in `Fuzzer`, so it is never wrapped or listed in `project.yaml`.
- `<Name>.dict` and `seeds/<Name>/` -- dictionary and seed corpus per target.
  Seeds are valid (and a few deliberately-rejected) request bodies built from
  MOSIP's own test data.
- `fixtures/identity-mapping.json` -- MOSIP's identity-mapping file, copied
  from their test resources and loaded as a classpath resource.
- `fixtures/identity-stored.json` -- MOSIP's sample identity, used as the default
  stored record by the service-level harness.

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

### Service-level harness

`IdRepoServiceUpdateIdentityFuzzer` runs the real `IdRepoServiceImpl.updateIdentity`
and fakes what sits behind it. The controller harnesses fake this layer and run
the controller instead, so the two cover different code.

**Input format:** `[request identity JSON] 0x00 [stored identity JSON]`. Everything
before the first NUL byte is the identity object the client sends; everything
after is the record already in the database. With no NUL byte a default stored
record (`fixtures/identity-stored.json`) is used. Seeds in
`seeds/IdRepoServiceUpdateIdentityFuzzer/` are binary because of the separator.

**What counts as a finding:**

1. Any exception other than MOSIP's own `IdRepoAppException` /
   `IdRepoAppUncheckedException` (NullPointerException, ClassCastException, a
   JsonPath exception escaping, ...).
2. A broken property after a *successful* update: the stored record is no
   longer a JSON object, its hash does not match, or a top-level attribute the
   request did not name was changed, removed or added (`verifiedAttributes` is
   exempt; the service manages it).

**Why the property check exists.** The merge logic builds JsonPath expressions
from key names in the request (splitting on dots, rewriting brackets and `=`),
so a crafted key could make it write somewhere the request did not point. That
is data corruption, not a crash, and only a property check can see it.

**Reading the code suggests two things to look at first** (hypotheses, not
confirmed): `updateRequestBodyData` runs with `trim-whitespaces` defaulting to
true and casts attribute values without checking their shape, and uses
`Collectors.toMap`, which throws on null values; and the key-name-to-JsonPath
handling above.

**Reachability caveat.** This harness calls the service directly, bypassing the
controller's validation and the schema validator. A finding here is a
*candidate*. Before reporting, check whether the real request path could deliver
that input to the service.

**Seeds must not crash.** They were written from MOSIP's own sample data. All of them were checked against a verbatim copy of `updateRequestBodyData` (the trimming step) and pass it; later steps (JsonPath, JSONCompare, the merge helpers) could not be run outside MOSIP, so a seed may still hit a different bug there. An earlier version had a seed with `selectedHandles` as a list of strings and one with `verifiedAttributes` inside the identity (it is a sibling field of the request, not part of the identity); both crashed at start-up Move any seed that triggers a finding out of the seeds
directory and reproduce it from the crash artifact instead.

### Input domain of the service-level harness

The service is called directly, bypassing the controller's validation and the
schema validator. To avoid fuzzing states the real front door would never let
through, the harness **skips** (does not run) any input that breaks these
assumptions:

- every attribute name, at any depth, in the request and in the stored record
  matches `[A-Za-z][A-Za-z0-9_]{0,63}`;
- the **shapes** follow MOSIP's own sample identity schemas, for the request and
  for the stored record alike: a top-level attribute is a scalar (string, number,
  boolean, never `null`), an object, or an array of objects; those objects hold
  scalars only, have a string `value`, and a `language`, if present, is three
  lowercase letters (`eng`, `ara`, `fra`);
- the fields inside an attribute's object are limited to the ones the sample schemas define (`language`, `value`, `type`, `format`, `version`, `fileReference`, `label`), and `selectedHandles` must be a list;
- exceptions to the shapes: `selectedHandles` may also be an array of strings,
  and `verifiedAttributes` is allowed only in the **stored** record, as an array
  of strings (in a real request it is a sibling field of the identity, managed by
  the service);
- the stored record's bytes are valid UTF-8. The service decodes the record with `new String(bytes)`,
  which turns an invalid byte into `U+FFFD`, so a record with invalid bytes is silently rewritten by
  the service. The harness checks this before any JSON parse and reads the record the same way the
  service does, so its "before" picture always agrees with the service's.

**Not** restricted: attribute *values* (names such as `O'Brien` are realistic
and are the kind of input the merge logic may mishandle), array lengths, and
which attributes are present.

**Why nested field names and `selectedHandles` are restricted:** a later soak crashed with a message-less `PathNotFoundException` (JsonPath throws it from `set`, `add` and `put` when the path matches nothing). The input used an object field `langue` (no sample schema has it) and a 21-digit number as `selectedHandles`. MOSIP builds the filter path in `updateFailingFields` by **global text replacement** (`[` becomes `[?(@.`, `=` becomes `=='`, `]` becomes `')]`), so when the value that identifies an array element contains one of those characters, the rewritten path matches nothing. With the real field `language` the identifying value is a three-letter code and cannot contain them. It could still happen if an element is identified by its free-text `value` (the first key of the request element, when `language` comes second). That is **an open question, not a confirmed bug**: see `experiments/`, three small inputs to check it on the real code.

**Why the shape rule exists:** an earlier soak crashed in `updateMissingValues` with a `ClassCastException`. The stored record held `"residenceStatus":["x","y"]`, an array of plain strings, while the request had objects; the merge reads the stored list as a list of objects. A real record cannot look like that: the service only stores requests that passed schema validation, and the schema requires objects for that attribute. It shows the merge code is not defensive about corrupted stored data, which is a robustness observation, not something a client can trigger.

**Why the oracle compares against the record "as the service would write it":** a later soak reported "attribute `ye` was CHANGED although the request did not name it" with `before="Infinity" after="Infinity"`. The stored record held `"ye":44444e754444444152`, a number too large for a double. Jackson reads it as `Infinity` and writes it back as the **string** `"Infinity"`, which prints identically but is a different JSON type. That is Jackson's own round trip, not a change made by the merge. The property check now compares against the stored record after the same round trip, which removes this whole class of representation differences (number spellings, non-finite numbers) while still catching a changed, removed, nulled or invented attribute.

**Why the UTF-8 rule exists:** an earlier soak reported "attribute `postalCoe` was changed although the request did not name it". The stored bytes held a raw `0xFF` inside that attribute name. The service turned it into `U+FFFD` while the oracle's byte-level parse produced a different name, so the two disagreed about the record, not because the merge lost data. Production records are valid UTF-8, so this was a harness artifact, not a MOSIP bug.

**These are assumptions, not verified facts.** Check them against the real
identity schema. Why they exist: without them the fuzzer kept finding one root
cause in new forms, because the update merge builds JsonPath expressions from
attribute **names** without escaping them. Seen so far:

| Input | Result |
|---|---|
| name `fulljava.util.SequencedCollectionue` | `PathNotFoundException: Missing property in path $['fulljava']` (no stack trace) |
| name `""` (empty) | `IllegalArgumentException: key can not be null or empty` from `JsonPath.put` in `updateMissingFields` line 687 |

If the real API does accept such names, that is a bug to report, and a dedicated
"hostile attribute names" harness is the place to hunt it, including the
property check for a dotted name silently writing to the wrong attribute. The
main harness cannot do that while this restriction is in place.

### Known issues (filtered by the oracles)

A bug that is already reported upstream but still present in MOSIP master can
sit at the front of a code path and end each fuzzing session within minutes,
hiding everything deeper. Such bugs are listed in `IdRepoKnownIssues.java`,
shared by the controller-level and service-level harnesses. The oracle skips
them, counts them, and prints one line per issue per process the first time
one is hit.

| Id | What | Upstream report |
|---|---|---|
| `validator-null-request` | `IdRequestValidator.validate()` dereferences `request.getRequest()` without a null check, so a body with no `request` object throws `NullPointerException` | _add link when filed_ |
| `update-trim-unchecked-casts` | `IdRepoServiceImpl.updateRequestBodyData()` trims attribute values (default `trim-whitespaces=true`) but casts them without checking their shape: a list element that is not an object, an object with no `value`, a non-string `value`, or a null value throw `ClassCastException` / `NullPointerException`. One entry covers the whole method, since they share one root cause. **Reachability from the real API is not yet confirmed**: the schema validator in front of the service may reject some of these shapes. Minimal input: `{"fullName":["abc"]}`. **Most plausible real-world trigger:** an update request carrying `selectedHandles`, which MOSIP's own `IdRepoServiceHelper.getSelectedHandles` reads as a `List<String>` and which is configured to be replaced on update (`fields-to-replace`), with the default `trim-whitespaces=true`. The trimming code assumes every list element is an object, so a list of strings throws `ClassCastException`. MOSIP's tests that enable trimming do not appear to use it that way (grep only, not read in full). Verify this input first when looking at reachability | _add link when filed_ |
| `update-key-names-in-jsonpath` | The update merge turns attribute **names** from the request into JsonPath expressions without escaping them (`updateMissingFields`, `updateFailingFields`, `updateMissingValues` split on dots and rewrite brackets and `=`). A name such as `a.b` is read as a path, so the merge looks for a parent that does not exist and a `JsonPathException` escapes `updateIdentity` (200 "unknown error" in production). Seen as `PathNotFoundException: Missing property in path $['fulljava']` for the key `fulljava.util.SequencedCollectionue`. **Currently not reachable by the service-level harness, because it restricts attribute names (see Input domain).** **Matched on context, not on the stack**: JsonPath throws these exceptions without a stack trace. The rule is a `JsonPathException` while the request names an attribute, at any depth, containing one of `. [ ] ' ? @ * ( ) = $`. The property check still runs on successful updates, so the more serious form, a name silently writing to the wrong place, is still hunted. Reachability not confirmed: the schema validator may reject such attribute names | _add link when filed_ |

Rules for this list:

- Add an entry only **after** the bug has been reported, and match on exception
  type, throwing method and message, never on line numbers.
- Matching uses the **first MOSIP frame** in the stack (`io.mosip.` classes), not
  the top frame (except for entries that must use harness context, because the
  exception has no stack at all), because a bug inside a JDK call made by MOSIP code has a JDK
  frame on top (`ArrayList.forEach` for a bad cast inside a lambda).
- Keep each entry as narrow as the root cause allows.
- Delete the entry when upstream fixes the bug, so a regression is caught again.
- ClusterFuzz re-tests an open testcase against each new build. Once an entry
  suppresses the crash, ClusterFuzz will mark that testcase "fixed". That means
  "no longer reproduces in our harness", not "MOSIP fixed it".
- The wrapper script runs the JVM with `-XX:-OmitStackTraceInFastThrow`. HotSpot
  can strip the message and stack from an exception thrown many times, which
  would make a match impossible. A stripped exception has no MOSIP frame, is not
  matched, and surfaces as a finding instead of being hidden.

### Inspecting a crash locally

A local crash does not need ClusterFuzz to understand it.

```bash
# 1. find the crash file (usually build/out/<project>/crash-<sha1>)
find build -name 'crash-*'

# 2. see the input. The service harness input is  request JSON, NUL, stored JSON
python3 -c "import sys; d=open(sys.argv[1],'rb').read(); r,_,s=d.partition(b'\0'); \
print('REQUEST:', r.decode(errors='replace')); print('STORED :', s.decode(errors='replace') or '(default record)')" build/out/<project>/crash-...

# 3. reproduce it and get the stack trace
python3 infra/helper.py reproduce <project> <FuzzerName> build/out/<project>/crash-...

# 4. open the source at the exact commit that was built. The line numbers in the
#    stack only match that commit.
cat build/out/<project>/SRCMAP_EXTRA.json      # contains the upstream "rev"
```

Read the stack top-down to the **first `io.mosip` frame**: that is the method at
fault. Then hand-minimize the input (replace values until a small input still
crashes) and try it with `printf '...' > min.bin` and step 3.

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
