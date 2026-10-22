# id-repository fuzzing integration

Jazzer targets against MOSIP's `id-repository`, laid out the same way
`vulnfuzz`/`vulnjava` are: this directory is its own small repo, meant to be
symlinked into a local OSS-Fuzz checkout as `projects/mosip-id-repository/`.

The targets here are the controller-level harnesses described below. The five
original smoke-test harnesses that proved the pipeline have been retired.

## Main fuzzers

| Harness | Entry point | How it runs | Faked | Status |
|---|---|---|---|---|
| `IdRepoControllerAddIdentityFuzzer` | `IdRepoController.addIdentity` (POST `/`) | Spring MVC standalone `MockMvc`: real Jackson binding, `IdRequestValidator`, controller, exception handler | service layer, audit, UIN checksum, kernel schema validation | running on ClusterFuzz; known issue filtered (see Known issues) |
| `IdRepoControllerUpdateIdentityFuzzer` | `IdRepoController.updateIdentity` (PATCH `/`) | same as above | same as above | running on ClusterFuzz; known issue filtered (see Known issues) |
| `IdRepoServiceUpdateIdentityFuzzer` | `IdRepoServiceImpl.updateIdentity` | plain objects, no web layer; the real service runs | every repository (the stored record comes from the fuzz input), object store, CBEFF, anonymous-profile helper | soaked locally (15 min 24 s, 8.5 M executions, flat memory) and submitted to ClusterFuzz; known issues and input domain filtered |

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
- `IdRepoKnownIssues.java` -- registry of known, catalogued bugs that both
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

**Both things the code suggested looking at first have since been confirmed:**
`updateRequestBodyData` casts attribute values without checking their shape, and
the merge uses attribute names as JsonPath expressions. See "Findings".

**Reachability caveat.** This harness calls the service directly, bypassing the
controller's validation and the schema validator. A finding here is a
*candidate*. Before reporting, check whether the real request path could deliver
that input to the service.

**Seeds must not crash.** They were written from MOSIP's own sample data. All of them were checked against a verbatim copy of `updateRequestBodyData` (the trimming step) and pass it; later steps (JsonPath, JSONCompare, the merge helpers) could not be run outside MOSIP, so a seed may still hit a different bug there. An earlier version had a seed with `selectedHandles` as a list of strings and one with `verifiedAttributes` inside the identity (it is a sibling field of the request, not part of the identity); both crashed at start-up. Move any seed that triggers a finding out of the seeds
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

**Why nested field names and `selectedHandles` are restricted:** a later soak crashed with a message-less `PathNotFoundException` (JsonPath throws it from `set`, `add` and `put` when the path matches nothing). The input used an object field `langue` (no sample schema has it) and a 21-digit number as `selectedHandles`. MOSIP builds the filter path in `updateFailingFields` by **global text replacement** (`[` becomes `[?(@.`, `=` becomes `=='`, `]` becomes `')]`), so when the value that identifies an array element contains one of those characters, the rewritten path matches nothing. With the real field `language` the identifying value is a three-letter code and cannot contain them. Whether a realistic request can trigger it was tested with the three inputs in `experiments/` (a name containing `[` or `'`, with `value` placed before `language`): **all three ran clean on the real build.** JSONAssert picks the identifying key of an array element alphabetically, so in a real `{language, value}` object `language` always wins and the free-text value never enters the path. The mechanism is still real when the method is called directly, so it is catalogued under `update-key-names-in-jsonpath` (see "Findings").

**Why the shape rule exists:** an earlier soak crashed in `updateMissingValues` with a `ClassCastException`. The stored record held `"residenceStatus":["x","y"]`, an array of plain strings, while the request had objects; the merge reads the stored list as a list of objects. A real record cannot look like that: the service only stores requests that passed schema validation, and the schema requires objects for that attribute. It shows the merge code is not defensive about corrupted stored data, which is a robustness observation, not something a client can trigger.

**Why the oracle compares against the record "as the service would write it":** a later soak reported "attribute `ye` was CHANGED although the request did not name it" with `before="Infinity" after="Infinity"`. The stored record held `"ye":44444e754444444152`, a number too large for a double. Jackson reads it as `Infinity` and writes it back as the **string** `"Infinity"`, which prints identically but is a different JSON type. Jackson is doing what its defaults say; the choice of settings is MOSIP's, so the fix would be in MOSIP's configuration or validation. This crash file reached it through a stored record MOSIP could never have written (every write already goes through the same mapper), but the same rewrite plausibly applies to a client's value: a `1e999` in a numeric attribute would be stored as the string `"Infinity"` (unconfirmed on the real build). It is catalogued as MOSIP behaviour in "Findings", with low reachability: in `IDSchemaVersion` the value is turned into the string `"Infinity"` and used to look up a schema version, which fails, so that request is rejected before anything is stored; only another numeric attribute in a country's schema could carry it. The property check compares against the stored record after the same round trip so that this one known behaviour does not end every session. That also hides number spellings that change on a round trip, while still catching a changed, removed, nulled or invented attribute.

**Why the UTF-8 rule exists:** an earlier soak reported "attribute `postalCoe` was changed although the request did not name it". The stored bytes held a raw `0xFF` inside that attribute name. The service turned it into `U+FFFD` while the oracle's byte-level parse produced a different name, so the two disagreed about the record, not because the merge lost data. Production records are valid UTF-8, so this was a harness artifact, not a MOSIP bug.

**These are assumptions, not verified facts.** Check them against the real
identity schema. Why they exist: without them the fuzzer kept finding one root
cause in new forms, because the update merge builds JsonPath expressions from
attribute **names** without escaping them. Seen so far:

| Input | Result |
|---|---|
| name `fulljava.util.SequencedCollectionue` | `PathNotFoundException: Missing property in path $['fulljava']` (no stack trace) |
| name `""` (empty) | `IllegalArgumentException: key can not be null or empty` from `JsonPath.put` in `updateMissingFields` line 687 (not a `JsonPathException`, so the `update-key-names-in-jsonpath` filter would not match it; the input domain skips it instead) |

If the real API does accept such names, that is a bug to report, and a dedicated
"hostile attribute names" harness is the place to hunt it, including the
property check for a dotted name silently writing to the wrong attribute. The
main harness cannot do that while this restriction is in place.

### Findings

These harnesses look for bugs that become environments for training an RL agent
to find bugs, and later to fix them. Any real bug in MOSIP's code counts,
security-relevant or not, including one that shows only when a unit is called
directly ("in isolation"). A harness artifact counts for nothing: there is
nothing wrong in MOSIP's code for the agent to find.

**How a crash is classified.** Two questions, in order:

1. *Where would the fix go?* In this harness (oracle, seeds, input domain,
   fakes): a **harness artifact**. In MOSIP's code: a **MOSIP bug**.
2. *Can a real request reach it?* Through the real front door: **reachable**.
   Only when the unit is called directly, on input its own types allow:
   **isolated**. Both count. Data MOSIP wrote itself is trusted: a crash that
   needs a stored record MOSIP could never have written is a harness artifact,
   not an isolated bug.

**What "crash" means.** In the harness, a crash is an exception escaping the
target, or an `AssertionError` the property check throws on purpose. Jazzer
prints `== Java Exception: ...` with the stack and stops. In production none of
these bugs stops the service: `IdRepoExceptionHandler` turns an escaping
exception into an error response, and the integrity issues produce no error at
all.

| Issue | Crash files (`crash-<prefix>...`) | Harness | Bucket | Effect in production |
|---|---|---|---|---|
| `validator-null-request` | `c3240055`, `ead6c8e6` | controller Add, Update | MOSIP bug, reachable | Error response `IDR-IDC-004` ("unknown error") instead of a missing-parameter error; an NPE in the logs |
| `validator-identity-not-object` | ClusterFuzz, October 13 and later (reproducers `Crash_73dd9536...`, `Crash_31014649...`) | controller Add | MOSIP bug, reachable | Error response `IDR-IDC-004` ("unknown error") instead of an invalid-parameter error; a `ClassCastException` in the logs |
| `update-trim-unchecked-casts` | `4a482cf5` (the old `selected-handles.bin` seed) | service | MOSIP bug, isolated; reachability via `selectedHandles` unconfirmed | Update fails with an unknown-error response |
| `update-key-names-in-jsonpath` | `fc4f1ff8` (dotted name), `81578e0d` (empty name), `5c8d8552` (value characters in the filter path; that input was not realistic) | service | MOSIP bug, isolated | Update fails with an unknown-error response. JsonPath exceptions carry no stack trace, so the logs do not show where it failed |
| stored number rewritten as `"Infinity"` (no filter entry; the oracle normalizes it) | `6caf6018` | service | MOSIP behaviour, isolated, low reachability | No error. An attribute's number silently becomes the string `"Infinity"` |
| invalid UTF-8 in a stored key | `f79a23e3` | service | harness artifact | none |
| stored shape MOSIP never writes (`residenceStatus:["x","y"]`) | `16cb308a` | service | harness artifact | none |
| out-of-memory (under investigation) | ClusterFuzz `oom-193bf56f...` | controller Update | probably the environment: process memory passed libFuzzer's 2,560 MB limit, with no Java `OutOfMemoryError` | none known |
| unclassified | `90f2c364` (2 bytes, not JSON) | unknown; probably a retired smoke-test harness | | |

**Candidates not yet seen by a harness** (unconfirmed on the real build):

- *Property-based test of the merge code, extracted verbatim and run outside
  MOSIP (about 600,000 merges, no crashes).* Three silent integrity issues: a
  request listing fewer languages than are stored drops its change; a new
  language added to several attributes in one update lands only in the first,
  alphabetically; the string `"null"` is treated as JSON null and the update is
  dropped. The service harness cannot see these: its property check only
  verifies that unmentioned attributes are untouched.
- *From reading `IdRequestValidator`.* Line 187 of `validate()` calls
  `validateRequest(..., UPDATE)` unconditionally, after the id-specific branch
  has already called it. A create request is validated twice, the second time
  with update rules, and the identity is validated even when `requesttime`,
  `version` or `id` already failed. It looks unintended (unconfirmed).
- *From reading `IdRepoServiceHelper`.* `getSchema` puts the client's
  `IDSchemaVersion` text into an internal master-data URL without encoding it,
  and caches every version string that master data answers, before the schema
  validator checks the field's type (possible unbounded cache growth if master
  data accepts variant spellings). `getSelectedHandles` calls
  `supportedHandlesInSchema.get(schemaVersion).contains(...)` with no null check.

**Record the commit.** The Dockerfile clones MOSIP master unpinned, so a bug and
its line numbers can change with every rebuild. For each finding, keep the `rev`
from `build/out/<project>/SRCMAP_EXTRA.json` of the build that found it. It was
not recorded for the findings above (found October 7 to 13, 2026).

### Known issues (filtered by the oracles)

A known bug can sit at the front of a code path and end each fuzzing session
within minutes, hiding everything deeper: libFuzzer stops at the first crash, and
the next session reaches the same shallow bug again within seconds. Such bugs are listed in `IdRepoKnownIssues.java`,
shared by the controller-level and service-level harnesses. The oracle skips
them, counts them, and prints one line per issue per process the first time
one is hit.

| Id | What | Upstream report |
|---|---|---|
| `validator-null-request` | `IdRequestValidator.validate()` dereferences `request.getRequest()` without a null check, so a body with no `request` object throws `NullPointerException`. Reachable through the real front door. Reproducers: `crash-c32400557cbd...`, `crash-ead6c8e6837c...` | _add link when filed_ |
| `validator-identity-not-object` | `IdRequestValidator.validateRequest()` casts `request.identity` to a `Map` without checking its type, so an identity that is a string, number, array or boolean throws `ClassCastException`. Reachable through the real front door: Jackson binds `identity` as an untyped object, and the schema validator runs after the cast. Reached even when the header fields are invalid, because `validate()` calls `validateRequest()` unconditionally (line 187). Predicted minimal body: `{"request":{"identity":"x"}}` | _add link when filed_ |
| `update-trim-unchecked-casts` | `IdRepoServiceImpl.updateRequestBodyData()` trims attribute values (default `trim-whitespaces=true`) but casts them without checking their shape: a list element that is not an object, an object with no `value`, a non-string `value`, or a null value throw `ClassCastException` / `NullPointerException`. One entry covers the whole method, since they share one root cause. **Reachability from the real API is not yet confirmed**: the schema validator in front of the service may reject some of these shapes. Minimal input: `{"fullName":["abc"]}`. **Most plausible real-world trigger:** an update request carrying `selectedHandles`, which MOSIP's own `IdRepoServiceHelper.getSelectedHandles` reads as a `List<String>` and which is configured to be replaced on update (`fields-to-replace`), with the default `trim-whitespaces=true`. The trimming code assumes every list element is an object, so a list of strings throws `ClassCastException`. MOSIP's tests that enable trimming do not appear to use it that way (grep only, not read in full). Verify this input first when looking at reachability. Reproducer: `crash-4a482cf5af1e...` | _add link when filed_ |
| `update-key-names-in-jsonpath` | The update merge turns attribute **names** from the request into JsonPath expressions without escaping them (`updateMissingFields`, `updateFailingFields`, `updateMissingValues` split on dots and rewrite brackets and `=`). A name such as `a.b` is read as a path, so the merge looks for a parent that does not exist and a `JsonPathException` escapes `updateIdentity` (200 "unknown error" in production). Seen as `PathNotFoundException: Missing property in path $['fulljava']` for the key `fulljava.util.SequencedCollectionue` (`crash-fc4f1ff885b7...`), and as `IllegalArgumentException: key can not be null or empty` for an empty name (`crash-81578e0d6287...`). **Currently not reachable by the service-level harness, because it restricts attribute names (see Input domain).** **Matched on context, not on the stack**: JsonPath throws these exceptions without a stack trace. The rule is a `JsonPathException` while the request names an attribute, at any depth, containing one of `. [ ] ' ? @ * ( ) = $`. The property check still runs on successful updates, so the more serious form, a name silently writing to the wrong place, is still hunted. Reachability not confirmed: the schema validator may reject such attribute names | _add link when filed_ |

Rules for this list:

- Add an entry only **after** the bug is in "Findings" with its crash file.
  Reporting upstream is separate (currently on hold). Match on exception type,
  throwing method and message, never on line numbers.
- Matching uses the **first MOSIP frame** in the stack (`io.mosip.` classes), not
  the top frame (except for entries that must use harness context, because the
  exception has no stack at all), because a bug inside a JDK call made by MOSIP code has a JDK
  frame on top (`ArrayList.forEach` for a bad cast inside a lambda).
- Keep each entry as narrow as the root cause allows.
- Delete the entry when upstream fixes the bug, so a regression is caught again.
  Keep the finding and its crash file: the bug is still real at the recorded commit.
- ClusterFuzz re-tests an open testcase against each new build. Once an entry
  suppresses the crash, ClusterFuzz will mark that testcase "fixed". That means
  "no longer reproduces in our harness", not "MOSIP fixed it".
- The wrapper script runs the JVM with `-XX:-OmitStackTraceInFastThrow`. HotSpot
  can strip the message and stack from an exception thrown many times, which
  would make a match impossible. A stripped exception has no MOSIP frame, is not
  matched, and surfaces as a finding instead of being hidden.

### What ClusterFuzz will and won't report

- **Known issues and inputs outside the input domain are never reported.** A
  resubmitted build does not make ClusterFuzz find the catalogue above again;
  those are reproduced locally from their crash files. What ClusterFuzz can add
  is *new* findings.
- **Sessions run long unless something new is found.** A known issue is skipped
  and fuzzing continues. The corpus is kept between sessions, so exploration
  accumulates.
- **A new finding ends that session**, and ClusterFuzz groups repeats into one
  testcase. If it is shallow, it will end most later sessions too, until it is
  catalogued and added here (or patched in our build).
- **Each rebuild fuzzes current MOSIP master**, so a rebuild can find bugs that
  are new upstream, and a filtered bug can disappear because upstream changed.
- **Check whether sessions run their full length.** On the Fuzzer Statistics
  page, compare `actual_duration` with `expected_duration`, and look at
  `crash_count`, `edge_coverage` and `corpus_size` over time. The service
  harness's local coverage flattened at about 7,270 edges after 8 million
  executions, so steady but small growth on ClusterFuzz is expected.

### Inspecting a crash locally

A local crash does not need ClusterFuzz to understand it.

```bash
# 1. find the crash file (usually build/out/<project>/crash-<sha1>)
find build -name 'crash-*'

# 2. see the input. The service harness input is  request JSON, NUL, stored JSON
python3 -c "import sys; d=open(sys.argv[1],'rb').read(); r,_,s=d.partition(b'\0'); \
print('REQUEST:', r.decode(errors='replace')); print('STORED :', s.decode(errors='replace') or '(default record)')" build/out/<project>/crash-...

# 3. reproduce it with the harness that found it, and get the stack trace.
#    The generated Crash_<sha1>.java names that harness (it calls
#    <FuzzerName>.fuzzerTestOneInput). Don't guess from the bytes: a service
#    input may have no NUL (it then uses the default stored record), and a
#    controller input's junk can contain NUL bytes.
python3 infra/helper.py reproduce <project> <FuzzerName> build/out/<project>/crash-...

# 4. open the source at the exact commit that was built. The line numbers in the
#    stack only match that commit.
cat build/out/<project>/SRCMAP_EXTRA.json      # contains the upstream "rev"
```

What the output means:

- `== Java Exception: ...` with a stack: a finding.
- `IdRepoKnownIssues: skipping known issue '<id>'`: the input hits a catalogued
  bug. This line goes to stderr, so pipe `2>&1` before any `grep`.
- A clean run in a few milliseconds with no other line: the service harness
  skipped the input before MOSIP ran (invalid UTF-8, not JSON, or outside the
  input domain). Check that it was run with the right harness.

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
ln -s /path/to/id-repository-fuzzing $OSS_FUZZ_DIR/projects/mosip-id-repository
cd $OSS_FUZZ_DIR
python3 infra/helper.py build_image mosip-id-repository
python3 infra/helper.py build_fuzzers --sanitizer=address mosip-id-repository
python3 infra/helper.py check_build mosip-id-repository <FuzzerName>
python3 infra/helper.py run_fuzzer mosip-id-repository <FuzzerName>
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
