#!/bin/bash -eu
# Runs inside gcr.io/oss-fuzz-base/base-builder-jvm.
# $SRC, $OUT, $JAZZER_API_PATH, $JVM_LD_LIBRARY_PATH are provided by the base image.

# Record exactly which upstream commit got cloned into this image, in the
# same srcmap.json shape ClusterFuzz's own build pipeline uses for
# multi-repo provenance. build_and_upload.sh looks for this exact filename
# and merges it into the base srcmap entry (this harness repo's own
# commit) before uploading -- so this is the only thing id-repository's
# build.sh needs to produce; the orchestrator does the rest.
UPSTREAM_SHA=$(git -C "$SRC/id-repository" rev-parse HEAD)
echo "{\"/src/id-repository\": {\"type\": \"git\", \"url\": \"https://github.com/mosip/id-repository.git\", \"rev\": \"$UPSTREAM_SHA\"}}" > "$OUT/SRCMAP_EXTRA.json"

# id-repository's GitHub repo root is NOT the Maven reactor root -- the
# actual multi-module pom.xml lives one directory further down, inside a
# same-named nested folder. That's how MOSIP laid the repo out, not a
# mistake here.
cd "$SRC/id-repository/id-repository"

# --- Step 1: build only the modules today's harnesses touch. ----------------
# -pl selects id-repository-core + id-repository-identity-service; -am
# ("also make") builds core first since identity-service depends on it via
# Maven coordinates. This intentionally skips vid-service, credential-
# service, salt-generator, and credential-request-generator for now -- add
# them to -pl as harnesses grow to cover those modules too.
#
# Compiles at id-repository's own pinned Java 21 -- no source/target
# override. That was tried and rolled back: it fixed our own classes, but
# kernel-core and other MOSIP dependencies are themselves published as
# Java 21 bytecode already, which no compiler flag on our side can touch.
# Rather than fight bytecode we don't control, Step 3 bundles a JDK 21 for
# the runner to actually execute against instead.
# maven.test.skip (not -DskipTests): id-repository's own pom hardcodes
# surefire's <skipTests>false</skipTests> as a literal, so a command-line
# -DskipTests has nothing to override -- it's silently ignored, and the
# full unit test suite runs on every build otherwise. maven.test.skip
# operates at the lifecycle level (skips test-compile entirely, not just
# surefire's own execution), which no plugin-level config can override.
mvn -q -Dmaven.test.skip=true -Dmaven.javadoc.skip=true -Dgpg.skip=true \
    -pl id-repository-core,id-repository-identity-service -am \
    clean install

CORE_JAR=$(find id-repository-core/target -maxdepth 1 -name 'id-repository-core-*.jar' ! -name '*sources*')
# identity-service binds spring-boot-maven-plugin's repackage goal, so
# target/id-repository-identity-service-*.jar is the executable Spring Boot
# jar (ZIP layout, classes nested under BOOT-INF/classes/) -- javac can't
# see anything in there at the normal package paths. The plugin preserves
# the pre-repackage thin jar right alongside it as *.jar.original; that's
# the one with classes where javac expects them. Falls back to the plain
# name if some future pom change ever drops the repackage goal.
IDENTITY_JAR=$(find id-repository-identity-service/target -maxdepth 1 -name 'id-repository-identity-service-*.jar.original')
if [ -z "$IDENTITY_JAR" ]; then
  IDENTITY_JAR=$(find id-repository-identity-service/target -maxdepth 1 -name 'id-repository-identity-service-*.jar' ! -name '*sources*')
fi
cp "$CORE_JAR" "$OUT/id-repository-core.jar"
cp "$IDENTITY_JAR" "$OUT/id-repository-identity-service.jar"

# --- Step 2: pull in Mockito + ReflectionTestUtils' jar (spring-test). ------
# These are dependencies OF THE HARNESSES (Mockito fakes, and Spring's
# MockMvc/spring-test for the controller-level harnesses), not of
# id-repository's production code, so they're
# resolved here rather than by touching id-repository's own pom.xml -- same
# idea as pulling commons-collections in for vulnjava's deserialization
# level.
#
# dependency:copy-dependencies against identity-service's own pom, scoped
# to "test", copies the exact Mockito/spring-test versions id-repository's
# poms already pin -- plus their transitive deps (byte-buddy, objenesis) --
# straight into $OUT itself, rather than us guessing version numbers by
# hand or parsing a classpath string back out ourselves.
# Not run with -q: if this comes back with fewer jars than expected again,
# seeing Maven's own resolution output is more useful than another silent
# empty result.
mvn -pl id-repository-identity-service dependency:copy-dependencies \
    -DincludeScope=test -DoutputDirectory="$OUT" -DoverWriteIfNewer=true

# --- Step 2b: seed corpora, dictionaries, and fixtures. ---------------------
# Seeds: every seeds/<Name>/ directory that has a matching harness
# (<Name>.java) is zipped to <Name>_seed_corpus.zip (ClusterFuzz's naming
# convention, sitting next to the fuzz target in $OUT). Same mechanism
# vulnfuzz uses (seeds/ committed as loose files, zipped here at build time),
# but generic, so adding a harness's seeds needs no edit to this script.
# A seeds/ directory with no matching harness is skipped rather than shipped.
for seed_dir in "$SRC"/seeds/*/; do
  seed_name=$(basename "$seed_dir")
  if [ -f "$SRC/$seed_name.java" ] && [ -n "$(ls -A "$seed_dir")" ]; then
    zip -j "$OUT/${seed_name}_seed_corpus.zip" "$seed_dir"*
  fi
done
cp "$SRC"/*.dict "$OUT/"

# Fixtures: plain files harnesses load as classpath resources (e.g.
# identity-mapping.json, read by IdRepoFuzzSupport). Copied flat into $OUT,
# which the wrapper script puts on the runtime classpath ($this_dir).
cp "$SRC"/fixtures/* "$OUT/"

# --- Step 3: bundle a JDK 21 for the runner, then compile+wrap each --------
# harness so ClusterFuzz can run it like any other libFuzzer binary.
#
# The runner environment that actually executes a fuzz target
# (check_build/run_fuzzer locally, the real bots in production) ships an
# older JVM than 21, and it's not just our own bytecode that needs 21 --
# kernel-core and other MOSIP dependencies are published as Java 21
# bytecode too, so downgrading our own compile target doesn't help once
# execution reaches into them. Jazzer's own docs confirm its driver reads
# JAVA_HOME directly to find libjvm.so, so rather than fight the runner's
# JVM, we ship our own: copy the JDK 21 this image already has (installed
# in the Dockerfile) into $OUT, and point the wrapper script's JAVA_HOME at
# that copy instead of relying on whatever the runner provides.
cp -a "$JAVA_HOME" "$OUT/jdk21"

PROJECT_JARS=$(cd "$OUT" && ls *.jar)
BUILD_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH
RUNTIME_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# Compile ALL top-level .java files together (the *Fuzzer.java harnesses AND
# any shared helper such as IdRepoFuzzSupport.java, which deliberately does
# not end in "Fuzzer" so it is never wrapped as a fuzz target), then copy
# every resulting .class into $OUT. Compiling one harness at a time and
# copying only <Name>.class would drop helper classes and nested/anonymous
# classes (Foo$Bar.class), which fail at runtime with NoClassDefFoundError.
# -proc:none: nothing here needs annotation processing, and lombok and other
# processors are on the classpath via copy-dependencies above.
HARNESS_CLASSES="$SRC/harness-classes"
mkdir -p "$HARNESS_CLASSES"
javac -proc:none -cp $BUILD_CLASSPATH -d "$HARNESS_CLASSES" $(find "$SRC" -maxdepth 1 -name '*.java')
cp -r "$HARNESS_CLASSES"/. "$OUT/"

# Only count coverage in code we care about. Instrumenting every class that
# loads (Spring, Mockito, byte-buddy, ...) slows the run and dilutes the
# coverage signal. Jackson and JsonPath stay in so the fuzzer gets feedback
# from their parsers and learns to produce well-formed JSON.
INSTRUMENT_INCLUDES='io.mosip.**:com.fasterxml.jackson.**:com.jayway.jsonpath.**'

for fuzzer in $(find "$SRC" -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java "$fuzzer")

  echo "#!/bin/bash
this_dir=\$(dirname \"\$0\")
export JAVA_HOME=\$this_dir/jdk21
LD_LIBRARY_PATH=\"\$JAVA_HOME/lib/server\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--instrumentation_includes=\"$INSTRUMENT_INCLUDES\" \
--jvm_args=\"-Xmx2048m:-Xss1024k:-Djava.awt.headless=true\" \
\$@" > "$OUT/$fuzzer_basename"
  chmod +x "$OUT/$fuzzer_basename"
done
