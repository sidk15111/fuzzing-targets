# OSS-Fuzz-format Dockerfile for MOSIP's id-repository.
#
# Same base image as vulnjava: base-builder-jvm ships OpenJDK, Jazzer's
# driver/agent/api jars, and the $OUT / $SRC / $JAZZER_API_PATH /
# $JVM_LD_LIBRARY_PATH env vars build.sh relies on.
FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && apt-get install -y maven git

# id-repository pins maven.compiler.source/target to 21, but base-builder-jvm
# ships OpenJDK 15 by default -- javac refuses to target a release higher
# than the JDK actually running it ("invalid target release: 21"). Install
# a JDK 21 alongside the base image's JDK 15 and point JAVA_HOME at it,
# mirroring exactly how the base image wires up its own JDK
# (JAVA_HOME -> JVM_LD_LIBRARY_PATH -> PATH). Prepending to PATH (not
# appending) matters: the base image already put its own JDK 15 bin/ on
# PATH, so ours has to come first to actually win.
RUN wget -q https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4%2B7/OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7.tar.gz -O /tmp/jdk21.tar.gz \
    && mkdir -p /usr/lib/jvm/java-21-temurin \
    && tar -xzf /tmp/jdk21.tar.gz -C /usr/lib/jvm/java-21-temurin --strip-components=1 \
    && rm /tmp/jdk21.tar.gz
ENV JAVA_HOME=/usr/lib/jvm/java-21-temurin
ENV JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
ENV PATH=$JAVA_HOME/bin:$PATH

# Unlike vulnjava/vulnfuzz -- ours, so COPY'd in directly from our own repo --
# id-repository belongs to MOSIP. We don't fork it or commit anything into
# it; we just clone it fresh at image-build time, the same way any real
# OSS-Fuzz integration pulls in a project it doesn't own (e.g. curl,
# openssl). No ref is pinned below, so every rebuild tracks MOSIP's current
# master and will pick up newly-introduced bugs as they land. If you'd
# rather freeze a known-good revision instead (e.g. because a harness is
# fragile against upstream refactors), add:
#   && cd $SRC/id-repository && git checkout <commit-or-tag>
RUN git clone --depth 1 https://github.com/mosip/id-repository.git \
    $SRC/id-repository

# OSS-Fuzz plumbing -- harness files sit at $SRC root, sibling to the
# project source, matching the vulnjava layout. seeds/ (loose per-fuzzer
# seed files, see project README) and the two .dict files are committed
# in this repo the same way vulnfuzz commits seeds/ -- zipped into the
# actual *_seed_corpus.zip by build.sh, not pre-zipped here.
COPY *.java *.dict $SRC/
COPY seeds/ $SRC/seeds/
COPY build.sh $SRC/
