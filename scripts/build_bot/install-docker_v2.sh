#!/bin/bash
set -e
# GCE startup-script - runs once at boot, as root.
# Installs the generic tooling needed to build ANY oss-fuzz-style
# project. Contains nothing project-specific.

apt-get update
apt-get install -y docker.io git unzip zip python3 apt-transport-https ca-certificates gnupg curl

# --- Google Cloud CLI (bundles gcloud + gsutil + bq together) ---
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
  > /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y google-cloud-cli

# Fail loudly, at boot, in the serial console - not silently, hours
# later, when a scheduled build tries to upload and can't.
command -v gsutil >/dev/null || { echo "FATAL: gsutil missing after google-cloud-cli install"; exit 1; }
command -v zip    >/dev/null || { echo "FATAL: zip missing"; exit 1; }

# --- Docker, usable without sudo, for whoever logs in ---
# A fixed `usermod -aG docker <name>` is unreliable here: with OS Login,
# the actual login account frequently doesn't exist yet at boot time -
# it gets created on first SSH. Relaxing the socket's own permission
# instead works for anyone who eventually logs in, regardless of when
# their account is created or what it ends up being named. Trade-off
# worth knowing: this gives docker (and therefore root-equivalent)
# access to any user who can reach this box - acceptable for a
# single-purpose internal build bot, not something I'd do on anything
# more broadly shared.
mkdir -p /etc/systemd/system/docker.socket.d
cat > /etc/systemd/system/docker.socket.d/override.conf << 'EOF'
[Socket]
SocketMode=0666
EOF
systemctl daemon-reload
systemctl restart docker.socket

# --- Generic build tooling - nothing project-specific below this line ---
TOOLS_ROOT=/opt/build-tools
mkdir -p "$TOOLS_ROOT"

git clone https://github.com/google/oss-fuzz.git "$TOOLS_ROOT/oss-fuzz"

curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/orchestrator-script" \
  -o "$TOOLS_ROOT/build_and_upload.sh"
chmod +x "$TOOLS_ROOT/build_and_upload.sh"

# Same reasoning as the docker.socket override above: everything under
# $TOOLS_ROOT was just created by root (this whole script runs as root at
# boot), but build_and_upload.sh runs later over SSH as whatever
# non-root, dynamically-provisioned OS Login account eventually connects
# -- an account that doesn't exist yet at this point in the boot, so
# there's no specific username to chown this to in advance. It needs to
# create a new workspace directory here (git clone) and write into the
# existing oss-fuzz checkout (symlinks under projects/, build output
# under build/), so the whole tree needs to be writable by whoever logs
# in, not just readable.
chmod -R 777 "$TOOLS_ROOT"

# Readiness marker -- SSH becoming reachable does NOT mean this script has
# finished (sshd comes up well before apt-get/git-clone below it are
# done). Whatever provisions this bot should poll for this file's
# existence over SSH, not just for SSH itself, before trying to run a
# build on it.
touch "$TOOLS_ROOT/READY"
