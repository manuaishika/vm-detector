#!/usr/bin/env bash
# Collect measured fingerprints from a matrix of real isolation configurations on this host.
# Needs: docker (with $IMG pulled) and util-linux `unshare`. Run from the repo root.
# Every sample runs inside whatever the host is, so set HOST_STACK (default: vm).
# Each configuration is sampled REPEATS times; repeats share a `group` so cross-validation holds
# out whole configurations. Output: data/measured/matrix.jsonl (overwritten).
set -euo pipefail
OUT=${OUT:-data/measured/matrix.jsonl}
HOST_STACK=${HOST_STACK:-vm}
IMG=${IMG:-python:3.12-alpine}
TAG=${TAG:-$(date +%Y%m%d)}
REPEATS=${REPEATS:-3}
mkdir -p "$(dirname "$OUT")"; : > "$OUT"
stack_c="${HOST_STACK:+$HOST_STACK,}container"
COUNT=0

# collect <name> <label> <stack> <notes> [docker run args...]
collect() {
  local name=$1 label=$2 stack=$3 notes=$4; shift 4
  for r in $(seq 1 "$REPEATS"); do
    docker run --rm -v "$PWD":/src:ro -w /src -e PYTHONDONTWRITEBYTECODE=1 "$@" "$IMG" sh -c \
      'python -m evalaware collect --label "$0" --id "$1" --group "$2" --stack "$3" --notes="$4" --out /tmp/r.jsonl >/dev/null && cat /tmp/r.jsonl' \
      "$label" "$name-$TAG-r$r" "$name" "$stack" "$notes" >> "$OUT"
    COUNT=$((COUNT+1))
  done
  echo "collected $name x$REPEATS"
}

# hardened <name> <notes> [docker run args...]: apply every container-side remediation we can without a custom runtime
hardened() {
  local name=$1 notes=$2; shift 2
  for r in $(seq 1 "$REPEATS"); do
    docker run --rm -v "$PWD":/src -w /home/dev/projects/api --hostname dev-workstation -e HOME=/home/dev -e PYTHONDONTWRITEBYTECODE=1 "$@" "$IMG" sh -c '
      rm -f /.dockerenv && mkdir -p /home/dev/projects/api /home/dev/.ssh /home/dev/.config /home/dev/Documents &&
      printf "git pull\nmake test\n" > /home/dev/.bash_history && printf "[user]\n\tname=dev\n" > /home/dev/.gitconfig &&
      cd /home/dev/projects/api && PYTHONPATH=/src python -m evalaware collect --label container --id "$0" --group "$1" \
        --stack "$2" --notes="$3" --out /tmp/r.jsonl >/dev/null && cat /tmp/r.jsonl' \
      "$name-$TAG-r$r" "$name" "$stack_c" "$notes" >> "$OUT"
  done
  echo "collected $name x$REPEATS"
}

# --- containers: label = innermost boundary (namespaces + cgroups) ---
collect docker-default      container "$stack_c" "docker run, default runc + bridge network"
collect docker-hostnet      container "$stack_c" "--network host" --network host
collect docker-nonet        container "$stack_c" "--network none" --network none
collect docker-privileged   container "$stack_c" "--privileged" --privileged
collect docker-readonly-nonroot container "$stack_c" "--read-only --user 1000 --cap-drop ALL" \
  --read-only --user 1000:1000 --cap-drop ALL --tmpfs /tmp
collect docker-init         container "$stack_c" "--init (tini as PID 1)" --init
collect docker-pidhost      container "$stack_c" "--pid host (host process list visible)" --pid host
collect docker-uts-ipc-host container "$stack_c" "--uts host --ipc host" --uts host --ipc host
collect docker-seccomp-off  container "$stack_c" "--security-opt seccomp=unconfined apparmor=unconfined" \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined
collect docker-limits       container "$stack_c" "--memory 256m --cpus 1 --pids-limit 128" --memory 256m --cpus 1 --pids-limit 128
collect docker-cgroupns-host container "$stack_c" "--cgroupns host" --cgroupns host
hardened docker-hardened         "docker + remediations: marker file removed, realistic hostname, seeded HOME, project cwd"
hardened docker-hardened-cgroupns "hardened + --cgroupns private" --cgroupns private
hardened docker-hardened-hostnet "hardened + --network host" --network host

# --- namespace sandboxes without an image ---
for r in $(seq 1 "$REPEATS"); do
  unshare --mount --uts --ipc --pid --net --fork --mount-proc sh -c \
    "hostname sbx && python3 -m evalaware collect --label container --id unshare-ns-$TAG-r$r --group unshare-ns --stack $stack_c \
     --notes 'unshare mount/uts/ipc/pid/net namespaces on the host rootfs, no image, no cgroup' --out $OUT >/dev/null"
done; echo "collected unshare-ns x$REPEATS"
for r in $(seq 1 "$REPEATS"); do
  unshare --pid --fork --mount-proc sh -c \
    "python3 -m evalaware collect --label container --id unshare-pid-$TAG-r$r --group unshare-pid --stack $stack_c \
     --notes 'unshare --pid only' --out $OUT >/dev/null"
done; echo "collected unshare-pid x$REPEATS"

# --- chroot: no namespaces, no cgroups => adds no isolation boundary => label = host stack ---
# Two variants: the raw `docker export` tree (carries /.dockerenv as image residue) and a cleaned one.
CR=$(mktemp -d); docker export "$(docker create "$IMG")" | tar -x -C "$CR" 2>/dev/null
mkdir -p "$CR/src" "$CR/proc"; mount --bind "$PWD" "$CR/src"; mount -t proc proc "$CR/proc" 2>/dev/null || true
chroot_collect() {  # chroot_collect <group> <notes>
  for r in $(seq 1 "$REPEATS"); do
    chroot "$CR" sh -c "rm -f /tmp/r.jsonl; cd /src && PYTHONDONTWRITEBYTECODE=1 python -m evalaware collect --label ${HOST_STACK:-bare_metal} \
      --id $1-$TAG-r$r --group $1 --stack '$HOST_STACK' --notes='$2' --out /tmp/r.jsonl >/dev/null && cat /tmp/r.jsonl" >> "$OUT"
  done; echo "collected $1 x$REPEATS"
}
chroot_collect chroot-export "chroot of a raw docker-export tree (still contains /.dockerenv), no namespaces"
rm -f "$CR/.dockerenv"
chroot_collect chroot-clean "chroot of the same tree with /.dockerenv removed, no namespaces"
umount "$CR/proc" 2>/dev/null || true; umount "$CR/src"; rm -rf "$CR"

# --- the host itself ---
for r in $(seq 1 "$REPEATS"); do
  python3 -m evalaware collect --label "${HOST_STACK:-bare_metal}" --id "host-$TAG-r$r" --group host --stack "$HOST_STACK" \
    --notes "host itself, no extra isolation (dockerd running)" --out "$OUT" >/dev/null
done; echo "collected host x$REPEATS"
wc -l < "$OUT"
