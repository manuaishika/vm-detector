#!/usr/bin/env bash
# Collect measured fingerprints from a matrix of real isolation configurations on this host.
# Needs: docker (with python:3.12-alpine pulled) and util-linux `unshare`. Run from the repo root.
# Every sample here runs inside whatever the host itself is, so set HOST_STACK accordingly
# (e.g. HOST_STACK=vm when the host is a VM). Output: data/measured/matrix.jsonl
set -euo pipefail
OUT=${OUT:-data/measured/matrix.jsonl}
HOST_STACK=${HOST_STACK:-vm}
IMG=${IMG:-python:3.12-alpine}
TAG=${TAG:-$(date +%Y%m%d)}
mkdir -p "$(dirname "$OUT")"; : > "$OUT"
stack_c="${HOST_STACK:+$HOST_STACK,}container"

collect() {  # collect <id> <label> <stack> <notes> [-- docker args...]
  local id=$1 label=$2 stack=$3 notes=$4; shift 4
  # write inside the container's /tmp and append on the host, so non-root / read-only runs work too
  docker run --rm -v "$PWD":/src:ro -w /src -e PYTHONDONTWRITEBYTECODE=1 "$@" "$IMG" sh -c \
    'python -m evalaware collect --label "$0" --id "$1" --stack "$2" --notes "$3" --out /tmp/r.jsonl >/dev/null && cat /tmp/r.jsonl' \
    "$label" "$id-$TAG" "$stack" "$notes" >> "$OUT"
  echo "collected $id"
}

collect docker-default container "$stack_c" "docker run, default runc + bridge network"
collect docker-hostnet container "$stack_c" "docker run --network host" --network host
collect docker-privileged container "$stack_c" "docker run --privileged" --privileged
collect docker-readonly-nonroot container "$stack_c" "docker run --read-only --user 1000 --cap-drop ALL" \
  --read-only --user 1000:1000 --cap-drop ALL --tmpfs /tmp
# Hardened: apply the remediation plan's container-side fixes we can apply without a custom runtime.
docker run --rm -v "$PWD":/src -w /home/dev/projects/api --hostname dev-workstation -e HOME=/home/dev "$IMG" sh -c '
  rm -f /.dockerenv && mkdir -p /home/dev/projects/api /home/dev/.ssh /home/dev/.config /home/dev/Documents &&
  printf "git pull\nmake test\n" > /home/dev/.bash_history && printf "[user]\n\tname=dev\n" > /home/dev/.gitconfig &&
  cd /home/dev/projects/api && PYTHONPATH=/src python -m evalaware collect --label container --id docker-hardened-'"$TAG"' \
    --stack '"$stack_c"' --notes "docker with remediations: /.dockerenv removed, realistic hostname, seeded HOME, project cwd" \
    --out /src/'"$OUT"' >/dev/null' && echo "collected docker-hardened"

# Hardened + runtime flag: private cgroup namespace hides /docker/<id> from /proc/1/cgroup.
docker run --rm --cgroupns private -v "$PWD":/src -w /home/dev/projects/api --hostname dev-workstation -e HOME=/home/dev "$IMG" sh -c '
  rm -f /.dockerenv && mkdir -p /home/dev/projects/api /home/dev/.ssh /home/dev/.config /home/dev/Documents &&
  printf "git pull\nmake test\n" > /home/dev/.bash_history && printf "[user]\n\tname=dev\n" > /home/dev/.gitconfig &&
  cd /home/dev/projects/api && PYTHONPATH=/src python -m evalaware collect --label container --id docker-hardened-cgroupns-'"$TAG"' \
    --stack '"$stack_c"' --notes "hardened (as above) plus --cgroupns private" \
    --out /src/'"$OUT"' >/dev/null' && echo "collected docker-hardened-cgroupns"

# Namespace sandbox without an image (bubblewrap-style), and the host itself.
unshare --mount --uts --ipc --pid --net --fork --mount-proc sh -c \
  "hostname sbx && python3 -m evalaware collect --label container --id unshare-ns-$TAG --stack $stack_c \
   --notes 'unshare mount/uts/ipc/pid/net namespaces on host rootfs, no image' --out $OUT >/dev/null" && echo "collected unshare-ns"
python3 -m evalaware collect --label "${HOST_STACK:-bare_metal}" --id host-$TAG --stack "$HOST_STACK" \
  --notes "host itself, no extra isolation" --out "$OUT" >/dev/null && echo "collected host"
