#!/usr/bin/env bash
set -euo pipefail

archive="${1:?usage: smoke-test.sh IMAGE_ARCHIVE VARIANT [ARCH]}"
variant="${2:?usage: smoke-test.sh IMAGE_ARCHIVE VARIANT [ARCH]}"
arch="${3:-amd64}"
image="baseless:${variant}-${arch}"

docker load --input "${archive}" >/dev/null

user="$(docker image inspect "${image}" --format '{{.Config.User}}')"
if [[ "${variant}" == "debug" ]]; then
  test "${user}" = "0"
else
  test "${user}" = "65532"
fi

container_id="$(docker create "${image}" /nonexistent)"
rootfs="$(mktemp)"
trap 'docker rm -f "${container_id}" >/dev/null 2>&1 || true; rm -f "${rootfs}"' EXIT
docker export --output "${rootfs}" "${container_id}"

for required in \
  etc/os-release \
  etc/passwd \
  etc/localtime \
  etc/ssl/certs/ca-certificates.crt \
  usr/share/zoneinfo/Asia/Ho_Chi_Minh; do
  tar -tf "${rootfs}" "${required}" >/dev/null
done

for forbidden in sbin/apk usr/bin/apk; do
  if tar -tf "${rootfs}" "${forbidden}" >/dev/null 2>&1; then
    echo "forbidden path found: /${forbidden}" >&2
    exit 1
  fi
done

if [[ "${variant}" != "debug" ]]; then
  for forbidden in bin/sh usr/bin/sh; do
    if tar -tf "${rootfs}" "${forbidden}" >/dev/null 2>&1; then
      echo "forbidden path found: /${forbidden}" >&2
      exit 1
    fi
  done
fi

if [[ "${variant}" == "glibc" ]]; then
  for forbidden in usr/bin/ldd usr/lib/gconv; do
    if tar -tf "${rootfs}" "${forbidden}" >/dev/null 2>&1; then
      echo "optional glibc payload leaked into runtime: /${forbidden}" >&2
      exit 1
    fi
  done
  docker run --rm --entrypoint /usr/lib/libc.so.6 "${image}" | grep -q 'GNU C Library'
fi

if [[ "${variant}" == "debug" ]]; then
  docker run --rm "${image}" -c \
    'jq --version && curl --version && openssl version && ps --version && test -d /etc/terminfo && TERM=xterm top -b -n 1 >/dev/null'
fi

echo "${image}: smoke test passed"
