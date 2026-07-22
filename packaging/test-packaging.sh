#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")/.."

bash -n packaging/build-linux-packages.sh
bash -n packaging/build-homebrew-formula.sh
grep -q '@VERSION@' packaging/debian-control.in
grep -q '@RPM_VERSION@' packaging/netwhy.spec.in
grep -q '@RPM_RELEASE@' packaging/netwhy.spec.in
grep -q '@SHA256@' packaging/netwhy.rb.in

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/tools" "$stage/dist"

printf '#!/bin/sh\nexit 0\n' > "$stage/netwhy"
chmod 0755 "$stage/netwhy"
printf 'archive fixture\n' > "$stage/archive.tar.gz"

cat > "$stage/tools/dpkg-deb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=${@: -2:1}
output=${@: -1}
grep -Fx 'Version: 1.2.3~rc.1' "$root/DEBIAN/control" >/dev/null
grep -Fx 'Architecture: amd64' "$root/DEBIAN/control" >/dev/null
: > "$output"
EOF

cat > "$stage/tools/rpmbuild" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
spec=${@: -1}
topdir=
for argument in "$@"; do
  if [[ $argument == '_topdir '* ]]; then
    topdir=${argument#_topdir }
  fi
done
test -n "$topdir"
grep -Fx 'Version:        1.2.3' "$spec" >/dev/null
grep -Fx 'Release:        0.rc.1.1%{?dist}' "$spec" >/dev/null
grep -Fx 'BuildArch:      x86_64' "$spec" >/dev/null
mkdir -p "$topdir/RPMS/x86_64"
: > "$topdir/RPMS/x86_64/netwhy-1.2.3-0.rc.1.1.x86_64.rpm"
EOF
chmod 0755 "$stage/tools/dpkg-deb" "$stage/tools/rpmbuild"

PATH="$stage/tools:$PATH" packaging/build-linux-packages.sh \
  1.2.3-rc.1 x86_64-unknown-linux-gnu "$stage/netwhy" "$stage/dist"

test -f "$stage/dist/netwhy_1.2.3-rc.1_amd64.deb"
test -f "$stage/dist/netwhy-1.2.3-0.rc.1.1.x86_64.rpm"
(
  cd "$stage/dist"
  sha256sum -c netwhy-v1.2.3-rc.1-x86_64-unknown-linux-gnu-packages.sha256
)

packaging/build-homebrew-formula.sh \
  1.2.3-rc.1 "$stage/archive.tar.gz" "$stage/dist"
grep -F 'version "1.2.3-rc.1"' "$stage/dist/netwhy.rb" >/dev/null
grep -F 'netwhy-v1.2.3-rc.1-aarch64-apple-darwin.tar.gz' "$stage/dist/netwhy.rb" >/dev/null
! grep -Eq '@(VERSION|SHA256)@' "$stage/dist/netwhy.rb"
