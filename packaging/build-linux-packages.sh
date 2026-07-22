#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )); then
  echo "usage: $0 VERSION TARGET BINARY DIST_DIR" >&2
  exit 2
fi

version=$1
target=$2
binary=$3
dist_dir=$4

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid package version: $version" >&2
  exit 2
fi

deb_version=${version/-/\~}
rpm_version=${version%%-*}
rpm_release=1
if [[ $version == *-* ]]; then
  rpm_suffix=${version#*-}
  rpm_release="0.${rpm_suffix//-/.}.1"
fi
if [[ ! -x $binary ]]; then
  echo "release binary is not executable: $binary" >&2
  exit 2
fi

case "$target" in
  x86_64-unknown-linux-gnu)
    deb_arch=amd64
    rpm_arch=x86_64
    ;;
  aarch64-unknown-linux-gnu)
    deb_arch=arm64
    rpm_arch=aarch64
    ;;
  *)
    echo "unsupported Linux package target: $target" >&2
    exit 2
    ;;
esac

mkdir -p "$dist_dir"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT

deb_root="$stage/deb/netwhy_${version}_${deb_arch}"
install -D -m 0755 "$binary" "$deb_root/usr/bin/netwhy"
install -D -m 0644 LICENSE "$deb_root/usr/share/doc/netwhy/LICENSE"
install -D -m 0644 README.md "$deb_root/usr/share/doc/netwhy/README.md"
mkdir -p "$deb_root/DEBIAN"
sed -e "s/@VERSION@/$deb_version/g" -e "s/@ARCH@/$deb_arch/g" \
  packaging/debian-control.in > "$deb_root/DEBIAN/control"
dpkg-deb --build --root-owner-group "$deb_root" "$dist_dir/netwhy_${version}_${deb_arch}.deb"

rpm_top="$stage/rpmbuild"
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
install -m 0755 "$binary" "$rpm_top/SOURCES/netwhy"
install -m 0644 LICENSE README.md "$rpm_top/SOURCES/"
sed -e "s/@RPM_VERSION@/$rpm_version/g" -e "s/@RPM_RELEASE@/$rpm_release/g" \
  -e "s/@ARCH@/$rpm_arch/g" \
  packaging/netwhy.spec.in > "$rpm_top/SPECS/netwhy.spec"
rpmbuild -bb \
  --define "_topdir $rpm_top" \
  --define "_sourcedir $rpm_top/SOURCES" \
  "$rpm_top/SPECS/netwhy.spec"
find "$rpm_top/RPMS" -type f -name '*.rpm' -exec cp '{}' "$dist_dir/" \;

(
  cd "$dist_dir"
  sha256sum ./*.deb ./*.rpm > "netwhy-v${version}-${target}-packages.sha256"
)
