#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 VERSION ARCHIVE DIST_DIR" >&2
  exit 2
fi

version=$1
archive=$2
dist_dir=$3

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid formula version: $version" >&2
  exit 2
fi
if [[ ! -f $archive ]]; then
  echo "release archive does not exist: $archive" >&2
  exit 2
fi

mkdir -p "$dist_dir"
digest=$(openssl dgst -sha256 "$archive" | awk '{print $NF}')
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$digest/g" \
  packaging/netwhy.rb.in > "$dist_dir/netwhy.rb"
