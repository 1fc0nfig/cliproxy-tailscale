#!/usr/bin/env bash
# Package plugin libraries into CLIProxyAPI plugin store release assets.
#
# Usage: scripts/package.sh <id> <version> <bin-dir> <dist-dir>
#
# Input:  <bin-dir>/<goos>/<goarch>/<id>-v<version>.{so,dylib,dll}
# Output: <dist-dir>/<id>_<version>_<goos>_<goarch>.zip, each with exactly one
#         library at the zip root named <id>.<ext>, plus <dist-dir>/checksums.txt
#         in sha256sum format.
set -euo pipefail

id=${1:?id}
version=${2:?version}
bin_dir=${3:?bin dir}
dist_dir=${4:?dist dir}

if ! [[ $version =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
  echo "version '$version' must be dotted numeric, without a leading v" >&2
  exit 1
fi

mkdir -p "$dist_dir"
dist_dir=$(cd "$dist_dir" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

count=0
shopt -s nullglob
for lib in "$bin_dir"/*/*/"$id-v$version".{so,dylib,dll}; do
  goarch=$(basename "$(dirname "$lib")")
  goos=$(basename "$(dirname "$(dirname "$lib")")")
  ext=${lib##*.}
  case "$goos/$ext" in
    linux/so | darwin/dylib | windows/dll) ;;
    *) echo "unexpected library $lib for $goos" >&2; exit 1 ;;
  esac
  zip_name="${id}_${version}_${goos}_${goarch}.zip"
  dir="$stage/$goos-$goarch"
  mkdir -p "$dir"
  cp "$lib" "$dir/$id.$ext"
  chmod 0755 "$dir/$id.$ext"
  rm -f "$dist_dir/$zip_name"
  # Zip from inside the stage dir so the library sits at the zip root.
  # -X: no extra attributes, -D: no directory entries.
  (cd "$dir" && zip -q -X -D "$dist_dir/$zip_name" "$id.$ext")
  entries=$(unzip -Z1 "$dist_dir/$zip_name")
  if [[ $entries != "$id.$ext" ]]; then
    echo "bad layout in $zip_name: $entries" >&2
    exit 1
  fi
  echo "packaged $zip_name"
  count=$((count + 1))
done

if [[ $count -eq 0 ]]; then
  echo "no libraries found under $bin_dir for $id v$version" >&2
  exit 1
fi

cd "$dist_dir"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -- *.zip >checksums.txt
else
  shasum -a 256 -- *.zip >checksums.txt
fi
echo "wrote checksums.txt ($count archives)"
