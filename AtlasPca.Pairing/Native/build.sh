#!/usr/bin/env bash
# Builds blst plus the GT shim into ONE shared library named so that DllImport("blst.dll") finds both (libblst.dll.so on Linux),
# and copies the official C# binding from the same pinned source next to the project. Usage: build.sh <blst-checkout> <output-dir>
set -euo pipefail
BLST="${1:?blst checkout}"; OUT="${2:?output dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
test "$(git -C "$BLST" rev-parse HEAD)" = "e7f90de551e8df682f3cc99067d204d8b90d27ad" # v0.3.16
mkdir -p "$OUT" "$HERE/../Blst"
cp "$BLST/bindings/c#/supranational.blst.cs" "$HERE/../Blst/blst.cs"
cc -O2 -fPIC -shared -D__BLST_PORTABLE__ -I"$BLST/bindings" -o "$OUT/libblst.dll.so" \
  "$HERE/pca_gt.c" "$BLST/src/server.c" "$BLST/build/assembly.S"
