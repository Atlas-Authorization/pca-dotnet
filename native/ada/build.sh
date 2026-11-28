#!/usr/bin/env bash
# Builds libatlasada (Ada + the C shim) from the pinned single-file release into <outdir>; prints the library path on the last line.
# Usage: build.sh <outdir>
set -euo pipefail
out="${1:?usage: build.sh <outdir>}"
here="$(cd "$(dirname "$0")" && pwd)"
tag="${ADA_TAG:-v4.0.0}"
cpp_sha="${ADA_CPP_SHA256:-1c722f8f5355d6bf2bf3601870684edc875aa8f56b4d4735440d96263dd0207c}"
h_sha="${ADA_H_SHA256:-0010b17b3ff489e13998e86d921b16e1643e370ee3276c584f1b0c4b72bdf628}"
mkdir -p "$out"
base="https://github.com/ada-url/ada/releases/download/$tag"
curl -fsSL -o "$out/ada.cpp" "$base/ada.cpp"
curl -fsSL -o "$out/ada.h" "$base/ada.h"
echo "$cpp_sha  $out/ada.cpp" | shasum -a 256 -c - >&2
echo "$h_sha  $out/ada.h" | shasum -a 256 -c - >&2
# ATLAS_ADA_CXXFLAGS adds target flags (e.g. "-arch x86_64" to cross-build on an arm64 Mac).
extra="${ATLAS_ADA_CXXFLAGS:-}"
case "$(uname -s)" in
  Darwin) lib="$out/libatlasada.dylib"; flags="-dynamiclib" ;;
  MINGW*|MSYS*|CYGWIN*)
    lib="$out/atlasada.dll"
    w() { cygpath -w "$1"; }
    cl //nologo //std:c++20 //O2 //EHsc //LD //I"$(w "$out")" "$(w "$out/ada.cpp")" "$(w "$here/ada_shim.cpp")" //Fe:"$(w "$lib")" //Fo:"$(w "$out")\\" >&2
    echo "$lib"; exit 0 ;;
  *) lib="$out/libatlasada.so"; flags="-shared -static-libstdc++ -static-libgcc" ;;
esac
# shellcheck disable=SC2086
${CXX:-c++} -std=c++20 -O2 -fPIC $flags $extra -I"$out" "$out/ada.cpp" "$here/ada_shim.cpp" -o "$lib" >&2
echo "$lib"
