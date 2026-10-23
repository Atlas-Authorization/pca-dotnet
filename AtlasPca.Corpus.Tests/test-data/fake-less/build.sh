#!/usr/bin/env bash
# Builds the fake libatlas_less variants used by the gated R9KillTests.LoadRefusesALibraryWithOtherSizesOrNoVerifyExport:
#   libfake_ok.so       reports the less-252-45 sizes and exports verify (must load)
#   libfake_badpk.so    wrong public-key size       libfake_badmin.so  wrong signature minimum
#   libfake_badmax.so   wrong signature maximum     libfake_noverify.so correct sizes, no atlas_less_cat1_verify export
# usage: build.sh <outdir>; then ATLAS_PCA_FAKELESS_DIR=<outdir> dotnet test --filter R9KillTests
set -euo pipefail
out="${1:?outdir}"; mkdir -p "$out"; tmp="$(mktemp -d)"
gen() { # name pk min max withverify
  cat > "$tmp/$1.c" <<C
#include <stddef.h>
size_t atlas_less_cat1_public_key_bytes(void) { return $2; }
size_t atlas_less_cat1_signature_min_bytes(void) { return $3; }
size_t atlas_less_cat1_signature_max_bytes(void) { return $4; }
C
  [ "$5" = 1 ] && echo 'int atlas_less_cat1_verify(const unsigned char *a, size_t b, const unsigned char *c, size_t d, const unsigned char *e, size_t f) { return 1; }' >> "$tmp/$1.c"
  "${CC:-cc}" -shared -fPIC -o "$out/libfake_$1.so" "$tmp/$1.c"
}
gen ok 97484 1153 1329 1
gen badpk 97485 1153 1329 1
gen badmin 97484 1154 1329 1
gen badmax 97484 1153 1330 1
gen noverify 97484 1153 1329 0
rm -rf "$tmp"
