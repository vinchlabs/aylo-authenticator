#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

CC_BIN=${CC:-gcc}

"$CC_BIN" -std=c11 -Wall -Wextra -Werror \
  -I"$ROOT/core/embed/projects/headless" \
  "$ROOT/core/embed/projects/headless/tests/test_protocol.c" \
  "$ROOT/core/embed/projects/headless/protocol.c" \
  -o "$TMP_DIR/protocol-test"
"$TMP_DIR/protocol-test"

"$CC_BIN" -std=gnu2x -Wall -Wextra -Werror -DNDEBUG \
  -idirafter "$ROOT/core/embed/rtl/inc" \
  -I"$ROOT/core/embed/rtl" \
  "$ROOT/core/embed/projects/headless/tests/test_cli_limit.c" \
  "$ROOT/core/embed/rtl/cli.c" \
  "$ROOT/core/embed/rtl/strutils.c" \
  "$ROOT/core/embed/rtl/printf.c" \
  -lm -o "$TMP_DIR/cli-limit-test"
"$TMP_DIR/cli-limit-test"

"$CC_BIN" -std=c11 -Wall -Wextra -Werror -DLOCKABLE_BOOTLOADER \
  -I"$ROOT/core/embed/projects/bootloader" \
  -I"$ROOT/core/embed/projects/bootloader/protob/pb" \
  -I"$ROOT/core/embed/sys/startup/inc" \
  -I"$ROOT/core/embed/sys/task/inc" \
  -I"$ROOT/core/embed/sys/mpu/inc" \
  -I"$ROOT/core/embed/rtl/inc" \
  -I"$ROOT/vendor/nanopb" \
  "$ROOT/core/embed/projects/bootloader/tests/test_headless_boot_policy.c" \
  "$ROOT/core/embed/projects/bootloader/headless_boot_policy.c" \
  -o "$TMP_DIR/boot-policy-test"
"$TMP_DIR/boot-policy-test"

CARGO_TARGET_DIR="$ROOT/core/build-xtask" \
  cargo test --manifest-path "$ROOT/core/embed/Cargo.toml" --package xtask
xtask test rtl
xtask check bootloader -m t3t1 --bootloader-devel
xtask check bootloader -m t3t1 --production
xtask build headless -m t3t1 --bootloader-devel
xtask build bootloader -m t3t1 --bootloader-devel --headless-dev
python "$ROOT/core/embed/projects/headless/tools/audit_artifacts.py"
git -C "$ROOT" diff --check

printf 'TS5 headless offline checks: PASS\n'
