#!/usr/bin/env bash
# Rebuild the authenticator, write down what the build was, and hold the artifact to
# it. Read-only with respect to the device: nothing here flashes, signs for
# production, or touches an option byte.
#
# Usage:
#   reproduce-release.sh IMAGE UNSIGNED MODE SECURITY_VERSION OUT_DIR [BUILD_COMMAND]
#
# The second build is the point. A single build that hashes to itself proves nothing;
# what matters is that a clean rebuild of the recorded commit produces the same
# unsigned payload byte for byte. This script does the comparison when it is given a
# previous record to compare against, and says plainly when it cannot.
set -uo pipefail

IMAGE="${1:?image path}"
UNSIGNED="${2:?unsigned payload path}"
MODE="${3:?development|production}"
VERSION="${4:?security version}"
OUT="${5:?output directory}"
# The command that produced IMAGE, recorded verbatim so a second party can repeat it.
# A record whose build command does not reproduce the artifact is not a record.
BUILD_COMMAND="${6:-cargo run -p xtask -- build authenticator -m t3t1 --assumed-presence}"

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE"
mkdir -p "$OUT"

echo "########## 1. the record ##########"
python3 -B "$TOOLS/release_record.py" \
  --image "$IMAGE" --unsigned "$UNSIGNED" --mode "$MODE" \
  --security-version "$VERSION" \
  --build-command "$BUILD_COMMAND" \
  --out "$OUT/release.json" || exit 1

echo
echo "########## 2. the artifact audit ##########"
echo "audit_image.py is run separately: it needs the map, elf and frozen inputs that"
echo "only the build directory has. Run it on every build, not just on releases:"
echo "  audit_image.py --map <authenticator.map> --kernel-elf <kernel.elf> \\"
echo "                 --image <authenticator.bin> --frozen <frozen_mpy.c>"

echo
echo "########## 3. the release audit ##########"
python3 -B "$TOOLS/audit_release.py" --record "$OUT/release.json" --image "$IMAGE"
STATUS=$?
echo "RELEASE_AUDIT_STATUS=$STATUS"

echo
echo "########## 4. reproducibility ##########"
if [ -f "$OUT/previous.json" ]; then
  BEFORE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unsigned_sha256"])' "$OUT/previous.json")
  AFTER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unsigned_sha256"])' "$OUT/release.json")
  if [ "$BEFORE" = "$AFTER" ]; then
    echo "REPRODUCED=yes  unsigned payload $AFTER"
  else
    echo "REPRODUCED=no   previous $BEFORE, now $AFTER"
    STATUS=1
  fi
else
  echo "REPRODUCED=unknown  no previous.json to compare against."
  echo "  Copy this run's release.json to $OUT/previous.json, rebuild from a clean"
  echo "  tree, and run this again. One build cannot establish reproducibility."
fi

echo
echo "RELEASE_GATE_STATUS=$STATUS"
exit $STATUS
