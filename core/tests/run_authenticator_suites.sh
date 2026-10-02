#!/usr/bin/env bash
# Run every authenticator applet suite and total the tests.
cd "$(dirname "$0")" || exit 1
export PYTHONPATH=../src
# Pinned, not plain `python3`. These suites put core/src on PYTHONPATH, where the
# firmware's own `typing` mock shadows the standard library's. CPython 3.13's asyncio
# imports typing at startup and dies on the mock, so whichever venv happens to be
# active would otherwise decide whether the suite runs at all. 3.10 is what these
# mocks were written against. Override with PY= for a different one.
PY="${PY:-/usr/bin/python3}"
total=0
bad=0
for f in test_apps.authenticator.*.py; do
  out=$("$PY" -B "$f" 2>&1)
  n=$(printf '%s' "$out" | grep -oP 'Ran \K[0-9]+' | tail -1)
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  %-52s %3s OK\n' "$f" "${n:-?}"
    total=$((total + ${n:-0}))
  else
    printf '  %-52s %3s FAIL\n' "$f" "${n:-?}"
    printf '%s\n' "$out" | tail -25
    bad=$((bad + 1))
  fi
done
echo "---"
echo "applet tests: $total   failing suites: $bad"
[ "$bad" -eq 0 ]
