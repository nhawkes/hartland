#!/usr/bin/env bash
# Checks that the hermeticity lint passes the real tree and rejects every fixture.
# Run from a repository root that mounts the hartland cell.
set -uo pipefail
fail=0
out="$(buck2 bxl hartland//lint/pins.bxl:lint -- --pattern 'hartland//lint/fixtures:' 2>&1)"
if [ $? -eq 0 ]; then echo "FAIL: lint accepted the fixtures"; fail=1; fi
for want in \
    "fixtures:no-sha256: http_archive without sha256" \
    "fixtures:no-sha256: sha1 pins are not allowed" \
    "fixtures:sha1-and-sha256: sha1 pins are not allowed" \
    "fixtures:fetches: genrule cmd calls network fetcher(s): curl" \
    "fixtures:clones: genrule bash calls network fetcher(s): git" \
    "fixtures:net-prop: attribute exec_properties sets exec property dockerNetwork"; do
    grep -qF "$want" <<<"$out" || { echo "FAIL: missing: $want"; fail=1; }
done
if grep -q "ok-gitignore" <<<"$out"; then echo "FAIL: false positive on ok-gitignore"; fail=1; fi
buck2 bxl hartland//lint/pins.bxl:lint >/dev/null 2>&1 || { echo "FAIL: real tree not clean"; fail=1; }
[ $fail -eq 0 ] && echo "lint tests passed"
exit $fail
