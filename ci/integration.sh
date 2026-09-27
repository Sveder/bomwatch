#!/bin/sh
# End-to-end check on a real system: scan, install things, scan, diff.
set -eu

export BOMWATCH_STATE_DIR="$(mktemp -d)"
work="$(mktemp -d)"

bomwatch scan --root "$work"
python -m venv "$work/env"
"$work/env/bin/pip" install -q "jinja2==2.10"
npm install -g --silent left-pad@1.3.0
mkdir "$work/app" && (cd "$work/app" && npm init -y >/dev/null && npm install --silent is-number@7.0.0)
bomwatch scan --root "$work"

set +e
bomwatch diff > diff.txt
code=$?
set -e
cat diff.txt
test "$code" -eq 3
grep -q "^+ pip jinja2 2.10 ($work/env)" diff.txt
grep -q "^+ npm left-pad 1.3.0" diff.txt
grep -q "^+ npm-project is-number 7.0.0" diff.txt

# jinja2 2.10 has published advisories, so --vulns must find them.
set +e
bomwatch diff --vulns --json > vulns.json
code=$?
set -e
test "$code" -eq 4
python -c "
import json
data = json.load(open('vulns.json'))
assert any(v['package']['name'] == 'jinja2' for v in data['vulns']), data['vulns']
"

bomwatch export --format cyclonedx -o sbom.cdx.json
bomwatch export --format spdx -o sbom.spdx.json
python -c "
import json
cdx = json.load(open('sbom.cdx.json'))
assert any(c['purl'].startswith('pkg:deb/') for c in cdx['components'])
assert any(c['purl'] == 'pkg:pypi/jinja2@2.10' for c in cdx['components'])
spdx = json.load(open('sbom.spdx.json'))
assert spdx['spdxVersion'] == 'SPDX-2.3'
"

bomwatch log jinja2 | grep -q "+ pip jinja2 2.10"
bomwatch prune --keep 1
test "$(ls "$BOMWATCH_STATE_DIR/snapshots" | wc -l)" -eq 1
echo "integration ok"
