# CRS regression tests

`regression-4.7.0.json` is the OWASP CRS project's own regression suite for the
CRS version shipped in `../rules` — `tests/regression/tests` of the
`coreruleset` v4.7.0 release (Apache-2.0, see `../LICENSE`), unmodified, bundled
as JSON so the runner needs no YAML parser. `meta.suite_sha256` is the SHA-256
over the YAML files it was made from.

It is run by `deploy/load-test/crs-regression.sh` (the `crs-regression` CI job)
and gated against `deploy/load-test/crs-regression-baseline.json`.

Regenerate it in the same change that upgrades the shipped CRS, from that
release's tests (PyYAML required):

    deploy/load-test/crs-regression.py --export <coreruleset-X.Y.Z>/tests/regression/tests \
        --suite-version X.Y.Z rules/owasp-crs/tests/regression-X.Y.Z.json

then point `SUITE` in `crs-regression.sh` at the new file and write a new
baseline: the suite changed, so the old baseline no longer applies (the gate
exits 2 on a suite mismatch).
