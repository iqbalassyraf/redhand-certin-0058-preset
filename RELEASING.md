# Releasing

A release is cut by pushing a version tag. **Pushing a `v*.*.*` tag triggers
`.github/workflows/release.yml`, which builds the distributions, generates an SBOM and Sigstore
build-provenance attestations, and publishes to PyPI.** Publishing cannot be undone (a PyPI
version can be yanked but never reused), so a person decides when to tag; nothing in this
repository tags automatically.

## Before tagging

1. **Branch is green.** CI passes on the commit you will tag: lint, format, `mypy --strict`, the
   test matrix with the 97% coverage floor, and the wheel smoke test (which also runs the
   documented quickstart against the built wheel).
2. **Version is consistent.** `pyproject.toml`, `redhand_fintech_shield.__version__`, the gateway's
   default `server_version` and `uv.lock` all carry the new version, and `SECURITY.md` lists it as
   supported. `pytest` fails if the package and the recorded measurements disagree.
3. **Generated files are current.** Run each command and commit the result:

```bash
redhand-shield replay --markdown docs/detection-results.md
redhand-shield api --out docs/public_api.json
python scripts/release_numbers.py --measure   # slow: runs the benchmark and the full suite
python scripts/release_numbers.py --render
python scripts/build_docs.py
```

4. **Changelog.** `CHANGELOG.md` has a dated entry for the version, with Added, Changed, Fixed and
   any Removed or Deprecated items.
5. **Numbers are honest.** Read `docs/announcement.md`. Every figure comes from a command; the
   machine-dependent ones say so. Re-run `--measure` on a quiet machine if a latency figure looks
   off, and never edit the announcement by hand.
6. **Clean install check.** Build and try the wheel the way a user would:

```bash
uv build
python -m venv /tmp/rel-check
/tmp/rel-check/bin/pip install dist/*.whl
python scripts/run_quickstart.py --python /tmp/rel-check/bin/python
/tmp/rel-check/bin/redhand-shield --version
/tmp/rel-check/bin/redhand-shield doctor
/tmp/rel-check/bin/redhand-shield schema --check
```

## Tagging

```bash
git switch main && git pull --ff-only
git tag -s v0.3.0 -m "v0.3.0"      # or -a if you do not sign tags
git push origin v0.3.0
```

## After tagging

1. Watch the **Release** workflow. It must finish all of: build, SBOM, attestations, upload, and
   PyPI publish.
2. Check PyPI shows the new version and that `pip install redhand-certin-0058-preset==0.3.0` works
   in a fresh environment.
3. Verify the provenance attestation for the downloaded wheel:

```bash
gh attestation verify redhand_certin_0058_preset-0.3.0-py3-none-any.whl \
  --repo iqbalassyraf/redhand-certin-0058-preset
```

4. Create the GitHub release from the tag, using the changelog entry and linking the announcement.
5. Start a new `## [Unreleased]` section in the changelog if one is not there.

## If something goes wrong

- A failed workflow before the PyPI step: fix forward on `main`, delete the remote tag
  (`git push origin :refs/tags/v0.3.0`) and the local one, and tag again.
- A bad release already on PyPI: yank it on PyPI, publish a fixed patch version, and say why in the
  changelog. Do not reuse the version number.
