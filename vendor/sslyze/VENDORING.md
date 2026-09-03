# Vendored SSLyze

This directory contains the SSLyze 6.3.0 source distribution published at
<https://pypi.org/project/sslyze/6.3.0/>.

- Source artifact: `sslyze-6.3.0.tar.gz`
- SHA-256: `ce3ac4231de96e4ac02f1326fda856817dc39e6eac5d81efa2c4d3348da5ddb7`
- License: GNU Affero General Public License v3 (see `LICENSE.txt`)

## Local changes

The `cryptography` dependency in `setup.py` was changed from `>=43,<45` to
`>=43`. The application pins the version it supports in its root `Pipfile`.

All other files under this directory are copied unchanged from the source
distribution. To update SSLyze, replace the upstream files from a verified
source distribution, reapply the dependency change, update the provenance
above, and regenerate `Pipfile.lock`.
