# Contributing to Cenziadah

Contributions are welcome: bug reports, false-positive reports from real systems, detector
improvements and fixes.

## License and CLA

Cenziadah is licensed under the **GNU Affero General Public License v3.0 or later**
([LICENSE](LICENSE)). Before your first contribution can be merged, you must sign the
[Contributor License Agreement](CLA.md): add your line to [CLA-SIGNATURES.md](CLA-SIGNATURES.md)
in your first merge/pull request. The CLA lets the maintainer keep the licensing coherent (for
example, offer the code under additional terms); you keep the copyright in your work.

Every source file starts with:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile
```

New files must carry the same header (add your own copyright line below it for substantial new
work).

## False-positive reports

The most valuable contribution is a report of a false alert on a real system. Please include the
process detail from `watch --tui` (select the row, press Enter), the OS/distribution, and what
the program is. Remove anything private (hostnames, IPs, command-line secrets) first.

## Development

```bash
make all               # fmt + vet + build + unit tests
make compromise-test   # integration test against the deliberately vulnerable victim (needs sudo)
```

- Unit tests for every package; they run without root, against fixtures.
- Every change bumps the version in `internal/version` (SemVer) and adds a `CHANGELOG.md` entry.
- Security-sensitive rule (any suppression or learning): explain in the change why a compromised
  service account (e.g. `www-data`) cannot satisfy it.
- Keep dependencies minimal; the detection core must stay free of network code.

## Security issues

Do not open a public issue for a vulnerability in Cenziadah itself; contact the maintainer
privately first.
