# EDRGAP — EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `blue-team`

[![install](https://img.shields.io/badge/install-git%2B%20%C2%B7%20pipx%20%C2%B7%20uv-6b46c1.svg)](#install--every-way-every-platform)
[![CI](https://github.com/cognis-digital/edrgap/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/edrgap/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories.**

*Blue Team / Defense — detection, deception, and monitoring for small teams.*

<!-- cognis:layman:start -->
## What is this?

EDRGAP helps security teams find computers in their organization that are missing or have broken antivirus/endpoint protection (called an EDR agent). You point it at your device lists — from Active Directory, your mobile device manager, or your EDR platform — and it cross-references them to show you exactly which machines have no protection, which have a broken or silent agent, and which devices showed up out of nowhere. It produces a plain summary table, a JSON report, or a file you can drop straight into GitHub's code-scanning dashboard, and it is designed for small security teams who want a quick, scriptable answer without deploying complex infrastructure.
<!-- cognis:layman:end -->

## Why

Security and intelligence teams need EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories without standing up heavyweight infrastructure. `edrgap` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

<!-- cognis:install:start -->
## Install

`edrgap` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/edrgap/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/edrgap/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/edrgap.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/edrgap.git"  # uv
pip install "git+https://github.com/cognis-digital/edrgap.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/edrgap.git
cd edrgap && pip install .
```

Then run:
```sh
edrgap --help
```
<!-- cognis:install:end -->

## Install

```bash
pip install "git+https://github.com/cognis-digital/edrgap.git"
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
edrgap --version
edrgap scan demos/                      # run against the bundled demo
edrgap scan demos/ --format sarif --out r.sarif --fail-on high
edrgap scan demos/ --format html --out report.html
edrgap mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-basic/`](demos/01-basic/SCENARIO.md)
- [`demos/01-enterprise-200-endpoints/`](demos/01-enterprise-200-endpoints/SCENARIO.md)
- [`demos/02-acquisition-merge/`](demos/02-acquisition-merge/SCENARIO.md)
- [`demos/03-clean-shop/`](demos/03-clean-shop/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## How it fits the Cognis Neural Suite

`edrgap` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `blue-team`:** [`sentrylog`](https://github.com/cognis-digital/sentrylog), [`canarynet`](https://github.com/cognis-digital/canarynet), [`phishforge`](https://github.com/cognis-digital/phishforge), [`sbomgate`](https://github.com/cognis-digital/sbomgate), [`honeytrace`](https://github.com/cognis-digital/honeytrace)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-8%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 8 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : C:\Python314\python.exe: No module named https
package      : https
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
C:\Python314\python.exe: No module named https
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m https --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>


## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
