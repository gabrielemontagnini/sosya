# Changelog

All notable changes to Sosya are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-24

The first release. Sosya turns one sentence into a working, isolated, verified security lab (a
range): an LLM picks and composes real vulnerable environments from the Vulhub catalog, and
deterministic code renders a Docker Compose project, starts it and proves it works.

### Added

- `sosya new "<description>"`: plan a range with an LLM, show the plan, ask before starting it,
  then build and validate it. Validation errors go back to the planner, at most 3 attempts, and
  every attempt is shown.
- `sosya up <range>`: start a range from its `range.yaml`, with no LLM and no key. `--proxy` adds
  a SOCKS5 proxy in the attacker box for the host browser and Burp; `--expose` forwards one target
  port. Both bind `127.0.0.1` only.
- `sosya down`, `sosya status`, `sosya shell`, `sosya validate`, `sosya catalog` and
  `sosya doctor`.
- `sosya mcp`: an MCP server on stdio exposing catalog search, range checks, up, down, status,
  validate and the scenario, for any MCP client. An agent can pass a `range.yaml` it wrote itself,
  with no LLM key.
- Isolation by default: no port is published on the host, targets live on internal Docker
  networks, and the only way in is a Kali attacker box inside the range.
- The 334 Vulhub environments at a pinned commit, searchable offline from an index shipped in the
  package.
- Multi-host topologies with dual-homed hosts for pivoting.
- An Anthropic adapter and an OpenAI-compatible adapter (OpenAI, Ollama, LM Studio, vLLM,
  OpenRouter), with structured output.
- `SCENARIO.md` for every range: objectives, progressive hints, CVE links and injected flags.
- Seven gallery ranges, started with `sosya up <name>`: `dmz-redis`, `wordpress`, `solr`,
  `grafana`, `drupal`, `file-server` and `jenkins`.
- A shareable `range.yaml` format (`apiVersion: sosya/v1`), documented in `docs/range-yaml.md`.

### Requirements

- Docker Engine 28 or newer with Docker Compose v2.
- Python 3.12 or newer.
- Tested on Linux (x86_64).

### Known limitations

- **macOS is not verified.** Docker Desktop should work but has not been tested. On Apple Silicon
  nearly every Vulhub image runs under amd64 emulation, so Java applications can take minutes to
  start. Reports are welcome through the
  [macOS issue form](https://github.com/gabrielemontagnini/sosya/issues/new?template=macos.yml).
- **Local models are slow on CPU.** They work, but an 8B model on CPU needs the default effort and
  10 to 15 minutes to plan a single-host range.
- **Containers share the host's kernel.** Docker isolation is not a virtual machine: a container
  escape stays possible through a kernel bug or a misconfiguration. Run sensitive labs on a
  dedicated machine or in a VM. See
  [SECURITY.md](https://github.com/gabrielemontagnini/sosya/blob/main/SECURITY.md).

### Credits

Vulnerable environments by [Vulhub](https://github.com/vulhub/vulhub), MIT license, pinned at
commit [`9b90d42`](https://github.com/vulhub/vulhub/tree/9b90d4276f84feed6333286afeb7e1250379a1da).
Thank you to the Vulhub maintainers and contributors.

[Unreleased]: https://github.com/gabrielemontagnini/sosya/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gabrielemontagnini/sosya/releases/tag/v0.1.0
