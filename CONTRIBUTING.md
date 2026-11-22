# Contributing to Sosya

Thank you for helping. Sosya is small and maintained by one person, so focused pull requests with
tests are the fastest way in. For anything bigger than a bug fix, open an issue first (the
*Proposal* form) so we can agree on the approach before you write code.

Security problems, above all anything that breaks the isolation of a range, are not issues:
report them privately as described in [SECURITY.md](SECURITY.md).

## Setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer (development happens on 3.14;
CI runs 3.12, 3.13 and 3.14). Docker is needed only for the tests marked `docker`.

```console
$ git clone https://github.com/gabrielemontagnini/sosya
$ cd sosya
$ uv sync                      # creates .venv with the dev tools
$ uv run sosya --version
$ uv run sosya doctor          # Docker Engine 28+, Compose v2, architecture, LLM configuration
```

## Before every commit

All three must be green; CI runs the same commands:

```console
$ uv run ruff check .
$ uv run ruff format .
$ uv run pytest
```

### Tests and markers

Plain `uv run pytest` runs the unit tests. They never need Docker, the network or an LLM: mock
`subprocess` and HTTP. The renderer has snapshot tests in `tests/snapshots/`; when you change the
rendered output on purpose, update the snapshot in the same commit and explain why.

Three markers select the slower tests. They are excluded by default:

| Marker | What it needs | Command |
| --- | --- | --- |
| `docker` | A running Docker Engine 28+ with Compose v2 | `uv run pytest -m "docker and not gallery"` |
| `gallery` | Docker, time and disk: starts every gallery range live (also marked `docker`) | `uv run pytest -m gallery` |
| `llm` | An LLM key (see [Gate 2](#running-gate-2-with-your-own-key)) | `uv run pytest -m llm` |

The `docker` tests use the published attacker image of the current version. If you change
`src/sosya/attacker/`, build it and point the tests at your build, as CI does:

```console
$ docker build --tag sosya-attacker:dev src/sosya/attacker
$ SOSYA_ATTACKER_IMAGE=sosya-attacker:dev uv run pytest -m "docker and not gallery"
```

Run `-m docker` whenever you touch `render/`, `runtime/`, `validate/` or `exposure.py`. To run a
single gallery range live, add `-k <name>` to the `gallery` command.

## Style

- Type hints everywhere. Pydantic v2 for external data, frozen dataclasses for internal records.
- Rich for terminal output: calm, one line per step, clear ok and fail marks.
- `cli.py` stays thin: logic lives in modules, and the MCP server calls the same functions.
- Code, comments, CLI text and commits in English.
- No syntax newer than Python 3.12.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/) in English: `feat:`, `fix:`,
  `test:`, `docs:`, `ci:`, `refactor:`, with an optional scope (`fix(validate): ...`).
- One commit per green step: each commit passes ruff and pytest on its own.
- Commit messages carry no attribution trailers or "generated with" lines for the tools you used.
  CI checks the commit messages of every pull request, and a test checks every tracked file.
- The pull request template has the checklist. Link the issue it closes.

## Rules that are not negotiable

A pull request that breaks one of these is not merged, however useful it is:

1. **Isolation by default.** No container port is ever published on `0.0.0.0`. Targets live only
   on networks with `internal: true`. `--expose` and `--proxy` bind `127.0.0.1` only, through a
   relay that no target joins.
2. **The LLM only plans.** It writes a `range.yaml`, which is validated against the schema and the
   catalog. Rendering, runtime and validation are deterministic and never call an LLM.
3. **No exploits.** Sosya composes public, documented images. It never generates or runs exploit
   code, and `SCENARIO.md` gives objectives, hints and CVE links, not attack steps.
4. **No secrets in output.** Keys and tokens are never printed or logged, not even in debug
   output.
5. **Scope.** v0.1 is Docker Compose and Linux containers only. VMs, Windows and Active Directory,
   a web UI, exploit generation, LLM-written Dockerfiles and hosted modes are out of scope.

## Adding a range to the gallery

Gallery ranges ship inside the package and start with `sosya up <name>`, with no key. Each one is
validated live every week by the `Gallery` workflow, so pick environments that are image-only
(no *local files* note in `sosya catalog`), run on `linux/amd64`, and are not dangerous.

1. Find the components with `sosya catalog <query>`. The format of the file is described in
   [docs/range-yaml.md](docs/range-yaml.md).
2. Create `src/sosya/gallery/<name>/range.yaml`. The directory name and the `name:` field must be
   the same.
3. Keep `name`, `description` and `objectives` free of advisory ids (CVE, GHSA, CNVD, Struts
   S2-NNN): the player should find out what runs. `tests/test_gallery.py` checks this.
4. Add the name to the `GALLERY` set in `tests/test_gallery.py`, and a row to the *Gallery* table in
   `README.md`.
5. Prove it live:

   ```console
   $ uv run sosya up src/sosya/gallery/<name>
   $ uv run sosya validate <name>
   $ uv run sosya down <name>
   $ uv run pytest -m gallery -k <name>
   ```

   Paste the output of `sosya validate` in the pull request.

## Adding a catalog override

Some Vulhub environments publish a port that never listens, which would make validation fail.
Corrections like these are data, in `data/catalog-overrides.yaml`:

```yaml
ports:
  - id: vulhub/jenkins/CVE-2017-1000353
    service: jenkins
    port: 50000
    optional: true
    reason: published by the compose file, but the Jenkins agent port never listens
```

Every entry names an existing environment, service and port, and gives a `reason`. Then rebuild
the packaged index from Vulhub at the pinned commit:

```console
$ uv run python -m sosya.catalog.build sync     # sparse clone into .cache/vulhub (git ignores it)
$ uv run python -m sosya.catalog.build index    # rewrites src/sosya/catalog/data/
```

The build fails on an entry that points to something that does not exist. Commit the YAML and the
regenerated `src/sosya/catalog/data/index.json` together, and show in the pull request that the
environment now validates (`sosya up` and `sosya validate` on a range that uses it).

An environment that is broken upstream (an image that no longer exists, for example) cannot be
fixed with an override: open an *Environment broken upstream* issue instead.

## Running Gate 2 with your own key

Gate 2 is the planner's acceptance test: ten fixed sentences in `evals/gate2.yaml`, and at least
8 of them must become green ranges that meet their expectations. Run it when you change the
planner, the prompt or an LLM adapter.

Export the key of the provider you want in your shell (`ANTHROPIC_API_KEY`, or `OPENAI_API_KEY`
with `SOSYA_MODEL`, or `OPENAI_BASE_URL` for a local server); see the *Configuration* table in the
README. Then:

```console
$ uv run python evals/run.py --plan-only                   # planning only: no Docker, minutes
$ uv run python evals/run.py --plan-only --effort low,medium
$ uv run python evals/run.py --only pivot,named-cve        # a few prompts, full run
$ uv run python evals/run.py                               # full run: builds and validates all ten
$ uv run pytest -m llm                                     # the live adapter tests
```

The full run needs Docker and pulls every image, so expect several minutes. A run calls the real
API, so it costs a little money with a hosted provider.

Reports go to `evals/reports/` and record the provider, the model line and the effort, never the
model id or a key. Paste the summary table of the Markdown report in your pull request; commit a
report only when the pull request is about planner quality. Recorded LLM responses
(`evals/run.py --record`, used for test fixtures) are sanitized so that they carry fake model ids
only; never commit a fixture or a report by hand that contains a real model id.

## License

By contributing, you agree that your contributions are licensed under the [MIT license](LICENSE).
