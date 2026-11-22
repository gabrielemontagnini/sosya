## What and why

<!-- What this pull request changes, and the problem it solves. -->

Closes #

## How I tested it

<!-- Commands you ran and what you saw. For a gallery range or an override, paste `sosya validate`. -->

## Checklist

- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format .` leaves nothing to change
- [ ] `uv run pytest` passes
- [ ] `uv run pytest -m "docker and not gallery"` passes, if this touches `render/`, `runtime/`,
      `validate/` or `exposure.py`
- [ ] Snapshots in `tests/snapshots/` updated on purpose, if the rendered output changed
- [ ] Commits follow Conventional Commits, each one green on its own
- [ ] Isolation is unchanged: no port on `0.0.0.0`, targets only on internal networks, nothing
      printed or logged that contains a key
- [ ] Docs updated (`README.md`, `docs/range-yaml.md`, `CONTRIBUTING.md`), if behaviour changed
