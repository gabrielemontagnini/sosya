"""Gate 2: run the fixed prompts in evals/gate2.yaml and write a report.

    ~/.local/bin/with-llm-key uv run python evals/run.py --plan-only --effort low,medium,high
    ~/.local/bin/with-llm-key uv run python evals/run.py --effort medium
    uv run python evals/run.py --rebuild evals/reports/gate2-plan-*.json

`--plan-only` measures planning alone (queries, candidates, drafts and static repairs), with no
Docker, once per effort level: latency and the share of valid plans. The full run builds every
prompt (`new`), validates it again and stops it (`down`). The gate passes when at least 8 of
the 10 prompts become green ranges that also meet their expectations. Expectations count only
on valid plans (plan only) or green ranges (full run). `--rebuild` writes the Markdown of saved
reports again from their JSON, keeping the header, without calling any LLM.

Reports go to evals/reports/. They record the provider, the model line and the effort, never
the model id. Working files go to evals/runs/, which git ignores.
"""

import argparse
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sosya import __version__, advisories, engine, llm, runtime
from sosya.build import build
from sosya.catalog.loader import load_index
from sosya.llm.base import RefusalError
from sosya.planner import Planner
from sosya.spec import RangeSpec
from sosya.validate import failures, validate

HERE = Path(__file__).parent
PROMPTS = HERE / "gate2.yaml"
REPORTS = HERE / "reports"
RUNS = HERE / "runs"
PASS_MARK = 8


@dataclass
class Row:
    id: str
    outcome: str
    expectations: str = ""
    attempts: int = 0
    components: list[str] = field(default_factory=list)
    times: dict[str, float] = field(default_factory=dict)
    message: str = ""
    refusal_category: str | None = None

    @property
    def counted(self) -> bool:
        """Expectations count only on a valid plan or a green range."""
        return self.outcome in ("valid", "green")

    @property
    def met(self) -> bool:
        return self.counted and self.expectations == "met"

    @property
    def shown(self) -> str:
        return self.expectations if self.counted else "-"

    @property
    def passed(self) -> bool:
        return self.outcome == "green" and self.expectations == "met"


def expectations(prompt: dict[str, Any], spec: RangeSpec | None) -> str:
    if spec is None:
        return "no plan"
    problems = []
    components = [host.component for host in spec.hosts]
    wanted = prompt.get("must_include") or []
    for word in wanted:
        if not any(word.lower() in c.lower() for c in components):
            problems.append(f"no component with {word!r}")
    if len(spec.hosts) < int(prompt.get("min_hosts", 1)):
        problems.append(f"fewer than {prompt['min_hosts']} hosts")
    if prompt.get("pivot"):
        reachable = set(spec.attacker.networks)
        if all(set(host.networks) & reachable for host in spec.hosts):
            problems.append("no host behind a pivot")
    named = advisories.find(prompt.get("sentence", ""))
    texts = [spec.name, spec.description, *spec.objectives]
    spoiled = sorted({s for text in texts for s in advisories.spoilers(text, named)})
    if spoiled:
        problems.append("spoiler: " + ", ".join(spoiled))
    return "; ".join(problems) or "met"


def say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


# --- plan only -------------------------------------------------------------------------------


def plan_only(prompts: list[dict[str, Any]], effort: str | None, platform: str | None) -> list[Row]:
    adapter = llm.select(effort=effort)
    planner = Planner(
        adapter,
        load_index(),
        host_platform=platform,
        effort=effort,
        warn=lambda text: say(f"  warn: {text}"),
    )
    rows = []
    for prompt in prompts:
        row = Row(prompt["id"], "failed")
        started = time.monotonic()
        try:
            t = time.monotonic()
            queries = planner.derive_queries(prompt["sentence"])
            row.times["queries"] = time.monotonic() - t
            found = planner.candidates(prompt["sentence"], queries)
            conversation = planner.start(prompt["sentence"], found)
            problems: list[str] = []
            plan_time = 0.0
            spec = None
            for _ in range(3):
                t = time.monotonic()
                draft = (
                    planner.repair(conversation, problems)
                    if problems
                    else planner.draft(conversation)
                )
                plan_time += time.monotonic() - t
                row.attempts += 1
                spec = draft.spec
                if not draft.errors and spec is not None:
                    row.outcome = "dangerous" if draft.dangerous else "valid"
                    break
                problems = [str(issue) for issue in draft.errors]
            if row.outcome == "failed":
                row.message = "; ".join(problems)[:600]
            row.times["plan"] = plan_time
            row.components = [h.component for h in spec.hosts] if spec else []
            row.expectations = expectations(prompt, spec)
        except RefusalError as exc:
            row.outcome, row.message, row.refusal_category = "refused", str(exc), exc.category
        except llm.LLMError as exc:
            row.outcome, row.message = "error", str(exc)
        row.times["total"] = time.monotonic() - started
        say(
            f"  {effort or 'default':>7} {row.id:<14} {row.outcome:<9} {row.times['total']:5.1f}s"
            f"  {row.expectations}"
        )
        rows.append(row)
    return rows


# --- full run --------------------------------------------------------------------------------


def full_run(
    prompts: list[dict[str, Any]],
    effort: str | None,
    platform: str | None,
    run_dir: Path,
    recorder: Any = None,
) -> list[Row]:
    adapter = llm.select(effort=effort, recorder=recorder)
    workspace = runtime.Workspace(run_dir / ".sosya")
    ranges = run_dir / "ranges"
    rows = []
    for prompt in prompts:
        say(f"- {prompt['id']}: {prompt['sentence']}")
        result = build(
            prompt["sentence"],
            adapter,
            report=lambda level, text: say(f"    {level}: {text}"),
            phase=lambda name, text: say(f"    {name:<10} {text}"),
            effort=effort,
            workspace=workspace,
            ranges=ranges,
            host_platform=platform,
        )
        row = Row(
            prompt["id"],
            result.outcome,
            attempts=len(result.attempts),
            components=[h.component for h in result.spec.hosts] if result.spec else [],
            times={k: round(v, 1) for k, v in result.phases.items()},
            message=result.message,
        )
        if result.outcome == "refused":
            row.refusal_category = (
                result.message.rsplit("category: ", 1)[-1].rstrip(")")
                if "category: " in result.message
                else None
            )
        row.expectations = expectations(prompt, result.spec)
        if result.outcome == "green":
            t = time.monotonic()
            checks = validate(result.name, workspace=workspace)
            row.times["revalidate"] = round(time.monotonic() - t, 1)
            if failures(checks):
                row.outcome = "failed"
                row.message = "the second validation failed"
            t = time.monotonic()
            runtime.down(result.name, report=lambda level, text: None, workspace=workspace)
            row.times["down"] = round(time.monotonic() - t, 1)
        say(f"    => {row.outcome} ({row.expectations}) in {row.times.get('total', 0):.0f}s")
        rows.append(row)
    return rows


# --- report ----------------------------------------------------------------------------------


def _stats(values: list[float]) -> str:
    if not values:
        return "-"
    ordered = sorted(values)
    p90 = ordered[min(len(ordered) - 1, round(0.9 * (len(ordered) - 1)))]
    return f"{statistics.median(ordered):.1f}s median, {p90:.1f}s p90"


def header(title: str, adapter: Any, platform: str | None, effort: str | None = None) -> list[str]:
    index = load_index()
    return [
        f"# {title}",
        "",
        f"- Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- Sosya {__version__}, Vulhub `{index.vulhub_commit[:7]}`, engine `{platform}`",
        f"- Provider: {adapter.provider}, model line: {adapter.line}",
        *([f"- Effort: {effort}"] if effort else []),
        "",
    ]


def report_plan_only(by_effort: dict[str, list[Row]], head: list[str]) -> str:
    lines = list(head)
    lines += [
        "| Effort | Valid plans | Expectations met | Queries | Plan | Total |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for effort, rows in by_effort.items():
        valid = sum(1 for r in rows if r.outcome == "valid")
        met = sum(1 for r in rows if r.met)
        lines.append(
            f"| {effort} | {valid}/{len(rows)} | {met}/{len(rows)} "
            f"| {_stats([r.times.get('queries', 0) for r in rows])} "
            f"| {_stats([r.times.get('plan', 0) for r in rows])} "
            f"| {_stats([r.times['total'] for r in rows])} |"
        )
    for effort, rows in by_effort.items():
        lines += [
            "",
            f"## Effort {effort}",
            "",
            "| Prompt | Result | Attempts | Plan | Expectations |",
            "| --- | --- | --- | --- | --- |",
        ]
        for r in rows:
            lines.append(
                f"| {r.id} | {r.outcome} | {r.attempts} | {r.times.get('plan', 0):.1f}s "
                f"| {r.shown} |"
            )
        notes = [r for r in rows if r.message]
        if notes:
            lines += ["", "Last problems:", ""]
            lines += [f"- {r.id}: {r.message.splitlines()[0]}" for r in notes]
    return "\n".join(lines) + "\n"


def report_full(rows: list[Row], head: list[str]) -> str:
    passed = sum(1 for r in rows if r.passed)
    verdict = "PASS" if passed >= PASS_MARK else "FAIL"
    lines = list(head)
    refused = sum(1 for r in rows if r.outcome == "refused")
    lines += [
        f"**{verdict}: {passed}/{len(rows)} prompts became green ranges that meet their "
        f"expectations** (the gate needs {PASS_MARK}). Refusals: {refused}.",
        "",
        "| Prompt | Result | Expectations | Attempts | Plan | Up | Validate | Total | Components |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        components = ", ".join(c.removeprefix("vulhub/") for c in r.components)
        lines.append(
            f"| {r.id} | {r.outcome} | {r.shown} | {r.attempts} "
            f"| {r.times.get('plan', 0):.0f}s | {r.times.get('up', 0):.0f}s "
            f"| {r.times.get('validate', 0):.0f}s | {r.times.get('total', 0):.0f}s | {components} |"
        )
    notes = [r for r in rows if r.message]
    if notes:
        lines += ["", "## Notes", ""]
        lines += [f"- {r.id}: {r.message.splitlines()[0]}" for r in notes]
    green = [r.times["total"] for r in rows if r.outcome == "green"]
    lines += ["", f"Time to a green range: {_stats(green)}."]
    return "\n".join(lines) + "\n"


def _row(data: dict[str, Any]) -> Row:
    return Row(**{k: v for k, v in data.items() if k != "passed"})


def rebuild(json_path: Path) -> Path:
    """Write the Markdown of a saved report again from its JSON, keeping its header."""
    md_path = json_path.with_suffix(".md")
    old = md_path.read_text(encoding="utf-8").splitlines()
    end = next(i for i, line in enumerate(old) if line.startswith(("|", "**")))
    head = old[:end]
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        text = report_plan_only({k: [_row(r) for r in v] for k, v in data.items()}, head)
    else:
        text = report_full([_row(r) for r in data], head)
    md_path.write_text(text, encoding="utf-8")
    return md_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--effort", default="", help="comma-separated effort levels")
    parser.add_argument("--only", default="", help="comma-separated prompt ids")
    parser.add_argument("--record", type=Path, help="save sanitized LLM responses here")
    parser.add_argument("--rebuild", type=Path, nargs="+", help="saved report JSON files")
    args = parser.parse_args()

    if args.rebuild:
        for path in args.rebuild:
            say(f"rebuilt: {rebuild(path)}")
        return 0

    prompts = yaml.safe_load(PROMPTS.read_text(encoding="utf-8"))["prompts"]
    if args.only:
        wanted = set(args.only.split(","))
        prompts = [p for p in prompts if p["id"] in wanted]
    efforts = [e for e in args.effort.split(",") if e] or [llm.DEFAULT_EFFORT or ""]
    platform = engine.docker_platform()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    REPORTS.mkdir(parents=True, exist_ok=True)

    if args.plan_only:
        by_effort = {}
        for effort in efforts:
            by_effort[effort or "default"] = plan_only(prompts, effort or None, platform)
        adapter = llm.select()
        text = report_plan_only(
            by_effort, header("Gate 2: planning latency by effort", adapter, platform)
        )
        name = f"gate2-plan-{stamp}"
        rows_data: Any = {k: [asdict(r) for r in v] for k, v in by_effort.items()}
        ok = True
    else:
        recorder = None
        if args.record:
            from record import Recorder

            recorder = Recorder(args.record)
        effort = efforts[0] or None
        run_dir = RUNS / stamp
        rows = full_run(prompts, effort, platform, run_dir, recorder)
        adapter = llm.select(effort=effort)
        text = report_full(rows, header("Gate 2: full run", adapter, platform, effort or "default"))
        name = f"gate2-{stamp}"
        rows_data = [asdict(r) | {"passed": r.passed} for r in rows]
        ok = sum(1 for r in rows if r.passed) >= PASS_MARK
    (REPORTS / f"{name}.md").write_text(text, encoding="utf-8")
    (REPORTS / f"{name}.json").write_text(json.dumps(rows_data, indent=2) + "\n", encoding="utf-8")
    print(text)
    say(f"report: {REPORTS / name}.md")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
