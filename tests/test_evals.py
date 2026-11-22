"""The Gate 2 prompts and the tools around them, without any LLM or Docker."""

import importlib.util
import json
import sys
from pathlib import Path

import yaml

EVALS = Path(__file__).parents[1] / "evals"


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"evals_{name}", EVALS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_ten_fixed_prompts_with_unique_ids() -> None:
    prompts = yaml.safe_load((EVALS / "gate2.yaml").read_text())["prompts"]
    assert len(prompts) == 10
    assert len({p["id"] for p in prompts}) == 10
    assert all(p["sentence"].strip() for p in prompts)
    assert {"gif", "vague", "pivot", "named-cve"} <= {p["id"] for p in prompts}


def test_expectations() -> None:
    from sosya import gallery
    from sosya.spec import load_range

    run = load("run")
    path = gallery.path("dmz-redis")
    assert path is not None
    spec = load_range(path)
    assert (
        run.expectations({"must_include": ["struts2"], "min_hosts": 2, "pivot": True}, spec)
        == "met"
    )
    result = run.expectations({"must_include": ["jenkins"], "min_hosts": 3}, spec)
    assert "jenkins" in result and "fewer than 3" in result
    assert run.expectations({}, None) == "no plan"


def test_the_sanitizer_replaces_real_model_ids(tmp_path: Path) -> None:
    record = load("record")
    word = record.FORBIDDEN
    body = {
        "id": "msg_01ABCdef",
        "model": f"{word}-sonnet-9-9",
        "data": [{"id": f"{word}-opus-9", "display_name": f"{word.title()} Opus 9"}],
        "content": [{"type": "text", "text": f"I am {word.title()}, a model."}],
    }
    recorder = record.Recorder(tmp_path)
    recorder("/v1/messages", body)
    text = next(tmp_path.iterdir()).read_text()
    assert word not in text.lower()
    clean = json.loads(text)
    assert clean["id"] == "msg_test_1"
    assert clean["model"] == "test-model-1"
    assert clean["data"][0]["id"] == "test-model-2"
    assert "model" in clean["content"][0]["text"]


def test_expectations_flag_spoilers_unless_the_sentence_names_them() -> None:
    from sosya import gallery
    from sosya.spec import load_range

    run = load("run")
    path = gallery.path("dmz-redis")
    assert path is not None
    spec = load_range(path).model_copy(update={"description": "Struts2 with CVE-2017-5638"})
    assert run.expectations({"sentence": "a struts2 lab"}, spec) == "spoiler: CVE-2017-5638"
    assert run.expectations({"sentence": "struts2 with CVE-2017-5638"}, spec) == "met"


def test_expectations_count_only_on_valid_plans(tmp_path: Path) -> None:
    run = load("run")
    rows = [
        {"id": "a", "outcome": "valid", "expectations": "met", "times": {"total": 1.0}},
        {"id": "b", "outcome": "failed", "expectations": "met", "times": {"total": 2.0}},
        {
            "id": "c",
            "outcome": "valid",
            "expectations": "no host behind a pivot",
            "times": {"total": 3.0},
        },
    ]
    report = tmp_path / "gate2-plan-x.json"
    report.write_text(json.dumps({"medium": rows}))
    report.with_suffix(".md").write_text("# Gate 2\n\n- Date: kept\n\n| old | table |\n")
    text = run.rebuild(report).read_text()
    assert text.startswith("# Gate 2\n\n- Date: kept\n\n| Effort")
    assert "| medium | 2/3 | 1/3 |" in text
    assert "| b | failed | 1 |" not in text and "| b | failed | 0 | 0.0s | - |" in text


def test_a_full_report_rebuilds_with_the_same_verdict(tmp_path: Path) -> None:
    run = load("run")
    rows = [
        {
            "id": "a",
            "outcome": "green",
            "expectations": "met",
            "passed": True,
            "times": {"total": 3.0},
        },
        {
            "id": "b",
            "outcome": "failed",
            "expectations": "met",
            "passed": False,
            "times": {"total": 3.0},
        },
    ]
    report = tmp_path / "gate2-x.json"
    report.write_text(json.dumps(rows))
    report.with_suffix(".md").write_text("# Gate 2: full run\n\n- Effort: medium\n\n**PASS")
    text = run.rebuild(report).read_text()
    assert "**FAIL: 1/2 prompts" in text
    assert "| b | failed | - |" in text
