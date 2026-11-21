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
