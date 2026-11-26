from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pindrift.capability import FACET_BY_NAME, infer_capabilities, server_capabilities
from pindrift.models import Severity, ToolManifest


def make_tool(name: str, description: str = "", schema: dict | None = None) -> ToolManifest:
    return ToolManifest(
        name=name,
        description=description,
        input_schema=schema or {"type": "object", "properties": {}},
    )


def test_read_only_tool_has_no_write_capability() -> None:
    tool = make_tool(
        "read_file",
        "Read the contents of a text file from the workspace.",
        {"type": "object", "properties": {"path": {"type": "string"}}},
    )
    caps = infer_capabilities(tool)
    assert "fs.read" in caps
    assert "fs.write" not in caps
    assert "fs.delete" not in caps


def test_write_tool_is_high_risk() -> None:
    tool = make_tool(
        "write_file",
        "Write or overwrite a text file in the workspace.",
        {"type": "object", "properties": {"path": {}, "content": {}}},
    )
    caps = infer_capabilities(tool)
    assert "fs.write" in caps
    assert caps["fs.write"].risk is Severity.HIGH


def test_shell_tool_is_critical() -> None:
    tool = make_tool("run_command", "Execute a shell command in the project directory.")
    caps = infer_capabilities(tool)
    assert "exec.shell" in caps
    assert caps["exec.shell"].risk is Severity.CRITICAL


def test_credential_tool_is_critical() -> None:
    tool = make_tool("get_config", "Read an API key from the environment variable store.")
    caps = infer_capabilities(tool)
    assert "cred.read" in caps
    assert caps["cred.read"].risk is Severity.CRITICAL


def test_evidence_is_recorded() -> None:
    tool = make_tool("write_file", "Write content to a path.")
    hits = infer_capabilities(tool)
    assert hits["fs.write"].evidence
    assert any("name contains" in item for item in hits["fs.write"].evidence)


def test_chinese_description_is_understood() -> None:
    tool = make_tool("文件助手", "读取文件并返回文件内容。")
    caps = infer_capabilities(tool)
    assert "fs.read" in caps


def test_server_capabilities_attributes_tools() -> None:
    tools = [
        make_tool("read_file", "Read a file from disk."),
        make_tool("write_file", "Write a file to disk."),
    ]
    aggregate = server_capabilities(tools)
    assert aggregate["fs.read"] == ["read_file"]
    assert aggregate["fs.write"] == ["write_file"]


def test_plain_text_tool_yields_nothing() -> None:
    tool = make_tool("hello", "Say hello to the user.")
    assert infer_capabilities(tool) == {}


# --- the labelled corpus is the contract -----------------------------------------
#
# T4 exists because neither error rate was measured. Precision is the hard gate:
# a false positive teaches users to ignore the tool. Recall is looser because a
# missed facet still leaves a visible manifest diff for a human to read.

CORPUS_PATH = Path(__file__).parent / "fixtures" / "facet_corpus.jsonl"
MIN_PRECISION = 0.85
MIN_RECALL = 0.80
MIN_BENIGN = 10


@dataclass
class Metric:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


def load_corpus() -> list[dict]:
    lines = CORPUS_PATH.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def tool_from_entry(entry: dict) -> ToolManifest:
    payload = entry["tool"]
    return ToolManifest(
        name=payload["name"],
        description=payload.get("description") or "",
        input_schema=payload.get("inputSchema") or {},
        annotations=payload.get("annotations") or {},
    )


def test_corpus_is_well_formed_and_covers_every_facet() -> None:
    entries = load_corpus()
    names = [entry["tool"]["name"] for entry in entries]
    assert len(names) == len(set(names)), "corpus tool names must be unique"

    known = set(FACET_BY_NAME)
    covered: set[str] = set()
    benign = 0
    for entry in entries:
        assert entry.get("note"), f"{entry['tool']['name']}: every entry needs a note"
        expected = entry.get("expect_facets")
        assert isinstance(expected, list), f"{entry['tool']['name']}: expect_facets must be a list"
        unknown = set(expected) - known
        assert not unknown, f"{entry['tool']['name']}: unknown facets {sorted(unknown)}"
        covered.update(expected)
        if not expected:
            benign += 1

    assert covered == known, f"facets with no positive example: {sorted(known - covered)}"
    assert benign >= MIN_BENIGN, f"need at least {MIN_BENIGN} benign tools, found {benign}"


def test_facet_corpus_meets_precision_and_recall_thresholds() -> None:
    metrics = {name: Metric() for name in FACET_BY_NAME}
    misses: list[str] = []

    for entry in load_corpus():
        name = entry["tool"]["name"]
        predicted = set(infer_capabilities(tool_from_entry(entry)))
        expected = set(entry["expect_facets"])
        for facet in predicted & expected:
            metrics[facet].tp += 1
        for facet in predicted - expected:
            metrics[facet].fp += 1
            misses.append(
                f"  FP {name}: predicted {facet} ({entry['note']}); all={sorted(predicted)}"
            )
        for facet in expected - predicted:
            metrics[facet].fn += 1
            misses.append(
                f"  FN {name}: missed {facet} ({entry['note']}); all={sorted(predicted)}"
            )

    below = [
        f"{facet}: precision {metric.precision:.3f} < {MIN_PRECISION} "
        f"(tp={metric.tp} fp={metric.fp})"
        for facet, metric in metrics.items()
        if metric.precision < MIN_PRECISION
    ]
    below += [
        f"{facet}: recall {metric.recall:.3f} < {MIN_RECALL} "
        f"(tp={metric.tp} fn={metric.fn})"
        for facet, metric in metrics.items()
        if metric.recall < MIN_RECALL
    ]

    if below:
        table = ["", "facet             precision  recall   tp  fp  fn"]
        for facet, metric in metrics.items():
            table.append(
                f"{facet:16}   {metric.precision:9.3f}  {metric.recall:6.3f}"
                f"  {metric.tp:3d} {metric.fp:3d} {metric.fn:3d}"
            )
        raise AssertionError("\n".join(below + table + ["misclassified:"] + misses))


def test_benign_corpus_tools_produce_no_facet() -> None:
    failures = []
    for entry in load_corpus():
        if entry["expect_facets"]:
            continue
        predicted = sorted(infer_capabilities(tool_from_entry(entry)))
        if predicted:
            failures.append(f"  {entry['tool']['name']}: {predicted} ({entry['note']})")
    assert not failures, "benign tools produced facets:\n" + "\n".join(failures)
