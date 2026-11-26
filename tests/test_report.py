"""SARIF 2.1.0 fidelity.

The document is validated by asserting the shape the specification requires, not by
downloading the schema: tests must not use the network. Anything CI consumes is
checked here -- rule metadata, result/rule agreement, locations and the partial
fingerprints that let code scanning dedupe a finding across runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pindrift import report
from pindrift.differ import summarise
from pindrift.models import (
    SARIF_LEVEL,
    Artifact,
    Finding,
    ServerFingerprint,
    ServerResult,
    Severity,
    State,
)

THREAT_MODEL = Path(__file__).resolve().parent.parent / "docs" / "THREAT-MODEL.md"
RULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SARIF_LEVELS = {"none", "note", "warning", "error"}

# Every kind differ.compare() and the check command can emit. A new kind must be
# added here and given metadata in report.SARIF_RULES -- that is the point of the
# test, not incidental coverage.
EXPECTED_KINDS = {
    "annotations_changed",
    "artifact_changed",
    "artifact_unverifiable",
    "capability_added",
    "capability_removed",
    "description_changed",
    "description_risk",
    "env_changed",
    "launch_changed",
    "manifest_established",
    "manifest_unverified",
    "schema_changed",
    "server_missing",
    "tool_added",
    "tool_removed",
    "transport_changed",
    "unpinned",
}


def github_anchor(heading: str) -> str:
    """Mirror of GitHub's heading slugger for the constructs used in the doc."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return text.replace(" ", "-")


def document_headings() -> set[str]:
    anchors: set[str] = set()
    for line in THREAT_MODEL.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            anchors.add(github_anchor(line.lstrip("#")))
    return anchors


def make_fingerprint(
    server_id: str = "claude-code:demo-fs",
    clients: list[str] | None = None,
) -> ServerFingerprint:
    return ServerFingerprint(
        server_id=server_id,
        client="claude-code",
        name="demo-fs",
        clients=list(clients or []),
        transport="stdio",
        source_config="/home/analyst/.claude.json",
        artifact=Artifact(kind="local", target="/opt/demo/server.py", sha256="a" * 64),
    )


def make_result(
    *findings: Finding,
    server_id: str = "claude-code:demo-fs",
    clients: list[str] | None = None,
) -> ServerResult:
    return ServerResult(
        fingerprint=make_fingerprint(server_id, clients),
        state=State.DRIFT,
        findings=list(findings),
    )


def finding(
    kind: str = "capability_added",
    severity: Severity = Severity.HIGH,
    title: str = "tool 'read_file' gained capability",
    detail: str = "fs.write (Writes files)",
    evidence: list[str] | None = None,
) -> Finding:
    return Finding(
        server_id="claude-code:demo-fs",
        kind=kind,
        severity=severity,
        title=title,
        detail=detail,
        evidence=["fs.write: write files"] if evidence is None else evidence,
    )


def render(*results: ServerResult) -> dict:
    return json.loads(report.render_sarif(list(results)))


def rules_of(document: dict) -> list[dict]:
    return document["runs"][0]["tool"]["driver"]["rules"]


def results_of(document: dict) -> list[dict]:
    return document["runs"][0]["results"]


# -- document shape ---------------------------------------------------------------


def test_empty_run_is_still_a_valid_document() -> None:
    document = render()

    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert document["version"] == "2.1.0"
    assert isinstance(document["runs"], list) and document["runs"]

    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "pindrift"
    assert run["tool"]["driver"]["version"]
    assert run["tool"]["driver"]["informationUri"].startswith("https://")
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_document_is_reparseable_and_complete() -> None:
    raw = report.render_sarif([make_result(finding())])
    document = json.loads(raw)

    assert raw == json.dumps(document, ensure_ascii=False, indent=2)
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1

    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "pindrift"
    assert isinstance(run["results"], list) and len(run["results"]) == 1

    result = run["results"][0]
    assert result["message"]["text"]
    assert result["level"] in SARIF_LEVELS
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].startswith("file://")
    assert location["region"]["startLine"] == 1


# -- rule metadata ----------------------------------------------------------------


def test_every_finding_kind_has_a_static_rule() -> None:
    assert set(report.SARIF_RULES) == EXPECTED_KINDS


def test_rules_match_their_results() -> None:
    document = render(
        make_result(finding(), finding(kind="launch_changed", title="launch command changed")),
        make_result(
            finding(kind="tool_added", title="tool 'exec' added"),
            server_id="cursor:other",
        ),
    )
    rules = rules_of(document)
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"

    for result in results_of(document):
        assert result["ruleId"] in ids
        assert result["ruleIndex"] == ids.index(result["ruleId"])
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_rule_metadata_is_schema_shaped_and_linked() -> None:
    anchors = document_headings()
    reported = EXPECTED_KINDS - {"unpinned"}  # info-level and intentionally omitted
    document = render(make_result(*(finding(kind=kind) for kind in sorted(reported))))
    rules = rules_of(document)

    assert {rule["id"] for rule in rules} == {f"pindrift/{kind}" for kind in reported}

    for rule in rules:
        assert RULE_NAME.match(rule["name"]), rule["name"]
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["helpUri"].startswith(report.THREAT_MODEL_URI + "#")
        anchor = rule["helpUri"].split("#", 1)[1]
        assert anchor in anchors, f"{rule['id']} links to a missing heading: {anchor}"
        assert rule["defaultConfiguration"]["level"] in SARIF_LEVELS

        properties = rule["properties"]
        assert properties["tags"]
        assert all(isinstance(tag, str) for tag in properties["tags"])


def test_default_rule_severity_does_not_flip_with_the_observed_finding() -> None:
    low = rules_of(render(make_result(finding(severity=Severity.LOW))))[0]
    critical = rules_of(render(make_result(finding(severity=Severity.CRITICAL))))[0]

    assert low == critical
    assert low["defaultConfiguration"]["level"] == "error"


def test_unpinned_info_is_not_reported() -> None:
    document = render(
        make_result(
            finding(kind="unpinned", severity=Severity.INFO, title="no pin yet", detail="")
        )
    )
    assert results_of(document) == []
    assert rules_of(document) == []


# -- dedupe provenance ------------------------------------------------------------


def test_single_client_is_recorded_as_a_one_element_list() -> None:
    result = results_of(render(make_result(finding())))[0]
    assert result["properties"]["clients"] == ["claude-code"]


def test_deduped_server_keeps_every_client_in_sarif() -> None:
    result = results_of(
        render(make_result(finding(), clients=["claude-code", "cursor"]))
    )[0]
    assert result["properties"]["clients"] == ["claude-code", "cursor"]


def test_text_and_json_name_every_client() -> None:
    result = make_result(finding(), clients=["claude-code", "cursor"])

    text = report.render_text([result], summarise([result]), baseline_label="test")
    assert "clients   claude-code, cursor" in text

    payload = json.loads(report.render_json([result], summarise([result])))
    assert payload["servers"][0]["clients"] == ["claude-code", "cursor"]


def test_partial_fingerprint_ignores_the_client_list() -> None:
    one = results_of(render(make_result(finding())))[0]
    two = results_of(
        render(make_result(finding(), clients=["claude-code", "cursor"]))
    )[0]

    assert one["partialFingerprints"] == two["partialFingerprints"]


# -- dedupe -----------------------------------------------------------------------


def test_partial_fingerprint_is_stable_across_runs() -> None:
    first = results_of(render(make_result(finding())))[0]
    second = results_of(render(make_result(finding())))[0]

    key = "pindrift/v1"
    assert first["partialFingerprints"][key] == second["partialFingerprints"][key]
    assert re.match(r"^[0-9a-f]{64}$", first["partialFingerprints"][key])


def test_partial_fingerprint_ignores_volatile_evidence() -> None:
    before = results_of(render(make_result(finding(evidence=["sha256: aaaa"]))))[0]
    after = results_of(render(make_result(finding(evidence=["sha256: bbbb"]))))[0]

    assert (
        before["partialFingerprints"]["pindrift/v1"]
        == after["partialFingerprints"]["pindrift/v1"]
    )


def test_partial_fingerprint_separates_server_rule_and_drift() -> None:
    def fingerprint(result: ServerResult) -> str:
        return results_of(render(result))[0]["partialFingerprints"]["pindrift/v1"]

    baseline = fingerprint(make_result(finding()))
    assert fingerprint(make_result(finding(), server_id="cursor:other")) != baseline
    assert fingerprint(make_result(finding(kind="tool_added", title="tool 'x' added"))) != baseline
    assert fingerprint(make_result(finding(detail="exec.shell (Shell)"))) != baseline


# -- untrusted text ---------------------------------------------------------------


def test_hidden_characters_are_escaped_before_they_reach_the_document() -> None:
    document = render(
        make_result(
            finding(
                kind="description_risk",
                severity=Severity.CRITICAL,
                title="tool 'read\u200bfile' description contains risky content",
                detail="hidden characters: ansi escape near 'x\x1b[2Ky'",
                evidence=["\x1b[2K\x1b[1A"],
            )
        )
    )
    serialized = json.dumps(document, ensure_ascii=False)

    assert "\u200b" not in serialized
    assert "\x1b" not in serialized
    assert "\\u200b" in serialized
    assert "\\x1b" in serialized


# -- unknown kinds ----------------------------------------------------------------


def test_unknown_kind_still_produces_a_referenceable_rule() -> None:
    document = render(make_result(finding(kind="future_signal", severity=Severity.MEDIUM)))
    rules = rules_of(document)

    assert len(rules) == 1
    assert rules[0]["id"] == "pindrift/future_signal"
    assert RULE_NAME.match(rules[0]["name"])
    assert rules[0]["defaultConfiguration"]["level"] == SARIF_LEVEL[Severity.MEDIUM]
    assert results_of(document)[0]["ruleIndex"] == 0


@pytest.mark.parametrize("kind", sorted(report.SARIF_RULES))
def test_rule_has_one_identifier_per_kind(kind: str) -> None:
    assert report.SARIF_RULES[kind].kind == kind
    assert report.SARIF_RULES[kind].rule_id == f"pindrift/{kind}"
