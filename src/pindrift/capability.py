"""Capability inference.

The point of this module is to answer a question that a plain text diff cannot:
*what can this tool now do that it could not do before?*

A five-line description edit that turns a read-only file viewer into something that
writes files and reads ``~/.ssh`` is a far more serious event than a fifty-line
refactor. Diff size is a bad proxy for risk; capability delta is a good one.

Inference is heuristic by construction. Every facet carries the evidence that
triggered it so a human can audit the call rather than trust it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .models import Severity, ToolManifest

# Threshold on the weighted score before a facet is considered present.
# Tool-name matches weigh 3, descriptive phrase matches weigh 2 when the phrase is
# specific (multi-word, underscored, or a CJK term), 1 when it is a single generic
# word, and schema parameter names weigh 1.
ACTIVATION_THRESHOLD = 2

NAME_WEIGHT = 3
STRONG_DESCRIPTION_WEIGHT = 2
WEAK_DESCRIPTION_WEIGHT = 1
SCHEMA_WEIGHT = 1


def _is_specific(phrase: str) -> bool:
    """A phrase is specific if it is unlikely to appear by accident.

    Single English words like ``overwrite`` fire on unrelated descriptions; phrases
    like ``write file`` or ``读取文件`` do not. Only the latter earn the higher weight.
    """
    if " " in phrase or "_" in phrase:
        return True
    return len(phrase) >= 3 and any(ord(char) > 0x2E80 for char in phrase)



@dataclass(frozen=True)
class Facet:
    name: str
    risk: Severity
    label: str
    phrases: tuple[str, ...]
    schema_keys: tuple[str, ...] = ()


FACETS: tuple[Facet, ...] = (
    Facet(
        name="exec.shell",
        risk=Severity.CRITICAL,
        label="execute shell commands",
        phrases=(
            "shell command", "shell_command", "run command", "run_command", "run a command",
            "execute command", "execute shell", "bash", "powershell", "subprocess", "spawn",
            "terminal", "cmd.exe", "执行命令", "运行命令", "命令行", "终端", "脚本执行",
        ),
        schema_keys=("command", "cmd", "script", "shell"),
    ),
    Facet(
        name="cred.read",
        risk=Severity.CRITICAL,
        label="read credentials or secrets",
        phrases=(
            "environment variable", "env var", "credential", "credentials", "api key", "api_key",
            "apikey", "access token", "secret key", "private key", "keychain", ".env", "password",
            "ssh key", "密钥", "凭据", "凭证", "环境变量", "访问令牌",
        ),
        schema_keys=("token", "api_key", "apikey", "secret", "password", "credential"),
    ),
    Facet(
        name="cloud.control",
        risk=Severity.CRITICAL,
        label="control cloud or cluster resources",
        phrases=(
            "aws", "amazon web services", "gcp", "azure", "kubernetes", "kubectl", "terraform",
            "cloud resource", "iam policy", "云服务", "集群", "容器编排",
        ),
        schema_keys=("instance", "bucket", "cluster", "namespace", "project_id"),
    ),
    Facet(
        name="fs.write",
        risk=Severity.HIGH,
        label="write or modify files",
        phrases=(
            "write file", "write_file", "writefile", "create file", "create_file", "save file",
            "edit file", "edit_file", "modify file", "append to", "overwrite", "patch file",
            "apply patch", "写入文件", "保存文件", "修改文件", "创建文件", "覆盖写入",
        ),
        schema_keys=("content", "new_content", "new_string", "text", "data"),
    ),
    Facet(
        name="fs.delete",
        risk=Severity.HIGH,
        label="delete files or directories",
        phrases=(
            "delete file", "delete_file", "remove file", "remove_file", "unlink", "rm -rf",
            "delete directory", "remove directory", "删除文件", "删除目录", "移除",
        ),
        schema_keys=("delete", "force", "recursive"),
    ),
    Facet(
        name="db.write",
        risk=Severity.HIGH,
        label="modify database state",
        phrases=(
            "insert into", "update row", "update record", "delete from", "execute sql",
            "run sql", "write query", "数据库", "写入表", "更新记录",
        ),
        schema_keys=("sql", "statement", "query"),
    ),
    Facet(
        name="repo.push",
        risk=Severity.HIGH,
        label="push code or change repositories",
        phrases=(
            "git push", "git commit", "create commit", "merge branch", "merge pull request",
            "create pull request", "create branch", "推送代码", "提交代码", "合并分支",
        ),
        schema_keys=("branch", "commit_message", "pull_number"),
    ),
    Facet(
        name="ci.trigger",
        risk=Severity.HIGH,
        label="trigger deployments or pipelines",
        phrases=(
            "deploy", "deployment", "release pipeline", "run workflow", "trigger workflow",
            "ci pipeline", "rollout", "部署", "发布流程", "触发流水线",
        ),
        schema_keys=("workflow_id", "environment", "deployment_id"),
    ),
    Facet(
        name="msg.send",
        risk=Severity.HIGH,
        label="send messages or email externally",
        phrases=(
            "send message", "send email", "send a message", "post message", "slack", "webhook post",
            "notify user", "发送消息", "发送邮件", "推送通知",
        ),
        schema_keys=("to", "recipient", "channel", "subject", "body"),
    ),
    Facet(
        name="net.listen",
        risk=Severity.HIGH,
        label="listen on the network",
        phrases=(
            "listen on port", "bind port", "http server", "start server", "webhook endpoint",
            "监听端口", "启动服务",
        ),
        schema_keys=("port", "host", "bind"),
    ),
    Facet(
        name="net.egress",
        risk=Severity.MEDIUM,
        label="make outbound network requests",
        phrases=(
            "http request", "https request", "fetch url", "make a request", "api call", "download",
            "upload", "web request", "curl", "网络请求", "下载文件", "上传文件",
        ),
        schema_keys=("url", "uri", "endpoint", "host", "domain"),
    ),
    Facet(
        name="browser.control",
        risk=Severity.MEDIUM,
        label="drive a browser",
        phrases=(
            "browser", "navigate to", "click element", "take screenshot", "playwright", "puppeteer",
            "selenium", "浏览器", "截图", "点击元素",
        ),
        schema_keys=("selector", "screenshot", "tab_id"),
    ),
    Facet(
        name="clipboard",
        risk=Severity.MEDIUM,
        label="read or write the clipboard",
        phrases=("clipboard", "copy to clipboard", "paste", "剪贴板", "复制粘贴"),
        schema_keys=("clipboard",),
    ),
    Facet(
        name="fs.read",
        risk=Severity.LOW,
        label="read files or directories",
        phrases=(
            "read file", "read_file", "readfile", "read the file", "view file", "open file",
            "list directory", "list_directory", "list files", "directory listing", "glob pattern",
            "file contents", "读取文件", "查看文件", "列出目录", "文件内容",
        ),
        schema_keys=("path", "file_path", "directory", "pattern"),
    ),
)

FACET_BY_NAME: dict[str, Facet] = {f.name: f for f in FACETS}


@dataclass
class CapabilityHit:
    facet: str
    score: int
    evidence: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Severity:
        return FACET_BY_NAME[self.facet].risk

    @property
    def label(self) -> str:
        return FACET_BY_NAME[self.facet].label


def _schema_blob(schema: object) -> str:
    if not isinstance(schema, dict):
        return ""
    parts: list[str] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        for key, value in props.items():
            parts.append(str(key))
            if isinstance(value, dict):
                parts.append(str(value.get("description") or ""))
                enum = value.get("enum")
                if isinstance(enum, list):
                    parts.extend(str(e) for e in enum)
            elif isinstance(value, str):
                parts.append(value)
    parts.append(str(schema.get("description") or ""))
    return " \n ".join(parts).lower()


def infer_capabilities(tool: ToolManifest) -> dict[str, CapabilityHit]:
    """Infer the capability facets of a single tool.

    Returns facets that reached :data:`ACTIVATION_THRESHOLD`, with the matched
    phrases recorded as evidence.
    """
    name_blob = tool.name.lower()
    desc_blob = tool.description.lower()
    schema_blob = _schema_blob(tool.input_schema)

    annotation_blob = " ".join(
        f"{k}={v}" for k, v in sorted(tool.annotations.items())
    ).lower()

    hits: dict[str, CapabilityHit] = {}
    for facet in FACETS:
        score = 0
        evidence: list[str] = []
        for phrase in facet.phrases:
            weight = (
                STRONG_DESCRIPTION_WEIGHT if _is_specific(phrase) else WEAK_DESCRIPTION_WEIGHT
            )
            if phrase in name_blob:
                score += NAME_WEIGHT
                evidence.append(f"name contains {phrase!r}")
            elif phrase in desc_blob:
                score += weight
                evidence.append(f"description contains {phrase!r}")
            elif phrase in schema_blob:
                score += SCHEMA_WEIGHT
                evidence.append(f"schema contains {phrase!r}")
        for key in facet.schema_keys:
            if re.search(rf"\b{re.escape(key)}\b", schema_blob):
                score += SCHEMA_WEIGHT
                evidence.append(f"schema parameter {key!r}")

        if facet.name == "fs.delete" and "destructivehint=true" in annotation_blob:
            score += 2
            evidence.append("annotation destructiveHint=true")
        if facet.name in ("fs.write", "db.write") and "readonlyhint=false" in annotation_blob:
            score += 1
            evidence.append("annotation readOnlyHint=false")

        if score >= ACTIVATION_THRESHOLD:
            hits[facet.name] = CapabilityHit(facet=facet.name, score=score, evidence=evidence[:4])
    return hits


def server_capabilities(tools: Iterable[ToolManifest]) -> dict[str, list[str]]:
    """Map facet name -> sorted tool names that expose it."""
    aggregate: dict[str, list[str]] = {}
    for tool in tools:
        for facet in infer_capabilities(tool):
            aggregate.setdefault(facet, []).append(tool.name)
    return {k: sorted(v) for k, v in sorted(aggregate.items())}
