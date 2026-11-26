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
            "shell command", "shell_command", "shell script", "shell_script", "bash script",
            "run command", "run_command", "run a command", "run the command",
            "execute command", "execute a command", "execute the command", "execute shell",
            "system shell", "powershell", "subprocess", "cmd.exe", "command line",
            "terminal", "执行命令", "运行命令", "命令行", "终端", "脚本执行",
        ),
        schema_keys=("command", "cmd", "script", "shell"),
    ),
    Facet(
        name="cred.read",
        risk=Severity.CRITICAL,
        label="read credentials or secrets",
        phrases=(
            "environment variable", "env var", "credential", "credentials", "credential store",
            "api key", "api_key", "apikey", "access token", "access key", "secret key",
            "secret value", "secret manager", "private key", "keychain", "stored password",
            "password store", "password manager", "look up a password", "look up the password",
            "retrieve a password", "retrieve the password", "get the password",
            "read the password", "show the password", ".env", "ssh key",
            "密钥", "凭据", "凭证", "环境变量", "访问令牌",
        ),
        schema_keys=("token", "api_key", "apikey", "secret", "credential"),
    ),
    Facet(
        name="cloud.control",
        risk=Severity.CRITICAL,
        label="control cloud or cluster resources",
        phrases=(
            "amazon web services", "aws s3", "aws_s3", "amazon s3", "s3 bucket", "aws lambda",
            "aws_lambda", "aws ec2", "aws_ec2", "ec2 instance", "aws iam", "iam role",
            "iam policy", "iam user", "google cloud", "gcp_", "compute instance", "azure_",
            "virtual machine", "kubernetes cluster", "k8s cluster", "kubectl", "helm",
            "terraform", "cloudformation", "cloud resource",
            "云服务", "集群", "容器编排",
        ),
        schema_keys=("instance", "bucket", "cluster", "namespace"),
    ),
    Facet(
        name="fs.write",
        risk=Severity.HIGH,
        label="write or modify files",
        phrases=(
            "write file", "write_file", "writefile", "write a file", "write to a file",
            "write to file", "write the file", "writes the file", "create file", "create_file",
            "create a file", "create a new file", "save file", "save the file", "save to disk",
            "edit file", "edit_file", "modify file", "modify the file", "update the file",
            "append to", "append text", "append content", "overwrite", "overwrite the file",
            "patch file", "apply patch", "apply a patch", "create directory", "create a directory",
            "mkdir", "写入文件", "保存文件", "修改文件", "创建文件", "覆盖写入",
        ),
        schema_keys=("content", "new_content", "new_string", "text"),
    ),
    Facet(
        name="fs.delete",
        risk=Severity.HIGH,
        label="delete files or directories",
        phrases=(
            "delete file", "delete_file", "delete a file", "delete the file", "remove file",
            "remove_file", "remove a file", "remove files", "remove the file", "delete directory",
            "delete_directory", "delete a directory", "remove directory", "remove_directory",
            "remove a directory", "unlink", "rm -rf", "rmdir",
            "删除文件", "删除目录", "移除",
        ),
        schema_keys=("delete", "force", "recursive"),
    ),
    Facet(
        name="db.write",
        risk=Severity.HIGH,
        label="modify database state",
        phrases=(
            "insert into", "insert a row", "insert row", "insert_row", "insert_record",
            "update record", "update_record", "update a record", "update the record",
            "update a row", "delete from", "delete_from", "delete row", "delete a row",
            "delete record", "execute sql", "execute_sql", "run sql", "run_sql", "write query",
            "sql statement", "alter table", "create table", "drop table", "truncate table",
            "database migration", "schema migration",
            "数据库", "写入表", "更新记录",
        ),
        schema_keys=("sql", "statement", "query"),
    ),
    Facet(
        name="repo.push",
        risk=Severity.HIGH,
        label="push code or change repositories",
        phrases=(
            "git push", "git_push", "push commit", "push commits", "push local commits",
            "push changes", "push the changes", "git commit", "git_commit", "create commit",
            "commit changes",
            "merge branch", "merge_branch", "merge pull request", "merge_pull_request",
            "create pull request", "create_pull_request", "open a pull request",
            "create branch", "create_branch", "create a branch",
            "推送代码", "提交代码", "合并分支",
        ),
        schema_keys=("branch", "commit_message", "pull_number"),
    ),
    Facet(
        name="ci.trigger",
        risk=Severity.HIGH,
        label="trigger deployments or pipelines",
        phrases=(
            "deploy to", "deploy the", "deploy a", "deploying", "deployed",
            "deployment pipeline", "release pipeline", "run workflow", "run a workflow",
            "run the workflow", "trigger workflow", "trigger a workflow", "trigger_workflow",
            "actions workflow", "run the ci pipeline", "ci pipeline run", "start a rollout",
            "canary rollout", "rollout to", "rollback", "roll back", "helm upgrade",
            "部署", "发布流程", "触发流水线",
        ),
        schema_keys=("workflow_id",),
    ),
    Facet(
        name="msg.send",
        risk=Severity.HIGH,
        label="send messages or email externally",
        phrases=(
            "send message", "send_message", "send a message", "send the message", "post message",
            "post_message", "post a message", "send email", "send_email", "send an email",
            "send notification", "send a notification", "post notification", "notify user",
            "notify a user", "notify the user", "send webhook", "send a webhook", "post to slack",
            "send to slack",
            "发送消息", "发送邮件", "推送通知",
        ),
        schema_keys=("recipient", "channel"),
    ),
    Facet(
        name="net.listen",
        risk=Severity.HIGH,
        label="listen on the network",
        phrases=(
            "listen on", "listen port", "listen_port", "bind port", "bind a socket", "http server",
            "web server", "start server", "start_server", "start a server", "accept connection",
            "websocket server", "监听端口", "启动服务",
        ),
        schema_keys=("port", "bind"),
    ),
    Facet(
        name="net.egress",
        risk=Severity.MEDIUM,
        label="make outbound network requests",
        phrases=(
            "http request", "http get", "http post", "https request", "make an http request",
            "fetch url", "fetch_url", "fetch a url", "api call", "api_call", "call an api",
            "rest api", "external api", "web request", "download file", "download a file",
            "download_file", "upload file", "upload a file", "upload_file", "web search",
            "search the web", "curl", "网络请求", "下载文件", "上传文件",
        ),
        schema_keys=("url", "uri", "endpoint", "host", "domain"),
    ),
    Facet(
        name="browser.control",
        risk=Severity.MEDIUM,
        label="drive a browser",
        phrases=(
            "control a browser", "drive a browser", "browser automation", "headless browser",
            "navigate to", "click element", "click an element", "take screenshot",
            "take a screenshot", "playwright", "puppeteer", "selenium",
            "浏览器", "截图", "点击元素",
        ),
        schema_keys=("selector", "screenshot", "tab_id"),
    ),
    Facet(
        name="clipboard",
        risk=Severity.MEDIUM,
        label="read or write the clipboard",
        phrases=(
            "clipboard", "copy to clipboard", "copy_to_clipboard", "system clipboard", "paste",
            "剪贴板", "复制粘贴",
        ),
        schema_keys=("clipboard",),
    ),
    Facet(
        name="fs.read",
        risk=Severity.LOW,
        label="read files or directories",
        phrases=(
            "read file", "read_file", "readfile", "read a file", "read the file", "read files",
            "view file", "view a file", "view the file", "open file", "open a file",
            "list directory", "list_directory", "list files", "list the files",
            "directory listing", "show the directory tree", "glob pattern", "file contents",
            "contents of a file", "file metadata",
            "读取文件", "查看文件", "列出目录", "文件内容",
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
