"""Standalone HTML review without rendering workflow values as markup."""

from __future__ import annotations

from html import escape
from typing import Any

from .advanced import GUIDANCE


def html_report(reports: list[dict[str, Any]], comparison: dict[str, Any]) -> str:
    rows = []
    for report in reports:
        for item in report["findings"]:
            cells = [
                report["source"],
                item["severity"],
                item["code"],
                item["location"],
                item["message"],
                GUIDANCE.get(item["code"], "Review this finding."),
                item.get("baselineState", "new"),
                "reviewed exception" if item.get("suppressed") else "active",
            ]
            rows.append(
                "<tr>" + "".join("<td>" + escape(str(x)) + "</td>" for x in cells) + "</tr>"
            )
    counts = {k: len(comparison.get(k, [])) for k in ("new", "unchanged", "resolved")}
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Workflow Sentry review</title><style>body{font:16px system-ui;margin:2rem;color:#182028;background:#fff}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:.65rem;text-align:left;overflow-wrap:anywhere}.table{overflow:auto}th{background:#eef2f5}</style><h1>Workflow Sentry review</h1><p>Static findings require review. No workflow was executed or changed.</p><p>'
        + escape(str(counts))
        + '</p><div class="table"><table><thead><tr>'
        + "".join(
            "<th>" + x + "</th>"
            for x in [
                "Source",
                "Severity",
                "Rule",
                "Location",
                "Finding",
                "Suggested review",
                "Baseline",
                "Status",
            ]
        )
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></html>"
    )
