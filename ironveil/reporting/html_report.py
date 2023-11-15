"""
IronVeil HTML Report Generator

Produces a self-contained HTML security audit report with findings,
risk scores, remediation recommendations, charts, and executive summary.
"""

import html
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ironveil.reporting.html_report")

# Inline CSS for self-contained reports
_REPORT_CSS = """
:root {
    --bg: #0a0e17; --surface: #131a2b; --border: #1e2a42;
    --text: #c8d6e5; --heading: #f5f6fa; --accent: #00d2ff;
    --critical: #ff3838; --high: #ff9f43; --medium: #feca57;
    --low: #54a0ff; --info: #576574;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg);
       color: var(--text); line-height: 1.6; padding: 2rem; }
.container { max-width: 1100px; margin: 0 auto; }
h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
h2 { color: var(--heading); font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
h3 { color: var(--heading); font-size: 1.1rem; margin: 1rem 0 0.5rem; }
.meta { color: var(--info); font-size: 0.9rem; margin-bottom: 2rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
.score { font-size: 3rem; font-weight: 700; text-align: center; }
.score.critical { color: var(--critical); }
.score.high { color: var(--high); }
.score.medium { color: var(--medium); }
.score.low { color: var(--low); }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--heading); font-weight: 600; }
.severity { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
.severity.critical { background: var(--critical); color: #fff; }
.severity.high { background: var(--high); color: #000; }
.severity.medium { background: var(--medium); color: #000; }
.severity.low { background: var(--low); color: #fff; }
.severity.info { background: var(--info); color: #fff; }
.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--info); font-size: 0.85rem; text-align: center; }
"""


def _escape(text: Any) -> str:
    """HTML-escape a value."""
    return html.escape(str(text))


def _severity_class(score: float) -> str:
    if score >= 8:
        return "critical"
    elif score >= 6:
        return "high"
    elif score >= 4:
        return "medium"
    return "low"


class HtmlReportGenerator:
    """Generates self-contained HTML audit reports."""

    def __init__(
        self,
        output_dir: str = "./reports",
        include_raw_data: bool = False,
    ) -> None:
        self.output_dir = output_dir
        self.include_raw_data = include_raw_data

    def generate(self, audit_result: Any) -> str:
        """Generate an HTML report and return the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"ironveil_report_{audit_result.audit_id}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        content = self._render(audit_result)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(content)

        logger.info("HTML report generated: %s", filepath)
        return filepath

    def _render(self, result: Any) -> str:
        """Render the full HTML document."""
        parts: List[str] = []
        parts.append(self._render_header(result))
        parts.append(self._render_executive_summary(result))
        parts.append(self._render_risk_score(result))
        parts.append(self._render_findings_table(result))
        parts.append(self._render_phase_details(result))
        parts.append(self._render_remediation(result))
        parts.append(self._render_footer(result))

        body = "\n".join(parts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IronVeil Security Audit Report — {_escape(result.audit_id)}</title>
    <style>{_REPORT_CSS}</style>
</head>
<body>
    <div class="container">
        {body}
    </div>
</body>
</html>"""

    def _render_header(self, result: Any) -> str:
        started = datetime.fromtimestamp(result.started_at, tz=timezone.utc)
        return f"""
        <h1>IronVeil Security Audit Report</h1>
        <div class="meta">
            <strong>Audit ID:</strong> {_escape(result.audit_id)} &nbsp;|&nbsp;
            <strong>Target:</strong> {_escape(result.target_url)} &nbsp;|&nbsp;
            <strong>Date:</strong> {started.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
            <strong>Duration:</strong> {result.duration_seconds:.0f}s &nbsp;|&nbsp;
            <strong>Status:</strong> {_escape(result.phase.value)}
        </div>"""

    def _render_executive_summary(self, result: Any) -> str:
        counts = result.finding_counts
        total = len(result.findings)
        return f"""
        <h2>Executive Summary</h2>
        <div class="card">
            <p>IronVeil performed an automated security audit of
            <strong>{_escape(result.target_url)}</strong> covering bot detection
            analysis, behavioral analysis, fingerprint testing, CAPTCHA classification,
            API security probing, and platform integrity verification.</p>
            <p style="margin-top:1rem;">
                <strong>Total findings:</strong> {total} &nbsp;—&nbsp;
                <span class="severity critical">Critical: {counts.get('critical', 0)}</span>
                <span class="severity high">High: {counts.get('high', 0)}</span>
                <span class="severity medium">Medium: {counts.get('medium', 0)}</span>
                <span class="severity low">Low: {counts.get('low', 0)}</span>
                <span class="severity info">Info: {counts.get('info', 0)}</span>
            </p>
        </div>"""

    def _render_risk_score(self, result: Any) -> str:
        score = result.risk_score
        css_class = _severity_class(score)
        return f"""
        <h2>Overall Risk Score</h2>
        <div class="card">
            <div class="score {css_class}">{score:.1f} / 10</div>
            <p style="text-align:center; margin-top:0.5rem;">
                Risk level: <strong>{css_class.upper()}</strong>
            </p>
        </div>"""

    def _render_findings_table(self, result: Any) -> str:
        if not result.findings:
            return "<h2>Findings</h2><div class='card'><p>No findings.</p></div>"

        rows = ""
        for i, f in enumerate(result.findings, 1):
            rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity {_escape(f.severity)}">{_escape(f.severity)}</span></td>
                <td>{_escape(f.module)}</td>
                <td>{_escape(f.title)}</td>
                <td>{_escape(f.description[:120])}</td>
            </tr>"""

        return f"""
        <h2>Findings ({len(result.findings)})</h2>
        <table>
            <thead>
                <tr><th>#</th><th>Severity</th><th>Module</th><th>Title</th><th>Description</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _render_phase_details(self, result: Any) -> str:
        sections = ""
        for phase_name, data in result.phase_results.items():
            sections += f"""
            <h3>{_escape(phase_name.replace('_', ' ').title())}</h3>
            <div class="card">
                <pre style="white-space:pre-wrap; font-size:0.85rem;">{_escape(self._format_data(data))}</pre>
            </div>"""

        return f"<h2>Phase Details</h2>{sections}"

    def _render_remediation(self, result: Any) -> str:
        recs = [f for f in result.findings if f.remediation]
        if not recs:
            return ""

        items = ""
        for f in recs:
            items += f"<li><strong>[{_escape(f.severity.upper())}] {_escape(f.title)}:</strong> {_escape(f.remediation)}</li>"

        return f"""
        <h2>Remediation Recommendations</h2>
        <div class="card">
            <ul style="padding-left:1.5rem;">{items}</ul>
        </div>"""

    def _render_footer(self, result: Any) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return f"""
        <div class="footer">
            Generated by <strong>IronVeil</strong> — Casino &amp; iGaming Security Audit Framework<br>
            Report generated at {now} &nbsp;|&nbsp; &copy; BypassCore Labs
        </div>"""

    @staticmethod
    def _format_data(data: Any, indent: int = 0) -> str:
        """Format nested data for display."""
        if isinstance(data, dict):
            lines = []
            for k, v in data.items():
                formatted_v = HtmlReportGenerator._format_data(v, indent + 2)
                lines.append(f"{' ' * indent}{k}: {formatted_v}")
            return "\n".join(lines)
        elif isinstance(data, list):
            if len(data) == 0:
                return "[]"
            lines = []
            for item in data[:20]:  # Limit to 20 items
                lines.append(f"{' ' * indent}- {HtmlReportGenerator._format_data(item, indent + 2)}")
            if len(data) > 20:
                lines.append(f"{' ' * indent}... and {len(data) - 20} more")
            return "\n".join(lines)
        else:
            return str(data)
