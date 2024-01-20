"""
IronVeil JSON Export

Exports audit results in structured JSON format for integration with
external tools, SIEM systems, dashboards, and CI/CD pipelines.
Supports filtering, schema versioning, and SARIF-compatible output.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("ironveil.reporting.json_export")

# Schema version for forward compatibility
SCHEMA_VERSION = "1.2.0"


def _serialize_value(obj: Any) -> Any:
    """Convert non-serializable objects to JSON-friendly types."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialize_value(getattr(obj, k)) for k in obj.__dataclass_fields__}
    if hasattr(obj, "value"):  # Enum
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted(str(x) for x in obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _serialize_value(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_value(item) for item in obj]
    return obj


class JsonExporter:
    """Exports audit results to JSON files."""

    def __init__(
        self,
        output_dir: str = "./reports",
        pretty: bool = True,
        include_raw: bool = False,
    ) -> None:
        self.output_dir = output_dir
        self.pretty = pretty
        self.include_raw = include_raw

    def export(
        self,
        audit_result: Any,
        filename: Optional[str] = None,
    ) -> str:
        """Export audit results to a JSON file, returning the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        if filename is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"ironveil_{audit_result.audit_id}_{ts}.json"

        filepath = os.path.join(self.output_dir, filename)
        data = self.build_document(audit_result)

        indent = 2 if self.pretty else None
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, default=str, ensure_ascii=False)

        logger.info("JSON report exported: %s (%.1f KB)",
                     filepath, os.path.getsize(filepath) / 1024)
        return filepath

    def build_document(self, audit_result: Any) -> Dict[str, Any]:
        """Build the complete JSON document structure."""
        doc = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "IronVeil",
                "version": "0.1.0",
                "vendor": "BypassCore Labs",
                "url": "https://github.com/bypasscore/ironveil",
            },
            "audit": {
                "id": audit_result.audit_id,
                "target_url": audit_result.target_url,
                "started_at": datetime.fromtimestamp(
                    audit_result.started_at, tz=timezone.utc
                ).isoformat(),
                "completed_at": datetime.fromtimestamp(
                    audit_result.completed_at, tz=timezone.utc
                ).isoformat() if audit_result.completed_at else None,
                "duration_seconds": round(audit_result.duration_seconds, 1),
                "status": audit_result.phase.value,
                "error": audit_result.error,
            },
            "summary": {
                "risk_score": audit_result.risk_score,
                "total_findings": len(audit_result.findings),
                "finding_counts": audit_result.finding_counts,
            },
            "findings": [
                self._serialize_finding(f) for f in audit_result.findings
            ],
        }

        if self.include_raw:
            doc["phase_results"] = _serialize_value(audit_result.phase_results)

        return doc

    def _serialize_finding(self, finding: Any) -> Dict[str, Any]:
        return {
            "phase": finding.phase.value if hasattr(finding.phase, "value") else str(finding.phase),
            "module": finding.module,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "data": _serialize_value(finding.data),
            "timestamp": datetime.fromtimestamp(
                finding.timestamp, tz=timezone.utc
            ).isoformat(),
            "remediation": finding.remediation,
        }

    def export_findings_only(
        self,
        audit_result: Any,
        min_severity: str = "low",
    ) -> str:
        """Export only findings, optionally filtered by minimum severity."""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_level = severity_order.get(min_severity, 0)

        filtered = [
            f for f in audit_result.findings
            if severity_order.get(f.severity, 0) >= min_level
        ]

        os.makedirs(self.output_dir, exist_ok=True)
        filename = f"ironveil_findings_{audit_result.audit_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        data = {
            "schema_version": SCHEMA_VERSION,
            "audit_id": audit_result.audit_id,
            "target_url": audit_result.target_url,
            "filter": {"min_severity": min_severity},
            "findings": [self._serialize_finding(f) for f in filtered],
        }

        indent = 2 if self.pretty else None
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, default=str, ensure_ascii=False)

        logger.info("Findings export: %d findings (min_severity=%s) -> %s",
                     len(filtered), min_severity, filepath)
        return filepath


class SarifExporter:
    """Exports findings in SARIF 2.1.0 format for GitHub/Azure integration."""

    SARIF_VERSION = "2.1.0"

    def __init__(self, output_dir: str = "./reports") -> None:
        self.output_dir = output_dir

    def export(self, audit_result: Any) -> str:
        """Export audit findings as a SARIF file."""
        os.makedirs(self.output_dir, exist_ok=True)

        filename = f"ironveil_{audit_result.audit_id}.sarif"
        filepath = os.path.join(self.output_dir, filename)

        sarif = self._build_sarif(audit_result)

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, default=str, ensure_ascii=False)

        logger.info("SARIF report exported: %s", filepath)
        return filepath

    def _build_sarif(self, result: Any) -> Dict[str, Any]:
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        rules: List[Dict[str, Any]] = []
        rule_ids: Set[str] = set()
        sarif_results: List[Dict[str, Any]] = []

        for i, finding in enumerate(result.findings):
            rule_id = f"IV{i:04d}"
            if finding.module not in rule_ids:
                rules.append({
                    "id": rule_id,
                    "name": finding.title[:60],
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": severity_map.get(finding.severity, "note"),
                    },
                })
                rule_ids.add(finding.module)

            sarif_results.append({
                "ruleId": rule_id,
                "level": severity_map.get(finding.severity, "note"),
                "message": {"text": finding.description},
                "properties": {
                    "module": finding.module,
                    "phase": finding.phase.value if hasattr(finding.phase, "value") else str(finding.phase),
                    "severity": finding.severity,
                },
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "IronVeil",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/bypasscore/ironveil",
                            "rules": rules,
                        },
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": result.error is None,
                            "startTimeUtc": datetime.fromtimestamp(
                                result.started_at, tz=timezone.utc
                            ).isoformat(),
                        }
                    ],
                },
            ],
        }
