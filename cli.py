#!/usr/bin/env python3
"""
IronVeil CLI — Command-line interface for casino/iGaming security audits.

Usage:
    ironveil audit <target_url> [options]
    ironveil report <audit_id> [options]
    ironveil config [show|validate|init]
    ironveil version
"""

import sys
import logging
from typing import Optional

import click

from ironveil import __version__, configure_logging
from ironveil.core.config import Config, ConfigNotFoundError
from ironveil.core.engine import AuditEngine, AuditResult
from ironveil.reporting.html_report import HtmlReportGenerator
from ironveil.reporting.json_export import JsonExporter, SarifExporter


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output")
@click.option("--config", "-c", "config_path", type=click.Path(), default=None,
              help="Path to configuration file")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool, config_path: Optional[str]) -> None:
    """IronVeil — Casino & iGaming Security Audit Framework"""
    ctx.ensure_object(dict)

    level = "DEBUG" if verbose else ("ERROR" if quiet else "INFO")
    configure_logging(level)

    try:
        ctx.obj["config"] = Config(config_path=config_path)
    except ConfigNotFoundError as exc:
        if config_path:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        ctx.obj["config"] = Config(auto_discover=False)


@cli.command()
@click.argument("target_url")
@click.option("--output", "-o", type=click.Path(), default="./reports",
              help="Output directory for reports")
@click.option("--format", "-f", "report_format", type=click.Choice(["html", "json", "sarif", "all"]),
              default="all", help="Report format")
@click.option("--headless/--no-headless", default=True, help="Run browser in headless mode")
@click.option("--proxy", "-p", type=str, default=None, help="Proxy URL")
@click.option("--timeout", "-t", type=int, default=300, help="Session timeout in seconds")
@click.option("--profile", type=click.Choice(["casual", "focused", "slow", "aggressive"]),
              default="casual", help="Timing profile")
@click.option("--skip-detection", is_flag=True, help="Skip detection analysis phase")
@click.option("--skip-evasion", is_flag=True, help="Skip evasion testing phase")
@click.option("--skip-platform", is_flag=True, help="Skip platform analysis phase")
@click.pass_context
def audit(
    ctx: click.Context,
    target_url: str,
    output: str,
    report_format: str,
    headless: bool,
    proxy: Optional[str],
    timeout: int,
    profile: str,
    skip_detection: bool,
    skip_evasion: bool,
    skip_platform: bool,
) -> None:
    """Run a security audit against a target casino/iGaming platform."""
    config: Config = ctx.obj["config"]

    # Apply CLI overrides
    config.set("general.output_dir", output)
    config.set("browser.headless", headless)
    config.set("session.session_timeout", timeout)

    if proxy:
        config.set("session.proxy_list_file", None)
        # Direct proxy override handled by session

    if skip_detection:
        config.set("detection.bot_detection_tests", False)
        config.set("detection.behavioral_analysis", False)
        config.set("detection.fingerprint_analysis", False)
        config.set("detection.captcha_analysis", False)

    if skip_evasion:
        config.set("evasion.human_simulation", False)
        config.set("evasion.fingerprint_spoofing", False)
        config.set("evasion.timing_evasion", False)

    if skip_platform:
        config.set("platform.api_probing", False)
        config.set("platform.integrity_checks", False)

    click.echo(f"IronVeil v{__version__}")
    click.echo(f"Target: {target_url}")
    click.echo(f"Profile: {profile}")
    click.echo(f"Output: {output}")
    click.echo("—" * 50)

    engine = AuditEngine(config)

    def on_finding(finding, **_):
        icon = {"critical": "!!", "high": "!", "medium": "*", "low": "-", "info": "."}
        click.echo(f"  [{icon.get(finding.severity, '?')}] {finding.title}")

    engine.register_hook("on_finding", on_finding)

    try:
        result = engine.run(target_url)
    except KeyboardInterrupt:
        click.echo("\nAudit interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        click.echo(f"\nAudit failed: {exc}", err=True)
        sys.exit(1)

    # Generate reports
    _generate_reports(result, output, report_format)

    # Summary
    click.echo("—" * 50)
    click.echo(f"Audit complete: {len(result.findings)} findings")
    click.echo(f"Risk score: {result.risk_score:.1f}/10")
    click.echo(f"Duration: {result.duration_seconds:.0f}s")
    click.echo(f"Reports saved to: {output}/")


@cli.command()
@click.argument("report_path", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["html", "json", "sarif"]),
              default="html", help="Convert to format")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
def report(report_path: str, output_format: str, output: Optional[str]) -> None:
    """Convert or view an existing audit report."""
    import json as json_mod

    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            data = json_mod.load(fh)
    except Exception as exc:
        click.echo(f"Error reading report: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Report: {report_path}")
    click.echo(f"Audit ID: {data.get('audit', {}).get('id', 'unknown')}")
    click.echo(f"Target: {data.get('audit', {}).get('target_url', 'unknown')}")
    click.echo(f"Findings: {data.get('summary', {}).get('total_findings', 0)}")
    click.echo(f"Risk Score: {data.get('summary', {}).get('risk_score', 0)}")


@cli.group()
def config() -> None:
    """Manage IronVeil configuration."""
    pass


@config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Display the current configuration."""
    import yaml
    cfg: Config = ctx.obj["config"]
    click.echo(f"Source: {cfg.source_file or 'built-in defaults'}")
    click.echo("—" * 50)
    click.echo(yaml.dump(cfg.as_dict(), default_flow_style=False, sort_keys=True))


@config.command("validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate the current configuration."""
    cfg: Config = ctx.obj["config"]
    warnings = cfg.validate()
    if warnings:
        click.echo("Configuration warnings:")
        for w in warnings:
            click.echo(f"  - {w}")
        sys.exit(1)
    else:
        click.echo("Configuration is valid.")


@config.command("init")
@click.option("--path", "-p", type=click.Path(), default="./ironveil.yaml",
              help="Output path for config file")
def config_init(path: str) -> None:
    """Create a default configuration file."""
    import shutil
    from pathlib import Path

    default_src = Path(__file__).parent / "config" / "default.yaml"
    if default_src.exists():
        shutil.copy2(default_src, path)
        click.echo(f"Configuration file created: {path}")
    else:
        import yaml
        cfg = Config(auto_discover=False)
        with open(path, "w", encoding="utf-8") as fh:
            yaml.dump(cfg.as_dict(), fh, default_flow_style=False, sort_keys=True)
        click.echo(f"Configuration file created: {path}")


@cli.command()
def version() -> None:
    """Display the IronVeil version."""
    click.echo(f"IronVeil v{__version__}")


def _generate_reports(result: AuditResult, output_dir: str, fmt: str) -> None:
    """Generate reports in the requested format(s)."""
    if fmt in ("html", "all"):
        gen = HtmlReportGenerator(output_dir)
        path = gen.generate(result)
        click.echo(f"  HTML report: {path}")

    if fmt in ("json", "all"):
        exp = JsonExporter(output_dir, pretty=True, include_raw=True)
        path = exp.export(result)
        click.echo(f"  JSON report: {path}")

    if fmt in ("sarif", "all"):
        sarif = SarifExporter(output_dir)
        path = sarif.export(result)
        click.echo(f"  SARIF report: {path}")


def main() -> None:
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
