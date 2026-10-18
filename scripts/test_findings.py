#!/usr/bin/env python3
"""
InfraMind - Mock-JSON Threat Triage Test Runner (scripts/test_findings.py)

CLI test runner that ingests AWS Security Hub findings JSON files,
executes the threat triage pipeline using MockInferenceProvider (offline mode),
and displays an executive security triage report without touching live AWS resources.

Usage:
    python scripts/test_findings.py <path_to_findings.json>
"""

from __future__ import annotations
import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Configure stdout for safe output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from inframind import MockInferenceProvider, triage_findings


def format_report_for_cli(result) -> str:
    """Format triage results into a readable security analyst report."""
    if result.total_findings == 0:
        return (
            "================================================================================\n"
            "[*] InfraMind Threat Triage Report (Offline Mock Mode)\n"
            "================================================================================\n"
            "No findings to process (empty findings payload).\n"
            "Total Findings: 0\n"
            "================================================================================"
        )

    lines = []
    lines.append("=" * 80)
    lines.append("[*] InfraMind Threat Triage Report (Offline Mock Mode)")
    lines.append("=" * 80)
    lines.append(f"Total Findings Processed: {result.total_findings}")
    lines.append(f"Priority Breakdown:       {dict(result.counts_by_priority)}")
    lines.append(f"Inference Provider:       {result.provider_info.get('provider')} ({result.provider_info.get('model', 'default')})")
    lines.append("-" * 80)

    for idx, item in enumerate(result.findings, 1):
        f = item.finding
        a = item.assessment
        e = item.explanation
        p = item.remediation_preview

        res_desc = ", ".join(f"{r.type}: {r.id}" for r in f.resources) if f.resources else "None specified"

        lines.append(f"\n[{idx}] PRIORITY: [{a.priority_tier.value}] (Score: {a.score}/100)")
        lines.append(f"    Title:           {f.title}")
        lines.append(f"    Finding ID:      {f.id}")
        lines.append(f"    Source Severity: {f.source_severity}")
        lines.append(f"    Resources:       {res_desc}")
        lines.append(f"    Scoring Basis:   {a.basis}")

        # Observed Facts
        if a.observed_facts:
            lines.append("    Observed Facts:")
            for fact in a.observed_facts:
                lines.append(f"      [FACT] {fact}")
        else:
            lines.append("    Observed Facts: None verified from payload")

        # Inferences
        if a.inferred_risks:
            lines.append("    Inferred Risks:")
            for inf in a.inferred_risks:
                lines.append(f"      [RISK] {inf}")

        # Unknowns
        if a.unknown_information:
            lines.append("    Evidence Gaps (Unknowns):")
            for unk in a.unknown_information:
                lines.append(f"      [GAP]  {unk}")

        # LLM Explanation
        lines.append(f"    AI Explanation (Available: {e.is_llm_available}):")
        lines.append(f"      Justification:   {e.priority_justification}")
        lines.append(f"      Business Impact: {e.business_impact_summary}")

        # Remediation
        if e.recommended_action:
            act = e.recommended_action
            lines.append("    Recommended Action:")
            lines.append(f"      Action ID:       {act.action_id}")
            lines.append(f"      Target Resource: {act.target_resource_id} ({act.target_resource_type})")
            lines.append(f"      Parameters:      {act.parameters}")
            lines.append(f"      Rationale:       {act.rationale}")

            if p:
                lines.append("    Remediation Preview:")
                lines.append(f"      Status:            {p.get('status')}")
                lines.append(f"      Mapped Action:     {p.get('action')}")
                lines.append(f"      Approval Required: {p.get('requires_approval', True)}")
                lines.append(f"      Executable:        {p.get('executable', False)}")
        else:
            lines.append("    Recommended Action: None")

        lines.append("-" * 80)

    lines.append("=" * 80)
    lines.append("[SAFE] Offline demo complete. Zero AWS API calls made.")
    lines.append("=" * 80)
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/test_findings.py <path_to_findings.json>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Error: Finding file '{file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
    except Exception as exc:
        print(f"Error reading file '{file_path}': {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        provider = MockInferenceProvider()
        result = triage_findings(raw_content, provider=provider)
    except ValueError as exc:
        print(f"Error: Malformed JSON or invalid finding payload in '{file_path}': {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: Triage pipeline failed for '{file_path}': {exc}", file=sys.stderr)
        sys.exit(1)

    print(format_report_for_cli(result))
    sys.exit(0)


if __name__ == "__main__":
    main()

