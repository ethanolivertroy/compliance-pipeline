#!/usr/bin/env python3
# -*- mode:python; coding:utf-8 -*-

"""Conftest runner for validating Terraform plans against OPA policies.

This module provides a wrapper around the Conftest CLI for running OPA/Rego
policies against Terraform plan JSON files.

Usage:
    from compliance_pipeline.collectors.conftest_runner import ConftestRunner

    runner = ConftestRunner(policy_dir="./pipeline/opa-policies")
    results = runner.validate_terraform_plan("./tfplan.json")
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import re


class ConftestRunner:
    """Execute Conftest against Terraform plans."""

    def __init__(
        self,
        policy_dir: str,
        data_dir: Optional[str] = None,
        fail_on_warn: bool = False
    ):
        """Initialize Conftest runner.

        Args:
            policy_dir: Path to directory containing Rego policies
            data_dir: Optional path to directory containing data files
            fail_on_warn: If True, treat warnings as failures
        """
        self.policy_dir = Path(policy_dir)
        self.data_dir = Path(data_dir) if data_dir else None
        self.fail_on_warn = fail_on_warn

    def validate_terraform_plan(
        self,
        plan_json_path: str,
        namespaces: Optional[List[str]] = None,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """Run Conftest against a Terraform plan JSON file.

        Args:
            plan_json_path: Path to terraform plan JSON (from `terraform show -json tfplan`)
            namespaces: Optional list of Rego namespaces to evaluate
            output_format: Output format (json, tap, table, junit, github)

        Returns:
            Dictionary containing normalized results
        """
        plan_path = Path(plan_json_path)
        if not plan_path.exists():
            raise FileNotFoundError(f"Terraform plan not found: {plan_path}")

        cmd = self._build_command(plan_path, namespaces, output_format)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Conftest returns non-zero on policy failures, which is expected
            if output_format == "json":
                output = json.loads(result.stdout) if result.stdout else []
            else:
                output = result.stdout

            return self._normalize_output(output, result.returncode)

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Conftest execution timed out",
                "results": []
            }
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Failed to parse Conftest output: {e}",
                "raw_output": result.stdout,
                "results": []
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "results": []
            }

    def _build_command(
        self,
        plan_path: Path,
        namespaces: Optional[List[str]],
        output_format: str
    ) -> List[str]:
        """Build the conftest command."""
        cmd = [
            "conftest", "test",
            str(plan_path),
            "--policy", str(self.policy_dir),
            "--output", output_format,
            "--all-namespaces",
        ]

        if self.data_dir and self.data_dir.exists():
            cmd.extend(["--data", str(self.data_dir)])

        if namespaces:
            for ns in namespaces:
                cmd.extend(["--namespace", ns])

        if self.fail_on_warn:
            cmd.append("--fail-on-warn")

        return cmd

    def _normalize_output(
        self,
        conftest_output: List[Dict],
        return_code: int
    ) -> Dict[str, Any]:
        """Normalize Conftest output for consumption by P2C.

        Conftest JSON output format:
        [
            {
                "filename": "tfplan.json",
                "namespace": "ksi.cna01.aws",
                "successes": [{"msg": "...", "metadata": {...}}],
                "failures": [{"msg": "...", "metadata": {...}}],
                "warnings": [{"msg": "...", "metadata": {...}}],
                "exceptions": []
            }
        ]
        """
        results = []
        total_failures = 0
        total_warnings = 0
        total_successes = 0

        for file_result in conftest_output:
            filename = file_result.get("filename", "unknown")
            namespace = file_result.get("namespace", "unknown")

            # Process failures
            for failure in file_result.get("failures", []):
                total_failures += 1
                results.append({
                    "policy": self._extract_policy_name(failure, namespace),
                    "status": "fail",
                    "message": failure.get("msg", ""),
                    "resource_id": self._extract_resource_from_message(failure.get("msg", "")),
                    "resource_type": "terraform_resource",
                    "filename": filename,
                    "namespace": namespace,
                    "metadata": failure.get("metadata", {}),
                })

            # Process warnings
            for warning in file_result.get("warnings", []):
                total_warnings += 1
                results.append({
                    "policy": self._extract_policy_name(warning, namespace),
                    "status": "warn",
                    "message": warning.get("msg", ""),
                    "resource_id": self._extract_resource_from_message(warning.get("msg", "")),
                    "resource_type": "terraform_resource",
                    "filename": filename,
                    "namespace": namespace,
                    "metadata": warning.get("metadata", {}),
                })

            # Process successes
            for success in file_result.get("successes", []):
                total_successes += 1
                results.append({
                    "policy": self._extract_policy_name(success, namespace),
                    "status": "pass",
                    "message": success.get("msg", "Policy check passed"),
                    "resource_id": "all",
                    "resource_type": "terraform_resource",
                    "filename": filename,
                    "namespace": namespace,
                    "metadata": success.get("metadata", {}),
                })

        return {
            "success": return_code == 0,
            "summary": {
                "total": len(results),
                "failures": total_failures,
                "warnings": total_warnings,
                "successes": total_successes,
            },
            "results": results,
        }

    def _extract_policy_name(self, result: Dict, namespace: str) -> str:
        """Extract policy/rule name from Conftest result."""
        metadata = result.get("metadata", {})

        # Try to get rule name from metadata
        rule = metadata.get("rule", "")
        if rule:
            return rule

        # Try to extract from namespace
        if namespace and namespace != "unknown":
            # Convert namespace like "ksi.cna01.aws" to "ksi-cna-01"
            parts = namespace.split(".")
            if len(parts) >= 2:
                return "-".join(parts[:2])

        return "unknown"

    def _extract_resource_from_message(self, msg: str) -> str:
        """Extract resource address from Conftest message.

        Common patterns in violation messages:
        - "Resource 'aws_security_group.main' ..."
        - "Security group rule 'aws_security_group_rule.ssh' allows..."
        - "'aws_lb_listener.http' uses HTTP..."
        """
        patterns = [
            r"Resource\s+'([^']+)'",
            r"'([a-z_]+\.[a-zA-Z0-9_-]+)'",
            r'"([a-z_]+\.[a-zA-Z0-9_-]+)"',
        ]

        for pattern in patterns:
            match = re.search(pattern, msg)
            if match:
                return match.group(1)

        return "unknown"


def main():
    """CLI entry point for running Conftest validation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate Terraform plan against OPA policies using Conftest"
    )
    parser.add_argument(
        "-p", "--policy-dir",
        type=str,
        required=True,
        help="Path to directory containing Rego policies"
    )
    parser.add_argument(
        "-t", "--terraform-plan",
        type=str,
        required=True,
        help="Path to Terraform plan JSON file"
    )
    parser.add_argument(
        "-d", "--data-dir",
        type=str,
        help="Path to directory containing data files"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Treat warnings as failures"
    )
    args = parser.parse_args()

    runner = ConftestRunner(
        policy_dir=args.policy_dir,
        data_dir=args.data_dir,
        fail_on_warn=args.fail_on_warn
    )

    results = runner.validate_terraform_plan(args.terraform_plan)

    output_json = json.dumps(results, indent=2)

    if args.output:
        Path(args.output).write_text(output_json)
        print(f"Results written to: {args.output}", file=sys.stderr)

        # Print summary
        summary = results.get("summary", {})
        print(f"\nSummary:", file=sys.stderr)
        print(f"  Failures: {summary.get('failures', 0)}", file=sys.stderr)
        print(f"  Warnings: {summary.get('warnings', 0)}", file=sys.stderr)
        print(f"  Successes: {summary.get('successes', 0)}", file=sys.stderr)
    else:
        print(output_json)

    # Exit with non-zero if there were failures
    if not results.get("success", True):
        sys.exit(1)


if __name__ == "__main__":
    main()
