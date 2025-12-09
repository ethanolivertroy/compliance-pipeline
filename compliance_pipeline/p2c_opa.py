#!/usr/bin/env python3
# -*- mode:python; coding:utf-8 -*-

"""P2C (Policy to Compliance) orchestration for OPA results.

This script transforms OPA/Conftest policy evaluation results into
OSCAL Assessment Results for FedRAMP 20x compliance reporting.

Usage:
    # From Conftest results:
    python -m compliance_pipeline.p2c_opa \
        -c ./pipeline/component-definition.json \
        --conftest-results ./pipeline/conftest-results.json

    # From OPA eval results:
    python -m compliance_pipeline.p2c_opa \
        -c ./pipeline/component-definition.json \
        --opa-results ./pipeline/opa-results.json

    # From a directory containing multiple result files:
    python -m compliance_pipeline.p2c_opa \
        -c ./pipeline/component-definition.json \
        --results-dir ./pipeline/results
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any

from c2p.framework.c2p import C2P
from c2p.framework.models import RawResult
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal

from compliance_pipeline.c2p_plugin.opa import PluginOPA


def load_json_file(path: Path) -> Any:
    """Load and parse a JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def merge_results(results: List[Any]) -> List[Any]:
    """Merge multiple result sets into a single list.

    Handles both Conftest format (list of file results) and
    OPA eval format (dict with 'result' key).
    """
    merged = []
    for result in results:
        if isinstance(result, list):
            # Conftest format - array of file results
            merged.extend(result)
        elif isinstance(result, dict):
            # OPA eval format or single result
            merged.append(result)
    return merged


def collect_results_from_dir(results_dir: Path) -> List[Any]:
    """Collect all JSON result files from a directory."""
    results = []
    for json_file in results_dir.rglob('*.json'):
        try:
            data = load_json_file(json_file)
            results.append(data)
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {json_file}: {e}", file=sys.stderr)
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Transform OPA/Conftest results to OSCAL Assessment Results'
    )
    parser.add_argument(
        '-c', '--component-definition',
        type=str,
        help='Path to component-definition.json',
        required=True,
    )
    parser.add_argument(
        '--conftest-results',
        type=str,
        help='Path to Conftest JSON results file',
        required=False,
    )
    parser.add_argument(
        '--opa-results',
        type=str,
        help='Path to OPA eval JSON results file',
        required=False,
    )
    parser.add_argument(
        '--results-dir',
        type=str,
        help='Path to directory containing result JSON files',
        required=False,
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: stdout)',
        required=False,
    )
    args = parser.parse_args()

    # Collect results from various sources
    all_results = []

    if args.conftest_results:
        conftest_path = Path(args.conftest_results)
        if conftest_path.exists():
            all_results.append(load_json_file(conftest_path))
        else:
            print(f"Warning: Conftest results not found: {conftest_path}", file=sys.stderr)

    if args.opa_results:
        opa_path = Path(args.opa_results)
        if opa_path.exists():
            all_results.append(load_json_file(opa_path))
        else:
            print(f"Warning: OPA results not found: {opa_path}", file=sys.stderr)

    if args.results_dir:
        results_dir = Path(args.results_dir)
        if results_dir.exists() and results_dir.is_dir():
            all_results.extend(collect_results_from_dir(results_dir))
        else:
            print(f"Warning: Results directory not found: {results_dir}", file=sys.stderr)

    if not all_results:
        print("Error: No results provided. Use --conftest-results, --opa-results, or --results-dir", file=sys.stderr)
        sys.exit(1)

    # Merge results if multiple sources
    merged_data = merge_results(all_results)

    # Setup C2P config
    c2p_config = C2PConfig()
    c2p_config.compliance = ComplianceOscal()
    c2p_config.compliance.component_definition = args.component_definition
    c2p_config.pvp_name = 'OPA'
    c2p_config.result_title = 'OPA FedRAMP 20x Assessment Results'
    c2p_config.result_description = 'OSCAL Assessment Results from OPA/Conftest policy evaluation'

    # Construct C2P
    c2p = C2P(c2p_config)

    # Create PVP result from raw OPA/Conftest results
    pvp_raw_result = RawResult(data=merged_data)
    pvp_result = PluginOPA().generate_pvp_result(pvp_raw_result)

    # Transform PVP result to OSCAL Assessment Result
    c2p.set_pvp_result(pvp_result)
    oscal_assessment_results = c2p.result_to_oscal()

    # Output results
    output_json = oscal_assessment_results.oscal_serialize_json(pretty=True)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(output_json)
        print(f"Assessment results written to: {output_path}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == '__main__':
    main()
