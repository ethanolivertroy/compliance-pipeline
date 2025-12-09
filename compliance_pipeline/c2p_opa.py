#!/usr/bin/env python3
# -*- mode:python; coding:utf-8 -*-

"""C2P (Compliance to Policy) orchestration for OPA/Rego policies.

This script transforms OSCAL Component Definitions into OPA Rego policies
for FedRAMP 20x compliance validation of cloud infrastructure.

Usage:
    python -m compliance_pipeline.c2p_opa \
        -c ./pipeline/component-definition.json \
        -o ./pipeline/opa-policies \
        --cloud-provider aws
"""

import argparse
import sys
import tempfile
from pathlib import Path

from c2p.framework.c2p import C2P
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal

from compliance_pipeline.c2p_plugin.opa import PluginConfigOPA, PluginOPA


def tree(path: Path, texts: list[str] = None, depth: int = 0) -> list[str]:
    """Generate tree representation of directory structure."""
    if texts is None:
        texts = []
    prefix = ''
    if depth > 0:
        prefix = '-' * depth + ' '
    for item in sorted(path.iterdir()):
        texts.append(f'{prefix}{item.name}')
        if item.is_dir():
            tree(item, texts, depth=depth + 1)
    return texts


def main():
    parser = argparse.ArgumentParser(
        description='Generate OPA/Rego policies from OSCAL Component Definition'
    )
    parser.add_argument(
        '-c', '--component-definition',
        type=str,
        help='Path to component-definition.json',
        required=True,
    )
    parser.add_argument(
        '-o', '--out',
        type=str,
        help='Path to output directory (default: system temporary directory)',
        required=False,
    )
    parser.add_argument(
        '--cloud-provider',
        type=str,
        choices=['aws', 'azure', 'gcp'],
        default='aws',
        help='Cloud provider for policy generation (default: aws)',
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress output tree',
    )
    args = parser.parse_args()

    output_dir = args.out if args.out else tempfile.mkdtemp()

    # Setup C2P config
    c2p_config = C2PConfig()
    c2p_config.compliance = ComplianceOscal()
    c2p_config.compliance.component_definition = args.component_definition
    c2p_config.pvp_name = 'OPA'
    c2p_config.result_title = 'OPA FedRAMP 20x Assessment Results'
    c2p_config.result_description = 'OSCAL Assessment Results from OPA/Conftest'

    # Construct C2P
    c2p = C2P(c2p_config)

    # Transform OSCAL (Compliance) to OPA Policy
    base_dir = Path(__file__).parent
    policy_template_dir = f'{base_dir.absolute().as_posix()}/c2p_plugin/opa-policy-resources'

    config = PluginConfigOPA(
        policy_template_dir=policy_template_dir,
        deliverable_policy_dir=output_dir,
        cloud_provider=args.cloud_provider,
    )
    PluginOPA(config).generate_pvp_policy(c2p.get_policy())

    if not args.quiet:
        print('')
        print(f'Generated OPA policies for {args.cloud_provider}:')
        print(f'tree {output_dir}')
        for text in tree(Path(output_dir)):
            print(text)
        print('')
        print(f'Policies written to: {output_dir}')
        print('')
        print('To validate Terraform with Conftest:')
        print(f'  conftest test tfplan.json --policy {output_dir}')


if __name__ == '__main__':
    main()
