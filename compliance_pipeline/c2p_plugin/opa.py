# -*- mode:python; coding:utf-8 -*-

# Copyright 2024 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OPA (Open Policy Agent) plugin for FedRAMP 20x compliance validation."""

from pathlib import Path
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re
import json

from c2p.common.err import C2PError
from c2p.common.logging import getLogger
from c2p.common.utils import get_datetime, get_dict_safely
from c2p.framework.models import Policy, PVPResult, RawResult
from c2p.framework.models.pvp_result import (
    ObservationByCheck,
    PVPResult,
    ResultEnum,
    Subject,
)
from c2p.framework.plugin_spec import PluginConfig, PluginSpec
from jinja2 import Environment, FileSystemLoader
from pydantic.v1 import Field

logger = getLogger(__name__)

# OPA/Conftest result status mapping
opa_status_dictionary = {
    'pass': ResultEnum.Pass,
    'success': ResultEnum.Pass,
    'fail': ResultEnum.Failure,
    'failure': ResultEnum.Failure,
    'violation': ResultEnum.Failure,
    'warn': ResultEnum.Failure,
    'warning': ResultEnum.Failure,
    'skip': ResultEnum.Error,
    'error': ResultEnum.Error,
}


class PluginConfigOPA(PluginConfig):
    """Configuration for OPA plugin."""
    policy_template_dir: str = Field(..., title='Path to Rego policy template directory')
    deliverable_policy_dir: str = Field(..., title='Path to deliverable (generated) policy directory')
    cloud_provider: str = Field('aws', title='Cloud provider: aws, azure, gcp')


class PluginOPA(PluginSpec):
    """OPA plugin for compliance-to-policy and policy-to-compliance transformations."""

    def __init__(self, config: Optional[PluginConfigOPA] = None) -> None:
        super().__init__()
        self.config = config
        self.jinja_env = None
        if config and config.policy_template_dir:
            self._init_jinja_env()

    def _init_jinja_env(self):
        """Initialize Jinja2 environment for Rego template rendering."""
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.config.policy_template_dir),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        """Transform OPA/Conftest JSON results to PVPResult.

        Handles both Conftest output format and OPA eval output format.

        Conftest format (array of file results):
        [
            {
                "filename": "tfplan.json",
                "successes": [...],
                "failures": [{"msg": "...", "metadata": {"rule": "..."}}],
                "warnings": [...]
            }
        ]

        OPA eval format:
        {
            "result": [
                {"expressions": [{"value": {...}, "text": "data.ksi..."}]}
            ]
        }
        """
        pvp_result: PVPResult = PVPResult()
        observations: List[ObservationByCheck] = []

        results_data = raw_result.data

        # Detect format and parse accordingly
        if isinstance(results_data, list):
            # Conftest format - array of file results
            policy_results = self._parse_conftest_results(results_data)
        elif isinstance(results_data, dict):
            # OPA eval format or wrapped results
            if 'result' in results_data:
                policy_results = self._parse_opa_eval_results(results_data)
            elif 'results' in results_data:
                # Pre-normalized format from collectors
                policy_results = self._group_results_by_policy(results_data['results'])
            else:
                policy_results = {}
        else:
            policy_results = {}

        for policy_name, results in policy_results.items():
            observation = ObservationByCheck(
                check_id=policy_name,
                methods=['AUTOMATED'],
                collected=get_datetime()
            )

            subjects = []
            for result in results:
                status = self._extract_status(result)
                resource_id = self._extract_resource_id(result)
                message = self._extract_message(result)
                resource_type = result.get('resource_type', 'terraform_resource')

                subject = Subject(
                    title=f"{resource_type}/{resource_id}",
                    type='resource',
                    result=opa_status_dictionary.get(status, ResultEnum.Error),
                    resource_id=resource_id,
                    evaluated_on=get_datetime(),
                    reason=message,
                )
                subjects.append(subject)

            observation.subjects = subjects
            observations.append(observation)

        pvp_result.observations_by_check = observations
        return pvp_result

    def generate_pvp_policy(self, policy: Policy):
        """Generate Rego policies from OSCAL policy definition.

        For each rule_set in the policy:
        1. Look for cloud-specific templates first (e.g., aws/ksi-cna-01/)
        2. Fall back to common templates (common/ksi-cna-01/)
        3. Render Jinja2 templates with parameters from OSCAL
        """
        rule_sets = policy.rule_sets
        parameters = policy.parameters
        policy_template_dir = self.config.policy_template_dir
        deliverable_policy_dir = self.config.deliverable_policy_dir
        cloud_provider = self.config.cloud_provider

        # Ensure output directory exists
        if not Path(deliverable_policy_dir).exists():
            logger.info(f"Creating deliverable policy directory: {deliverable_policy_dir}")
            Path(deliverable_policy_dir).mkdir(parents=True)
        elif not Path(deliverable_policy_dir).is_dir():
            raise C2PError(f"Deliverable policy path is not a directory: {deliverable_policy_dir}")

        # Build parameter dictionary for template rendering
        param_dict = {p.id.replace('-', '_'): p.value for p in parameters}
        param_dict['cloud_provider'] = cloud_provider

        # Copy shared libraries first
        self._copy_shared_libs(Path(policy_template_dir), Path(deliverable_policy_dir))

        # Generate policies for each rule set
        for rule_set in rule_sets:
            self._generate_rule_policies(
                rule_set.rule_id,
                param_dict,
                Path(policy_template_dir),
                Path(deliverable_policy_dir),
                cloud_provider
            )

        # Handle -enforced parameters (for policies with enforcement variants)
        for parameter in parameters:
            matched = re.match(r'(.+)-enforced', parameter.id)
            if matched and parameter.value.lower() == "true":
                enforce_rule_id = f"{matched.group(1)}-enforced"
                self._generate_rule_policies(
                    enforce_rule_id,
                    param_dict,
                    Path(policy_template_dir),
                    Path(deliverable_policy_dir),
                    cloud_provider
                )

    def _generate_rule_policies(
        self,
        rule_id: str,
        params: dict,
        template_dir: Path,
        output_dir: Path,
        cloud_provider: str
    ):
        """Generate Rego files for a specific rule.

        Tries cloud-specific templates first, then falls back to common.
        """
        # Template search paths in order of preference
        template_paths = [
            template_dir / cloud_provider / rule_id,
            template_dir / "common" / rule_id,
        ]

        source_dir = None
        relative_template_path = None
        for path in template_paths:
            if path.exists() and path.is_dir():
                source_dir = path
                relative_template_path = path.relative_to(template_dir)
                break

        if source_dir is None:
            logger.warning(f"No template found for rule '{rule_id}' (cloud: {cloud_provider})")
            return

        target_dir = output_dir / rule_id
        target_dir.mkdir(parents=True, exist_ok=True)

        for rego_file in source_dir.glob("*.rego"):
            # Skip test files in deliverables
            if rego_file.name.endswith("_test.rego"):
                continue

            try:
                template_name = str(relative_template_path / rego_file.name)
                template = self.jinja_env.get_template(template_name)
                rendered = template.render(params)
                (target_dir / rego_file.name).write_text(rendered)
                logger.info(f"Generated policy: {target_dir / rego_file.name}")
            except Exception as e:
                logger.error(f"Failed to render template {rego_file}: {e}")
                # Copy file without rendering as fallback
                shutil.copy(rego_file, target_dir / rego_file.name)

    def _copy_shared_libs(self, template_dir: Path, output_dir: Path):
        """Copy shared Rego libraries to output directory."""
        lib_source = template_dir / "_lib"
        if lib_source.exists() and lib_source.is_dir():
            lib_target = output_dir / "_lib"
            lib_target.mkdir(parents=True, exist_ok=True)
            for rego_file in lib_source.glob("*.rego"):
                shutil.copy(rego_file, lib_target / rego_file.name)
                logger.info(f"Copied shared library: {lib_target / rego_file.name}")

    def _parse_conftest_results(self, conftest_output: List[Dict]) -> Dict[str, List]:
        """Parse Conftest JSON output into grouped policy results."""
        grouped = {}

        for file_result in conftest_output:
            filename = file_result.get('filename', 'unknown')

            # Process failures
            for failure in file_result.get('failures', []):
                policy_name = self._extract_policy_name_from_conftest(failure)
                if policy_name not in grouped:
                    grouped[policy_name] = []
                grouped[policy_name].append({
                    'status': 'fail',
                    'message': failure.get('msg', ''),
                    'resource_id': self._extract_resource_from_message(failure.get('msg', '')),
                    'resource_type': 'terraform_resource',
                    'filename': filename,
                    'metadata': failure.get('metadata', {}),
                })

            # Process warnings
            for warning in file_result.get('warnings', []):
                policy_name = self._extract_policy_name_from_conftest(warning)
                if policy_name not in grouped:
                    grouped[policy_name] = []
                grouped[policy_name].append({
                    'status': 'warn',
                    'message': warning.get('msg', ''),
                    'resource_id': self._extract_resource_from_message(warning.get('msg', '')),
                    'resource_type': 'terraform_resource',
                    'filename': filename,
                    'metadata': warning.get('metadata', {}),
                })

            # Process successes
            for success in file_result.get('successes', []):
                policy_name = self._extract_policy_name_from_conftest(success)
                if policy_name not in grouped:
                    grouped[policy_name] = []
                grouped[policy_name].append({
                    'status': 'pass',
                    'message': success.get('msg', 'Policy passed'),
                    'resource_id': 'all',
                    'resource_type': 'terraform_resource',
                    'filename': filename,
                    'metadata': success.get('metadata', {}),
                })

        return grouped

    def _parse_opa_eval_results(self, opa_output: Dict) -> Dict[str, List]:
        """Parse OPA eval JSON output into grouped policy results."""
        grouped = {}

        for result in opa_output.get('result', []):
            for expr in result.get('expressions', []):
                value = expr.get('value', {})
                text = expr.get('text', '')

                # Extract policy name from expression text (e.g., "data.ksi.cna01.aws")
                policy_name = text.replace('data.', '').replace('.', '-')

                if isinstance(value, dict):
                    # Handle deny/warn/pass rule results
                    for rule_type in ['deny', 'warn', 'violation']:
                        for msg in value.get(rule_type, []):
                            if policy_name not in grouped:
                                grouped[policy_name] = []
                            grouped[policy_name].append({
                                'status': 'fail' if rule_type in ['deny', 'violation'] else 'warn',
                                'message': msg if isinstance(msg, str) else str(msg),
                                'resource_id': self._extract_resource_from_message(str(msg)),
                                'resource_type': 'cloud_resource',
                            })

                    for msg in value.get('pass', []):
                        if policy_name not in grouped:
                            grouped[policy_name] = []
                        grouped[policy_name].append({
                            'status': 'pass',
                            'message': msg if isinstance(msg, str) else str(msg),
                            'resource_id': self._extract_resource_from_message(str(msg)),
                            'resource_type': 'cloud_resource',
                        })

        return grouped

    def _group_results_by_policy(self, results: List[Dict]) -> Dict[str, List]:
        """Group pre-normalized results by policy name."""
        grouped = {}
        for result in results:
            policy_name = result.get('policy', result.get('rule', 'unknown'))
            if policy_name not in grouped:
                grouped[policy_name] = []
            grouped[policy_name].append(result)
        return grouped

    def _extract_policy_name_from_conftest(self, result: Dict) -> str:
        """Extract policy/rule name from Conftest result."""
        metadata = result.get('metadata', {})
        # Try different metadata fields that might contain the rule name
        return (
            metadata.get('rule', '') or
            metadata.get('policy', '') or
            metadata.get('package', '') or
            'unknown'
        )

    def _extract_status(self, result: Dict) -> str:
        """Extract status from result dict."""
        status = result.get('status', '')
        if status:
            return status
        # Infer from presence of failures
        if result.get('failures') or result.get('fail'):
            return 'fail'
        if result.get('success', True) and not result.get('failures'):
            return 'pass'
        return 'fail'

    def _extract_resource_id(self, result: Dict) -> str:
        """Extract resource identifier from result."""
        return (
            result.get('resource_id') or
            result.get('address') or
            result.get('name') or
            result.get('id') or
            'unknown'
        )

    def _extract_message(self, result: Dict) -> str:
        """Extract failure/success message from result."""
        if 'message' in result:
            return result['message']
        if 'msg' in result:
            return result['msg']
        if 'failures' in result and result['failures']:
            return '; '.join([
                f.get('msg', str(f)) if isinstance(f, dict) else str(f)
                for f in result['failures']
            ])
        return 'No details available'

    def _extract_resource_from_message(self, msg: str) -> str:
        """Extract resource address from OPA/Conftest message.

        Messages typically contain resource addresses like:
        - 'aws_security_group.example'
        - "resource 'aws_s3_bucket.data' ..."
        """
        # Try to find Terraform resource addresses
        patterns = [
            r"'([a-z_]+\.[a-zA-Z0-9_-]+)'",  # 'aws_security_group.example'
            r'"([a-z_]+\.[a-zA-Z0-9_-]+)"',  # "aws_security_group.example"
            r'resource\s+([a-z_]+\.[a-zA-Z0-9_-]+)',  # resource aws_security_group.example
        ]
        for pattern in patterns:
            match = re.search(pattern, msg)
            if match:
                return match.group(1)
        return 'unknown'
