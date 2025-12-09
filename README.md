# Compliance Pipeline

A **compliance-as-code** framework that automates security policy enforcement and compliance assessment for both **Kubernetes** (via Kyverno) and **Cloud Infrastructure** (via OPA/Terraform).

Implements the **Compliance-to-Policy (C2P)** and **Policy-to-Compliance (P2C)** workflow using OSCAL as the standard compliance data format.

## Features

| Target | Policy Engine | Use Case |
|--------|---------------|----------|
| Kubernetes | Kyverno | Runtime policy enforcement for K8s resources |
| Terraform/Cloud | OPA/Conftest | Pre-deployment IaC validation for AWS/Azure/GCP |

## Supported Compliance Frameworks

- **FedRAMP 20x Key Security Indicators (KSIs)** - for cloud infrastructure
- **NIST SP 800-53** - for Kubernetes workloads

---

## Quick Start: OPA/Terraform (FedRAMP 20x)

### Prerequisites

```bash
pip install -e .
# Install OPA CLI
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x /usr/local/bin/opa
# Install Conftest
brew install conftest  # or download from https://github.com/open-policy-agent/conftest/releases
```

### 1. Generate OSCAL from CSV

```bash
python3 -m c2p tools csv-to-oscal-cd \
  --title "FedRAMP 20x" \
  --csv ./data/component-definition-opa.csv \
  -o ./pipeline
```

### 2. Generate OPA Policies

```bash
python3 -m compliance_pipeline.c2p_opa \
  -c ./pipeline/component-definition.json \
  -o ./pipeline/opa-policies \
  --cloud-provider aws
```

### 3. Validate Terraform Plan

```bash
# Generate Terraform plan
cd terraform/aws/non-compliant
terraform init && terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run Conftest
conftest test tfplan.json --policy ../../../pipeline/opa-policies --all-namespaces
```

### 4. Generate OSCAL Assessment Results

```bash
conftest test tfplan.json --policy ./pipeline/opa-policies --output json > ./pipeline/conftest-results.json

python3 -m compliance_pipeline.p2c_opa \
  -c ./pipeline/component-definition.json \
  --conftest-results ./pipeline/conftest-results.json \
  -o ./pipeline/assessment-results.json

python3 -m c2p tools viewer \
  -ar ./pipeline/assessment-results.json \
  -cdef ./pipeline/component-definition.json \
  -o ./pipeline/assessment-results.md
```

### FedRAMP 20x KSIs Implemented

| KSI | Description | Policy File |
|-----|-------------|-------------|
| KSI-CNA-01 | Restrict Network Traffic | `aws/ksi-cna-01/restrict_network_traffic.rego` |
| KSI-SVC-02 | Network Encryption (TLS) | `aws/ksi-svc-02/network_encryption.rego` |
| KSI-IAM-01 | Phishing-Resistant MFA | `aws/ksi-iam-01/phishing_resistant_mfa.rego` |
| KSI-SVC-06 | Secrets Management | `aws/ksi-svc-06/secrets_management.rego` |

### GitHub Actions (CI/CD)

The `c2p-opa.yml` workflow automates:
1. CSV → OSCAL conversion
2. OPA policy generation
3. Terraform plan validation via Conftest
4. OSCAL assessment result generation
5. PR creation with compliance summary

```bash
# Trigger manually
gh workflow run c2p-opa.yml -f cloud_provider=aws -f terraform_dir=terraform/aws/non-compliant
```

---

## Quick Start: Kyverno/Kubernetes

### Prerequisites

```bash
kubectl create namespace kyverno
kubectl create namespace ingress-nginx

helm install kyverno kyverno/kyverno --namespace kyverno
helm install nginx ingress-nginx/ingress-nginx --namespace ingress-nginx
```

### Deploy Test Applications

```bash
kubectl apply -f ./deployment/good-application.yaml
kubectl apply -f ./deployment/bad-application.yaml
```

### Run C2P Workflow

```bash
# CSV to OSCAL
python3 -m c2p tools csv-to-oscal-cd \
  --title "Component Definition" \
  --csv ./data/component-definition.csv \
  -o ./pipeline

# Generate Kyverno Policies
python3 -m compliance_pipeline.c2p \
  -c ./pipeline/component-definition.json \
  -o ./pipeline/policy

# Apply Policies
find ./pipeline/policy -name '*.yaml' -exec kubectl apply -f {} \;

# Collect Policy Reports
kubectl get policyreports.wgpolicyk8s.io -o yaml > ./pipeline/policyreports.wgpolicyk8s.io.yaml

# Generate Assessment Results
python3 -m compliance_pipeline.p2c \
  -c ./pipeline/component-definition.json \
  -polr ./pipeline/policyreports.wgpolicyk8s.io.yaml > ./pipeline/assessment-results.json
```

### GitHub Actions

Use the `c2p.yml` workflow for Kubernetes compliance automation with self-hosted runners.

---

## Architecture

```
                    OSCAL Layer
┌─────────────────────────────────────────────────────────┐
│  component-definition.csv  →  component-definition.json │
│     (Control mappings)           (OSCAL format)         │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                              ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│   C2P (Kyverno)     │      │      C2P (OPA)              │
│   Kubernetes YAML   │      │      Rego Policies          │
└──────────┬──────────┘      └──────────────┬──────────────┘
           │                                 │
           ▼                                 ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│  Kyverno Engine     │      │  Conftest / OPA             │
│  (Runtime)          │      │  (Pre-deployment)           │
└──────────┬──────────┘      └──────────────┬──────────────┘
           │                                 │
           ▼                                 ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│  PolicyReport       │      │  Conftest JSON Results      │
└──────────┬──────────┘      └──────────────┬──────────────┘
           │                                 │
           └──────────────┬──────────────────┘
                          ▼
              ┌───────────────────────┐
              │   P2C Transformation  │
              │   → OSCAL Assessment  │
              └───────────────────────┘
```

---

## Project Structure

```
compliance-pipeline/
├── compliance_pipeline/
│   ├── c2p.py                    # Kyverno C2P orchestration
│   ├── c2p_opa.py                # OPA C2P orchestration
│   ├── p2c.py                    # Kyverno P2C orchestration
│   ├── p2c_opa.py                # OPA P2C orchestration
│   ├── c2p_plugin/
│   │   ├── kyverno.py            # Kyverno plugin
│   │   ├── opa.py                # OPA plugin
│   │   ├── policy-resources/     # Kyverno templates
│   │   └── opa-policy-resources/ # Rego templates
│   │       ├── _lib/             # Shared Rego libraries
│   │       └── aws/              # AWS-specific policies
│   └── collectors/
│       └── conftest_runner.py    # Conftest wrapper
├── data/
│   ├── component-definition.csv      # Kyverno control mappings
│   └── component-definition-opa.csv  # OPA/FedRAMP 20x mappings
├── terraform/
│   └── aws/
│       ├── compliant/            # Passing example
│       └── non-compliant/        # Failing example
├── deployment/                   # K8s test manifests
└── .github/workflows/
    ├── c2p.yml                   # Kyverno workflow
    └── c2p-opa.yml               # OPA workflow
```

---

## Configuration

### Adding New OPA Policies

1. Create a new policy directory:
   ```
   compliance_pipeline/c2p_plugin/opa-policy-resources/aws/ksi-xxx-yy/
   ```

2. Add Rego policy with Jinja2 parameters:
   ```rego
   package ksi.xxxyy.aws

   my_param := "{{ my_param | default('default_value') }}"

   deny[msg] {
       # policy logic
   }
   ```

3. Add mapping to `data/component-definition-opa.csv`

4. Regenerate policies:
   ```bash
   python3 -m compliance_pipeline.c2p_opa -c ./pipeline/component-definition.json -o ./pipeline/opa-policies
   ```

### Customizing Parameters

Edit `data/component-definition-opa.csv` to customize:
- `allowed_ingress_cidrs` - Allowed network CIDR blocks
- `minimum_tls_version` - Minimum TLS version (default: TLSv1.2)
- `require_rotation` - Require secret rotation (default: true)
- `max_rotation_days` - Maximum days between rotations (default: 90)

---

## References

- [FedRAMP 20x Core Concepts](https://www.fedramp.gov/20x/core-concepts/)
- [OSCAL (Open Security Controls Assessment Language)](https://pages.nist.gov/OSCAL/)
- [Compliance-to-Policy (C2P) Framework](https://github.com/oscal-compass/compliance-to-policy)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Conftest](https://www.conftest.dev/)
- [Kyverno](https://kyverno.io/)
