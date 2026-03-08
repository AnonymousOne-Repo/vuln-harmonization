# vuln-harmonization

A research-oriented toolkit for measuring and integrating multi-source vulnerability data across heterogeneous databases.

## Overview

Public vulnerability databases serve as critical infrastructure for vulnerability analysis; however, quality issues such as incomplete entries, conflicting or erroneous fields remain a challenge. Researchers and maintainers face significant difficulties in selecting databases and integrating data from multiple sources. The lack of systematic measurement studies leads to source selection relying on convention rather than comparative evaluation, while cross-database integration is hindered by the inconsistent nature of vulnerability information across sources.

This repository provides tools and methodologies for:
- **Cross-database measurement** of completeness, consistency, and accuracy across 16 vulnerability databases
- **Field schema standardization** using a unified 24-field schema with LLM-based extraction
- **Missing field completion** through structured prompts and multi-source integration
- **Comparative analysis** via field-level visualizations and statistical metrics

## Key Findings

Our measurement study reveals three integration challenges:

1. **Uneven coverage and richness**: General databases cover around 70% of vulnerabilities but provide limited analytical fields, while ecosystem databases contribute 29% non-CVE records and richer details that remain largely missing across sources.

2. **Low cross-database consistency**: Over 70% of database pairs show weak agreement and substantial divergence in weakness, severity, and affected component annotations, particularly due to heterogeneous classification and version reporting practices, while descriptions vary in contextual richness.

3. **Variable accuracy by field**: While Weakness and Severity exceed 80%, Affected remains lowest at 62.06%, with wide variation across databases. Different fields benefit from different integration strategies, indicating that effective integration requires field-aware design rather than uniform aggregation.

## Repository Structure

```
vuln-harmonization/
├── FieldStandardization/                   # Field extraction and standardization across 16 databases
│   ├── field_map_more.py        # Field mapping and transformation logic
│   ├── schema_template.py       # Unified 24-field schema definitions
│   ├── stage1_definitions.py    # Stage 1: Field presence detection
│   ├── stage2_schemas.py        # Stage 2: Detailed field extraction schemas
│   ├── graph_CVE.pdf            # Completeness visualization for CVE
│   ├── graph_NVD.pdf            # Completeness visualization for NVD
│   ├── graph_RustSec.pdf        # Completeness visualization for RustSec
│   ├── graph_cert.pdf           # Completeness visualization for CERT
│   ├── graph_curl.pdf           # Completeness visualization for cURL
│   ├── graph_debian.pdf         # Completeness visualization for Debian
│   ├── graph_edb.pdf            # Completeness visualization for ExploitDB
│   ├── graph_githubAdvisory.pdf # Completeness visualization for GitHub Advisory
│   ├── graph_gitlab.pdf         # Completeness visualization for GitLab
│   ├── graph_hunter.pdf         # Completeness visualization for CVE-Hunter
│   ├── graph_ibm_xforce.pdf     # Completeness visualization for IBM X-Force
│   ├── graph_mend_io.pdf        # Completeness visualization for Mend.io
│   ├── graph_osv.pdf            # Completeness visualization for OSV
│   ├── graph_redhat.pdf         # Completeness visualization for Red Hat
│   ├── graph_snyk.pdf           # Completeness visualization for Snyk
│   └── graph_ubuntu.pdf         # Completeness visualization for Ubuntu
│
├── FieldCompletion/             # LLM-based field completion
│   ├── templates/               # Prompt templates for missing fields
│   │   ├── extract_core_info.txt        # Core field extraction prompt
│   │   ├── output_format.txt            # JSON output format specification
│   │   └── summarize_status_info.txt    # Status field summarization prompt
│   └── utils/                   # Utility scripts
│       ├── input_builder.py             # Input construction for LLM prompts
│       ├── build_prompt                 # Prompt assembly utilities
│       └── field_completion_more.py     # Field completion orchestration
│
├── schema.txt                   # Unified field schema (24 fields)
└── README.md                    # This file
```

## Unified Field Schema

Our schema standardizes 24 fields across heterogeneous vulnerability databases:

### Core Fields (8)
- **Identification**: `id`, `aliases`, `related`
- **Source**: `source` (provider, reporter, category)
- **Description**: `title`, `description` (multi-language support)
- **Temporal**: `published`, `modified`, `withdrawn`, `timeline`

### Classification & Severity (3)
- **Weakness**: `weaknesses` (CWE, OWASP, RustSec categories)
- **Severity**: `severity` (CVSS 2.0/3.0/3.1/4.0, vendor-specific ratings)
- **Impact**: `impacts` (CAPEC-linked impact descriptions)

### Affected Components (2)
- **Affected**: `affected` (vendor, product, ecosystem, versions, CPE, PURL)
- **CPE Configurations**: `cpe_configurations` (nested matching logic)

### Exploitation & Remediation (3)
- **Exploitation**: `exploitation` (exploits, EPSS scores)
- **Remediation**: `remediation` (solutions, workarounds, fixed versions)
- **References**: `references`, `primary_urls`

### Metadata (8)
- **Status**: `vuln_status`
- **Credits**: `acknowledgements`
- **Vendor Input**: `vendor_comments`
- **Organization**: `tags`, `copyrights`

**Full schema**: See [`schema.txt`](schema.txt) for complete JSON schema with sub-field structures.

## Supported Databases (16)

| Category | Databases |
|----------|-----------|
| **Official** | CVE, NVD |
| **General** | OSV, Vulners |
| **Ecosystem** | RustSec, npm Advisory, PyPI Advisory, Maven Central |
| **Vendor** | Red Hat, Ubuntu, Debian, Mend.io, Snyk |
| **Security** | GitHub Advisory, GitLab, CERT, IBM X-Force, CVE-Hunter |
| **Exploit** | ExploitDB |
| **Application** | cURL |


## Usage Examples

### Field Standardization
```python
from databases.field_map_more import FieldMapper
from databases.schema_template import UNIFIED_SCHEMA

# Load raw vulnerability data
raw_data = load_database("nvd_data.json")

# Map to unified schema
mapper = FieldMapper(UNIFIED_SCHEMA)
standardized_data = mapper.transform(raw_data, source="NVD")
```

### Field Completion
```python
from FieldCompletion.utils.field_completion_more import complete_missing_fields

# Complete missing Weakness field using LLM
incomplete_record = {
    "id": "CVE-2024-12345",
    "description": {"details": [{"value": "XSS vulnerability in..."}]},
    "weaknesses": []  # Missing
}

completed_record = complete_missing_fields(
    record=incomplete_record,
    target_fields=["weaknesses"],
    model="claude-3-5-sonnet-20241022"
)
```
