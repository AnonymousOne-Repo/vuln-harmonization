"""
Vulnerability Data Extractor and Mapper
Extracts data from 13 vulnerability databases and maps to unified 24-field schema
"""

import json
from turtledemo.sorting_animate import ssort

import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional, List
import copy
from datetime import datetime

from nltk.inference.discourse import drt_discourse_demo
from urllib3.util import wait_for_write

# Import schema templates
from schema_template import get_empty_schema, ALL_FIELD_NAMES
from stage1_definitions import STAGE1_FIELD_DEFINITIONS
from stage2_schemas import STAGE2_FIELD_SCHEMAS


class VulnerabilityDataMapper:
    """Maps vulnerability data from various sources to unified 24-field schema"""

    def __init__(self):
        self.data_sources = {
            'CVE': {'file': 'dataset/cve_org_msg.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'NVD': {'file': 'dataset/nvd_data.csv', 'type': 'csv', 'id_col': 'nvd_id'},
            'GitHub': {'file': 'dataset/ghsa_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Mend.io': {'file': 'dataset/mend_io_craw.json', 'type': 'json_list'},
            'OSV': {'file': 'dataset/osv_data.csv', 'type': 'csv', 'id_col': 'osv_id'},
            'IBM': {'file': 'dataset/ibm_xforce_cve_20240619.json', 'type': 'json_list'},
            'Debian': {'file': 'dataset/debian_json.json', 'type': 'json_nested'},
            # 'EDB': {'file': 'dataset/edb.json', 'type': 'json_nested'},
            'EDB': {'file': 'dataset/edb_files_exploits.csv', 'type': 'csv', 'id_col': 'codes'},  # ← 改为csv，id_col指向codes
            'RedHat': {'file': 'dataset/redhat_cve.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Snyk': {'file': 'dataset/snyk_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'GitLab': {'file': 'dataset/gitlab_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'RustSec': {'file': 'dataset/rustsec_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Cert': {'file': 'dataset/cert.json', 'type': 'json_list'},
            # === 新增三个数据库 ===
            'Curl': {'file': 'dataset/more/curl_vul.json', 'type': 'json_list'},
            'Hunter': {'file': 'dataset/more/dataFromHunter.json', 'type': 'json_nested'},
            'Ubuntu': {'file': 'dataset/more/ubuntu_cve.csv', 'type': 'csv', 'id_col': 'cve_id'}
        }
        self.data_sources0 = {
            'CVE': {'file': './multiDBs/dataset/cve_org_msg.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'NVD': {'file': './multiDBs/dataset/nvd_data.csv', 'type': 'csv', 'id_col': 'nvd_id'},
            'GitHub': {'file': './multiDBs/dataset/ghsa_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Mend.io': {'file': './multiDBs/dataset/mend_io_craw.json', 'type': 'json_list'},
            'OSV': {'file': './multiDBs/dataset/osv_data.csv', 'type': 'csv', 'id_col': 'osv_id'},
            'IBM': {'file': './multiDBs/dataset/ibm_xforce_cve_20240619.json', 'type': 'json_list'},
            'Debian': {'file': './multiDBs/dataset/debian_json.json', 'type': 'json_nested'},
            # 'EDB': {'file': 'dataset/edb.json', 'type': 'json_nested'},
            'EDB': {'file': './multiDBs/dataset/edb_files_exploits.csv', 'type': 'csv', 'id_col': 'codes'},
            # ← 改为csv，id_col指向codes
            'RedHat': {'file': './multiDBs/dataset/redhat_cve.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Snyk': {'file': './multiDBs/dataset/snyk_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'GitLab': {'file': './multiDBs/dataset/gitlab_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'RustSec': {'file': './multiDBs/dataset/rustsec_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Cert': {'file': './multiDBs/dataset/cert.json', 'type': 'json_list'},
            # === 新增三个数据库 ===
            'Curl': {'file': './multiDBs/dataset/more/curl_vul.json', 'type': 'json_list'},
            'Hunter': {'file': './multiDBs/dataset/more/dataFromHunter.json', 'type': 'json_nested'},
            'Ubuntu': {'file': './multiDBs/dataset/more/ubuntu_cve.csv', 'type': 'csv', 'id_col': 'cve_id'}
        }
        self.data_sources_more = {
            'CVE': {'file': './dataset/cve_org_msg.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'NVD': {'file': './dataset/nvd_data.csv', 'type': 'csv', 'id_col': 'nvd_id'},
            'GitHub': {'file': './dataset/ghsa_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Mend.io': {'file': './dataset/mend_io_craw.json', 'type': 'json_list'},
            'OSV': {'file': './dataset/osv_data.csv', 'type': 'csv', 'id_col': 'osv_id'},
            'IBM': {'file': './dataset/ibm_xforce_cve_20240619.json', 'type': 'json_list'},
            'Debian': {'file': './dataset/debian_json.json', 'type': 'json_nested'},
            # 'EDB': {'file': 'dataset/edb.json', 'type': 'json_nested'},
            'EDB': {'file': './dataset/edb_files_exploits.csv', 'type': 'csv', 'id_col': 'codes'},
            # ← 改为csv，id_col指向codes
            'RedHat': {'file': './dataset/redhat_cve.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Snyk': {'file': './dataset/snyk_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'GitLab': {'file': './dataset/gitlab_vulnerabilities.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'RustSec': {'file': './dataset/rustsec_advisories.csv', 'type': 'csv', 'id_col': 'cve_id'},
            'Cert': {'file': './dataset/cert.json', 'type': 'json_list'},
            # === 新增三个数据库 ===
            'Curl': {'file': './dataset/more/curl_vul.json', 'type': 'json_list'},
            'Hunter': {'file': './dataset/more/dataFromHunter.json', 'type': 'json_nested'},
            'Ubuntu': {'file': './dataset/more/ubuntu_cve.csv', 'type': 'csv', 'id_col': 'cve_id'}
        }
        self.data_sources_new = {
            # === 新增三个数据库 ===
            'Curl': {'file': './multiDBs/dataset/more/curl_vul.json', 'type': 'json_list'},
            'Hunter': {'file': './multiDBs/dataset/more/dataFromHunter.json', 'type': 'json_nested'},
            'Ubuntu': {'file': './multiDBs/dataset/more/ubuntu_cve.csv', 'type': 'csv', 'id_col': 'cve_id'}
        }

    def extract_cve_data(self, cve_id: str, source_name: str) -> Optional[Dict[str, Any]]:
        """Extract raw data for a CVE from specific source"""
        source_info = self.data_sources_more.get(source_name)
        if not source_info:
            return None

        file_path = source_info['file']
        file_type = source_info['type']

        try:
            if file_type == 'csv':
                return self._extract_from_csv(file_path, cve_id, source_info.get('id_col', 'cve_id'))
            elif file_type == 'json_list':
                return self._extract_from_json_list(file_path, cve_id)
            elif file_type == 'json_nested':
                return self._extract_from_json_nested(file_path, cve_id)
        except Exception as e:
            print(f"Error extracting from {source_name}: {e}")
            return None

    def _extract_from_csv(self, file_path: str, cve_id: str, id_col: str) -> Optional[Dict]:
        """Extract from CSV file"""
        df = pd.read_csv(file_path)
        # 特殊处理：如果id_col是'codes'（用于EDB），需要在codes列中搜索CVE ID
        if id_col == 'codes':
            if 'codes' in df.columns:
                # 在codes列中搜索包含CVE ID的行
                # codes格式: "CVE-2009-4265;OSVDB-60681"
                result = df[df['codes'].astype(str).str.contains(cve_id, case=False, na=False, regex=False)]
                if not result.empty:
                    row = result.iloc[0]
                    return row.to_dict()
            return None


        result = df[df[id_col] == cve_id]
        if result.empty:
            return None

        row = result.iloc[0]
        data = row.to_dict()

        # Parse JSON columns if present
        for col in data:
            if isinstance(data[col], str) and (data[col].startswith('{') or data[col].startswith('[')):
                try:
                    data[col] = json.loads(data[col])
                except:
                    pass

        return data

    def _extract_from_json_list(self, file_path: str, cve_id: str) -> Optional[Dict]:
        """Extract from JSON list file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)


        if 'curl_vul' in file_path:
            # Hunter格式: {uuid: {vulnerability_data}, uuid2: {...}}
            for item in data:
                # Check various CVE ID fields
                if (item.get("id").split('CURL-')[-1] == cve_id or
                        cve_id in item.get("aliases", [])):
                    return item
            return None
        for item in data:
            # Check various CVE ID fields
            if (item.get('cve_id') == cve_id or
                    item.get('vul_id') == cve_id or
                    cve_id in item.get('stdcode', []) or
                    cve_id in item.get('cveids', [])):
                return item

        return None

    def _extract_from_json_nested(self, file_path: str, cve_id: str) -> Optional[Dict]:
        """Extract from nested JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # For Hunter database - 特殊处理
        if 'Hunter' in file_path or 'dataFromHunter' in file_path:
            # Hunter格式: {uuid: {vulnerability_data}, uuid2: {...}}
            for vuln_id, vuln_data in data.items():
                if isinstance(vuln_data, dict):
                    # Check if CVE matches
                    if vuln_data.get('cve') == cve_id:
                        vuln_data['id'] = vuln_id  # 添加UUID作为ID
                        return vuln_data
            return None
        for package_name, package_data in data.items():
            if isinstance(package_data, dict) and cve_id in package_data:
                result = package_data[cve_id].copy()
                result['package'] = package_name
                result['cve_id'] = cve_id
                return result

        return None

    def map_to_unified_schema(self, raw_data: Dict, source_name: str) -> Dict[str, Any]:
        """Map raw data from specific source to unified 24-field schema"""
        unified = get_empty_schema()

        # Source-specific mapping logic
        if source_name == 'CVE':
            unified = self._map_cve(raw_data, unified)
        elif source_name == 'NVD':
            unified = self._map_nvd(raw_data, unified)
        elif source_name == 'GitHub':
            unified = self._map_github(raw_data, unified)
        elif source_name == 'Mend.io':
            unified = self._map_mend(raw_data, unified)
        elif source_name == 'OSV':
            unified = self._map_osv(raw_data, unified)
        elif source_name == 'IBM':
            unified = self._map_ibm(raw_data, unified)
        elif source_name == 'Debian':
            unified = self._map_debian(raw_data, unified)
        elif source_name == 'EDB':
            unified = self._map_edb(raw_data, unified)
        elif source_name == 'RedHat':
            unified = self._map_redhat(raw_data, unified)
        elif source_name == 'Snyk':
            unified = self._map_snyk(raw_data, unified)
        elif source_name == 'GitLab':
            unified = self._map_gitlab(raw_data, unified)
        elif source_name == 'RustSec':
            unified = self._map_rustsec(raw_data, unified)
        elif source_name == 'Cert':
            unified = self._map_cert(raw_data, unified)
        # 在现有的 elif source_name == 'Cert': 之后添加：
        elif source_name == 'Curl':
            unified = self._map_curl(raw_data, unified)
        elif source_name == 'Hunter':
            unified = self._map_hunter(raw_data, unified)
        elif source_name == 'Ubuntu':
            unified = self._map_ubuntu(raw_data, unified)

        return unified

    # Source-specific mapping methods

    def _map_cve(self, data: Dict, schema: Dict) -> Dict:
        """Map CVE data to unified schema"""
        if 'cve_msg' in data:
            cve_data = json.loads(data['cve_msg']) if isinstance(data['cve_msg'], str) else data['cve_msg']
        else:
            cve_data = data

        cna = cve_data.get('containers', {}).get('cna', {})

        # ID
        schema['id'] = cve_data.get('cveMetadata', {}).get('cveId') or data.get('cve_id')

        # Source
        schema['source'] = {
            'provider': 'CVE',
            'reporter': cna.get('providerMetadata', {}).get('shortName'),
            'category': 'cve-record'
        }

        # Title - 直接从CNA中提取
        schema['title'] = cna.get('title')

        # Description
        descriptions = cna.get('descriptions', [])
        schema['description'] = [
            {
                'lang': desc.get('lang', 'en'),
                'value': desc.get('value', ''),
                'format': 'text',
                'media': desc.get('supportingMedia', [])
            }
            for desc in descriptions
        ]

        # 如果没有title，从description生成
        if not schema['title'] and descriptions:
            desc_value = descriptions[0].get('value', '')
            schema['title'] = desc_value[:256] if len(desc_value) > 256 else desc_value

        # Timeline - CVE 5.0格式包含timeline字段
        timeline = cna.get('timeline', [])
        schema['timeline'] = [
            {
                'time': self._normalize_timestamp(event.get('time')),
                'description': event.get('value', ''),
                'source': 'CVE',
                'lang': event.get('lang', 'en')
            }
            for event in timeline
        ]

        # Timestamps
        schema['published'] = self._normalize_timestamp(
            cve_data.get('cveMetadata', {}).get('datePublished') or
            cna.get('datePublic')
        )
        schema['modified'] = self._normalize_timestamp(
            cve_data.get('cveMetadata', {}).get('dateUpdated')
        )

        # Withdrawn (for rejected CVEs)
        cve_state = cve_data.get('cveMetadata', {}).get('state', '').lower()
        if cve_state == 'rejected':
            schema['withdrawn'] = self._normalize_timestamp(
                cve_data.get('cveMetadata', {}).get('dateRejected')
            )
            schema['vuln_status'] = 'rejected'
        else:
            schema['vuln_status'] = 'published'

        # Weaknesses
        problem_types = cna.get('problemTypes', [])
        for pt in problem_types:
            for desc in pt.get('descriptions', []):
                cwe_id = desc.get('cweId')
                if cwe_id:
                    schema['weaknesses'].append({
                        'id': cwe_id,
                        'taxonomy': desc.get('type', 'CWE'),
                        'name': None,
                        'description': desc.get('description'),
                        'source': 'CVE'
                    })
                elif desc.get('description'):
                    # 无CWE ID的文本描述
                    schema['weaknesses'].append({
                        'id': None,
                        'taxonomy': 'Text',
                        'name': None,
                        'description': desc.get('description'),
                        'source': 'CVE'
                    })

        # Severity (metrics)
        metrics = cna.get('metrics', [])
        for metric in metrics:
            # CVSS v3.1
            if 'cvssV3_1' in metric:
                cvss = metric['cvssV3_1']
                schema['severity'].append({
                    'source': 'CVE',
                    'scheme': 'CVSS:3.1',
                    'score': cvss.get('baseScore'),
                    'vector': cvss.get('vectorString'),
                    'rating': cvss.get('baseSeverity')
                })
            # CVSS v3.0
            elif 'cvssV3_0' in metric:
                cvss = metric['cvssV3_0']
                schema['severity'].append({
                    'source': 'CVE',
                    'scheme': 'CVSS:3.0',
                    'score': cvss.get('baseScore'),
                    'vector': cvss.get('vectorString'),
                    'rating': cvss.get('baseSeverity')
                })
            # CVSS v2.0
            elif 'cvssV2_0' in metric:
                cvss = metric['cvssV2_0']
                schema['severity'].append({
                    'source': 'CVE',
                    'scheme': 'CVSS:2.0',
                    'score': cvss.get('baseScore'),
                    'vector': cvss.get('vectorString'),
                    'rating': None
                })
            # Format-based CVSS (newer format)
            elif metric.get('format') == 'CVSS':
                for cvss_key in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                    if cvss_key in metric:
                        cvss = metric[cvss_key]
                        version = cvss.get('version', '3.1')
                        schema['severity'].append({
                            'source': 'CVE',
                            'scheme': f"CVSS:{version}",
                            'score': cvss.get('baseScore'),
                            'vector': cvss.get('vectorString'),
                            'rating': cvss.get('baseSeverity')
                        })

        # Impacts - 从impacts字段提取
        impacts = cna.get('impacts', [])
        for impact in impacts:
            capec_id = impact.get('capecId')
            descriptions = impact.get('descriptions', [])

            for desc in descriptions:
                schema['impacts'].append({
                    'source': 'CVE',
                    'lang': desc.get('lang', 'en'),
                    'text': desc.get('value', ''),
                    'capec_id': capec_id
                })

        # Exploitation - exploits字段
        exploits = cna.get('exploits', [])
        for exploit in exploits:
            schema['exploitation']['exploits'].append({
                'source': 'CVE',
                'lang': exploit.get('lang', 'en'),
                'text': exploit.get('value', ''),
                'links': []
            })

        # References
        references = cna.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': ref.get('name'),
                'tags': ref.get('tags', [])
            }
            for ref in references
        ]

        # Affected
        affected_list = cna.get('affected', [])
        for affected_item in affected_list:
            # Extract version information
            versions_list = []
            version_ranges = []

            versions = affected_item.get('versions', [])
            for v in versions:
                status = v.get('status', 'affected')
                version = v.get('version')

                # Check if it's a range
                if v.get('lessThan') or v.get('lessThanOrEqual'):
                    version_ranges.append({
                        'scheme': v.get('versionType', 'custom'),
                        'introduced': version,
                        'last_affected': v.get('lessThanOrEqual'),
                        'fixed': v.get('lessThan'),
                        'limit': None,
                        'status': status
                    })
                else:
                    versions_list.append(version)

            schema['affected'].append({
                'vendor': affected_item.get('vendor'),
                'product': affected_item.get('product'),
                'ecosystem': affected_item.get('packageName'),  # May indicate ecosystem
                'package': affected_item.get('packageName'),
                'status': affected_item.get('defaultStatus', 'affected'),
                'versions': versions_list,
                'version_range': version_ranges,
                'repo': affected_item.get('repo'),
                'cpe': None,
                'purl': affected_item.get('packageURL'),
                'os': [],
                'os_version': [],
                'arch': [],
                'platform': affected_item.get('platforms', []),
                'modules': affected_item.get('modules', []),
                'files': affected_item.get('programFiles', []),
                'functions': [r.get('name') for r in affected_item.get('programRoutines', [])]
            })

        # Remediation - solutions and workarounds
        solutions = cna.get('solutions', [])
        for solution in solutions:
            schema['remediation']['solutions'].append({
                'lang': solution.get('lang', 'en'),
                'value': solution.get('value', ''),
                'supportingMedia': solution.get('supportingMedia', [])
            })

        workarounds = cna.get('workarounds', [])
        for workaround in workarounds:
            schema['remediation']['workarounds'].append({
                'lang': workaround.get('lang', 'en'),
                'value': workaround.get('value', ''),
                'supportingMedia': workaround.get('supportingMedia', [])
            })

        # Credits/Acknowledgements
        credits = cna.get('credits', [])
        schema['acknowledgements'] = [
            {
                'name': credit.get('value'),
                'type': credit.get('type'),
                'contact': credit.get('contact', []) if isinstance(credit.get('contact'), list) else [],
                'lang': credit.get('lang'),
                'uuid': credit.get('user')
            }
            for credit in credits
        ]

        # Tags
        tags = cna.get('tags', [])
        for tag in tags:
            schema['tags'].append({
                'description': tag,
                'source': 'CVE'
            })

        return schema

    def _map_nvd(self, data: Dict, schema: Dict) -> Dict:
        """Map NVD data to unified schema"""
        if 'cve_msg' in data:
            nvd_data = json.loads(data['cve_msg']) if isinstance(data['cve_msg'], str) else data['cve_msg']
        else:
            nvd_data = data

        # ID
        schema['id'] = nvd_data.get('id') or data.get('nvd_id')

        # Source
        schema['source'] = {
            'provider': 'NVD',
            'reporter': nvd_data.get('sourceIdentifier'),
            'category': 'database-entry'
        }

        # Description
        descriptions = nvd_data.get('descriptions', [])
        schema['description'] = [
            {
                'lang': desc.get('lang', 'en'),
                'value': desc.get('value', ''),
                'format': 'text',
                'media': []
            }
            for desc in descriptions
        ]

        # if descriptions:
        #     schema['title'] = descriptions[0].get('value', '')[:256]
        schema['title'] = None

        # Timestamps
        schema['published'] = self._normalize_timestamp(nvd_data.get('published'))
        schema['modified'] = self._normalize_timestamp(nvd_data.get('lastModified'))

        # Status
        vuln_status = nvd_data.get('vulnStatus', '').lower()
        status_map = {
            'modified': 'modified',
            'analyzed': 'published',
            'rejected': 'rejected',
            'undergoing_analysis': 'analyzing'
        }
        schema['vuln_status'] = status_map.get(vuln_status, 'published')

        # Weaknesses
        weaknesses = nvd_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_value = desc.get('value', '')
                if cwe_value.startswith('CWE-'):
                    schema['weaknesses'].append({
                        'id': cwe_value,
                        'taxonomy': 'CWE',
                        'name': None,
                        'description': None,
                        'source': 'NVD'
                    })

        # Severity (CVSS metrics)
        metrics = nvd_data.get('metrics', {})
        for metric_version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric_version in metrics:
                for metric in metrics[metric_version]:
                    cvss_data = metric.get('cvssData', {})
                    version = cvss_data.get('version', '3.1')
                    schema['severity'].append({
                        'source': metric.get('source', 'NVD'),
                        'scheme': f"CVSS:{version}",
                        'score': cvss_data.get('baseScore'),
                        'vector': cvss_data.get('vectorString'),
                        'rating': cvss_data.get('baseSeverity') or metric.get('baseSeverity')
                    })


        # Impacts - evaluatorImpact字段
        evaluator_impact = nvd_data.get('evaluatorImpact')
        if evaluator_impact:
            schema['impacts'].append({
                'source': 'NVD',
                'lang': 'en',
                'text': evaluator_impact,
                'capec_id': None
            })

        # References
        references = nvd_data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': ref.get('source'),
                'tags': ref.get('tags', [])
            }
            for ref in references
        ]


        # CPE Configurations
        configurations = nvd_data.get('configurations', [])
        schema['cpe_configurations'] = [
            {
                'source': 'nvd',
                'operator': config.get('operator', 'OR'),
                'negate': config.get('negate', False),
                'nodes': self._extract_cpe_nodes(config.get('nodes', []))
            }
            for config in configurations
        ]

        # Affected - 从 CPE configurations 解析
        schema['affected'] = self._parse_affected_from_cpe(configurations)

        # Remediation - evaluatorSolution字段
        evaluator_solution = nvd_data.get('evaluatorSolution')
        if evaluator_solution:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': evaluator_solution,
                'supportingMedia': []
            })

        # Vendor Comments - vendorComments字段
        vendor_comments = nvd_data.get('vendorComments', [])
        for comment in vendor_comments:
            # evaluatorComment也可能存在
            schema['vendor_comments'].append({
                'source': comment.get('organization', 'NVD Evaluator'),
                'comment': comment.get('comment'),
                'time': self._normalize_timestamp(comment.get('lastModified'))
            })

        # 如果有evaluatorComment字段（独立于vendorComments）
        evaluator_comment = nvd_data.get('evaluatorComment')
        if evaluator_comment:
            schema['vendor_comments'].append({
                'source': 'NVD Evaluator',
                'comment': evaluator_comment,
                'time': None
            })

        # Tags - cveTags字段
        cve_tags = nvd_data.get('cveTags', [])
        for tag in cve_tags:
            schema['tags'].append({
                'description': tag,
                'source': 'NVD'
            })

        return schema

    def _parse_affected_from_cpe(self, configurations: List[Dict]) -> List[Dict]:
        """
        从 NVD CPE configurations 解析 affected 字段

        CPE 格式: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        示例: cpe:2.3:a:apache:tomcat:5.0.0:*:*:*:*:*:*:*

        Args:
            configurations: NVD configurations 列表

        Returns:
            affected 列表
        """
        affected_map = {}  # 用于去重和合并版本：(vendor, product) -> affected_entry

        for config in configurations:
            nodes = config.get('nodes', [])
            self._extract_affected_from_nodes(nodes, affected_map)

        return list(affected_map.values())

    def _extract_affected_from_nodes(self, nodes: List[Dict], affected_map: Dict):
        """
        递归提取 CPE nodes 中的 affected 信息

        Args:
            nodes: CPE nodes 列表
            affected_map: 用于收集和去重的字典
        """
        for node in nodes:
            # 处理当前节点的 cpeMatch
            cpe_matches = node.get('cpeMatch', [])

            for cpe_match in cpe_matches:
                if not cpe_match.get('vulnerable', True):
                    continue

                cpe_criteria = cpe_match.get('criteria', '')
                if not cpe_criteria:
                    continue

                # 解析 CPE 字符串
                cpe_parts = self._parse_cpe_string(cpe_criteria)
                if not cpe_parts:
                    continue

                vendor = cpe_parts.get('vendor')
                product = cpe_parts.get('product')
                version = cpe_parts.get('version')
                update = cpe_parts.get('update')

                # 跳过无效数据
                if not product or product == '*':
                    continue

                # 创建唯一键
                key = (vendor or 'unknown', product)

                # 推断版本方案
                ecosystem = self._infer_ecosystem_from_cpe(cpe_parts)
                version_scheme = self._infer_version_scheme(ecosystem, product)

                # 获取或创建 affected entry
                if key not in affected_map:
                    affected_map[key] = {
                        'vendor': vendor if vendor and vendor != '*' else None,
                        'product': product,
                        'ecosystem': ecosystem,
                        'package_type': 'upstream',
                        'versions': [],
                        'version_range': [],
                        'platform': [],
                        'distribution': None
                    }

                affected_entry = affected_map[key]

                # 处理版本信息
                # 1. 精确版本
                if version and version != '*':
                    full_version = version
                    if update and update != '*':
                        full_version = f"{version}-{update}"
                    if full_version not in affected_entry['versions']:
                        affected_entry['versions'].append(full_version)

                # 2. 版本范围 (从 versionStartIncluding, versionEndExcluding 等字段)
                has_range = any([
                    cpe_match.get('versionStartIncluding'),
                    cpe_match.get('versionStartExcluding'),
                    cpe_match.get('versionEndIncluding'),
                    cpe_match.get('versionEndExcluding')
                ])

                if has_range:
                    version_range_entry = {
                        'scheme': version_scheme,
                        'introduced': None,
                        'last_affected': None,
                        'fixed': None,
                        'limit': None,
                        'status': 'affected'
                    }

                    # 设置 introduced (开始版本)
                    if cpe_match.get('versionStartIncluding'):
                        version_range_entry['introduced'] = cpe_match['versionStartIncluding']
                    elif cpe_match.get('versionStartExcluding'):
                        # versionStartExcluding 表示不包含这个版本，我们记录在 limit 中
                        version_range_entry['limit'] = f"> {cpe_match['versionStartExcluding']}"
                        version_range_entry['introduced'] = cpe_match['versionStartExcluding']

                    # 设置 last_affected 或 fixed
                    if cpe_match.get('versionEndIncluding'):
                        # 包含这个版本，说明这是最后一个受影响的版本
                        version_range_entry['last_affected'] = cpe_match['versionEndIncluding']
                    elif cpe_match.get('versionEndExcluding'):
                        # 不包含这个版本，说明这是修复版本
                        version_range_entry['fixed'] = cpe_match['versionEndExcluding']

                    # 添加到 version_range 列表
                    affected_entry['version_range'].append(version_range_entry)

            # 递归处理子节点
            if 'children' in node:
                self._extract_affected_from_nodes(node['children'], affected_map)

    def _extract_affected_from_nodes(self, nodes: List[Dict], affected_map: Dict):
        """
        递归提取 CPE nodes 中的 affected 信息

        Args:
            nodes: CPE nodes 列表
            affected_map: 用于收集和去重的字典
        """
        for node in nodes:
            # 处理当前节点的 cpeMatch
            cpe_matches = node.get('cpeMatch', [])

            for cpe_match in cpe_matches:
                if not cpe_match.get('vulnerable', True):
                    continue

                cpe_criteria = cpe_match.get('criteria', '')
                if not cpe_criteria:
                    continue

                # 解析 CPE 字符串
                cpe_parts = self._parse_cpe_string(cpe_criteria)
                if not cpe_parts:
                    continue

                vendor = cpe_parts.get('vendor')
                product = cpe_parts.get('product')
                version = cpe_parts.get('version')

                # 跳过无效数据
                if not product or product == '*':
                    continue

                # 创建唯一键
                key = (vendor or 'unknown', product)

                # 推断版本方案
                ecosystem = self._infer_ecosystem_from_cpe(cpe_parts)
                version_scheme = self._infer_version_scheme(ecosystem, product)

                # 获取或创建 affected entry
                if key not in affected_map:
                    affected_map[key] = {
                        'vendor': vendor if vendor and vendor != '*' else None,
                        'product': product,
                        'ecosystem': ecosystem,
                        'package_type': 'upstream',
                        'versions': [],
                        'version_range': [],
                        'platform': [],
                        'distribution': None
                    }

                affected_entry = affected_map[key]

                # 处理版本信息
                # 1. 精确版本
                if version and version != '*':
                    if version not in affected_entry['versions']:
                        affected_entry['versions'].append(version)

                # 2. 版本范围 (从 versionStartIncluding, versionEndExcluding 等字段)
                has_range = any([
                    cpe_match.get('versionStartIncluding'),
                    cpe_match.get('versionStartExcluding'),
                    cpe_match.get('versionEndIncluding'),
                    cpe_match.get('versionEndExcluding')
                ])

                if has_range:
                    version_range_entry = {
                        'scheme': version_scheme,
                        'introduced': None,
                        'last_affected': None,
                        'fixed': None,
                        'limit': None,
                        'status': 'affected'
                    }

                    # 设置 introduced (开始版本)
                    if cpe_match.get('versionStartIncluding'):
                        version_range_entry['introduced'] = cpe_match['versionStartIncluding']
                    elif cpe_match.get('versionStartExcluding'):
                        # versionStartExcluding 表示不包含这个版本，我们记录在 limit 中
                        version_range_entry['limit'] = f"> {cpe_match['versionStartExcluding']}"
                        version_range_entry['introduced'] = cpe_match['versionStartExcluding']

                    # 设置 last_affected 或 fixed
                    if cpe_match.get('versionEndIncluding'):
                        # 包含这个版本，说明这是最后一个受影响的版本
                        version_range_entry['last_affected'] = cpe_match['versionEndIncluding']
                    elif cpe_match.get('versionEndExcluding'):
                        # 不包含这个版本，说明这是修复版本
                        version_range_entry['fixed'] = cpe_match['versionEndExcluding']

                    # 添加到 version_range 列表
                    affected_entry['version_range'].append(version_range_entry)

            # 递归处理子节点
            if 'children' in node:
                self._extract_affected_from_nodes(node['children'], affected_map)

    def _infer_version_scheme(self, ecosystem: str, product: str) -> str:
        """
        根据生态系统和产品推断版本方案

        Args:
            ecosystem: 生态系统名称
            product: 产品名称

        Returns:
            版本方案 (semver|rpm|deb|maven|ecosystem|custom)
        """
        ecosystem_lower = ecosystem.lower()
        product_lower = product.lower()

        # 基于生态系统
        if ecosystem_lower in ['pypi', 'npm', 'rubygems', 'crates.io', 'go']:
            return 'semver'
        elif ecosystem_lower in ['debian', 'ubuntu']:
            return 'deb'
        elif ecosystem_lower in ['rhel', 'centos', 'fedora', 'rocky', 'alma']:
            return 'rpm'
        elif ecosystem_lower == 'maven':
            return 'maven'

        # 基于产品特征
        if any(indicator in product_lower for indicator in ['node', 'npm', 'javascript', 'typescript']):
            return 'semver'
        elif any(indicator in product_lower for indicator in ['python', 'django', 'flask']):
            return 'semver'
        elif any(indicator in product_lower for indicator in ['java', 'apache', 'tomcat', 'spring']):
            return 'maven'

        # 默认使用生态系统特定方案
        return 'ecosystem'

    def _parse_cpe_string(self, cpe: str) -> Dict[str, str]:
        """
        解析 CPE 2.3 字符串

        格式: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

        Args:
            cpe: CPE 字符串

        Returns:
            解析后的字典 {part, vendor, product, version, ...}
        """
        parts = cpe.split(':')

        if len(parts) < 6:
            return {}

        # CPE 2.3 格式
        if parts[0] == 'cpe' and parts[1] == '2.3':
            return {
                'part': parts[2] if len(parts) > 2 else None,
                'vendor': parts[3] if len(parts) > 3 else None,
                'product': parts[4] if len(parts) > 4 else None,
                'version': parts[5] if len(parts) > 5 else None,
                'update': parts[6] if len(parts) > 6 else None,
                'edition': parts[7] if len(parts) > 7 else None,
                'language': parts[8] if len(parts) > 8 else None,
                'sw_edition': parts[9] if len(parts) > 9 else None,
                'target_sw': parts[10] if len(parts) > 10 else None,
                'target_hw': parts[11] if len(parts) > 11 else None,
                'other': parts[12] if len(parts) > 12 else None
            }

        # CPE 2.2 格式
        elif parts[0] == 'cpe':
            part_vendor = parts[1].split('/') if len(parts) > 1 else []
            return {
                'part': part_vendor[0] if len(part_vendor) > 0 else None,
                'vendor': part_vendor[1] if len(part_vendor) > 1 else (parts[2] if len(parts) > 2 else None),
                'product': parts[3] if len(parts) > 3 else None,
                'version': parts[4] if len(parts) > 4 else None,
                'update': parts[5] if len(parts) > 5 else None,
                'edition': parts[6] if len(parts) > 6 else None,
                'language': parts[7] if len(parts) > 7 else None
            }

        return {}

    def _infer_ecosystem_from_cpe(self, cpe_parts: Dict[str, str]) -> str:
        """
        从 CPE 信息推断 ecosystem

        Args:
            cpe_parts: 解析后的 CPE 字段

        Returns:
            ecosystem 字符串
        """
        part = cpe_parts.get('part', '')
        vendor = cpe_parts.get('vendor', '').lower()
        product = cpe_parts.get('product', '').lower()

        # 基于 part 类型
        if part == 'o':
            # 操作系统
            if 'debian' in vendor or 'debian' in product:
                return 'Debian'
            elif 'ubuntu' in vendor or 'ubuntu' in product:
                return 'Ubuntu'
            elif 'redhat' in vendor or 'red_hat' in vendor:
                return 'RHEL'
            elif 'centos' in vendor or 'centos' in product:
                return 'CentOS'
            elif 'alpine' in vendor or 'alpine' in product:
                return 'Alpine'
            elif 'windows' in product:
                return 'Windows'
            elif 'linux' in product:
                return 'Linux'
            else:
                return 'OS'

        elif part == 'a':
            # 应用程序
            language_indicators = {
                'python': ['python', 'pypi', 'django', 'flask', 'pip'],
                'javascript': ['node', 'npm', 'yarn', 'react', 'vue', 'angular'],
                'java': ['apache', 'maven', 'spring', 'tomcat'],
                'ruby': ['ruby', 'rubygems', 'rails'],
                'php': ['php', 'composer', 'wordpress', 'drupal'],
                'go': ['golang', 'go_'],
                'rust': ['rust', 'cargo'],
                '.net': ['microsoft', 'dotnet', '.net'],
            }

            for lang, indicators in language_indicators.items():
                if any(ind in vendor or ind in product for ind in indicators):
                    if lang == 'python':
                        return 'PyPI'
                    elif lang == 'javascript':
                        return 'npm'
                    elif lang == 'java':
                        return 'Maven'
                    elif lang == 'ruby':
                        return 'RubyGems'
                    elif lang == 'php':
                        return 'Packagist'
                    elif lang == 'go':
                        return 'Go'
                    elif lang == 'rust':
                        return 'crates.io'
                    elif lang == '.net':
                        return 'NuGet'

            return 'upstream'

        elif part == 'h':
            return 'Hardware'

        return 'upstream'

    def _map_github(self, data: Dict, schema: Dict) -> Dict:
        """Map GitHub Security Advisories to unified schema"""
        if 'data' in data:
            github_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
        else:
            github_data = data

        # ID
        schema['id'] = github_data.get('id') or data.get('id')

        # Aliases
        schema['aliases'] = github_data.get('aliases', [])
        if data.get('cve_id'):
            if data['cve_id'] not in schema['aliases']:
                schema['aliases'].append(data['cve_id'])

        # Source
        schema['source'] = {
            'provider': 'GitHub',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = github_data.get('summary')
        schema['description'] = [{
            'lang': 'en',
            'value': github_data.get('details', ''),
            'format': 'markdown',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(github_data.get('published'))
        schema['modified'] = self._normalize_timestamp(github_data.get('modified'))
        schema['withdrawn'] = self._normalize_timestamp(github_data.get('withdrawn'))


        # Weaknesses - 从database_specific中提取cwe_ids
        db_specific = github_data.get('database_specific', {})
        cwe_ids = db_specific.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            schema['weaknesses'].append({
                'id': cwe_id,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': 'GitHub'
            })

        # Severity
        severity_list = github_data.get('severity', [])
        for sev in severity_list:
            sev_type = sev.get('type', '')
            if 'CVSS' in sev_type:
                version = '3.1' if 'V3' in sev_type else '2.0'
                schema['severity'].append({
                    'source': 'OSV',
                    'scheme': f"CVSS:{version}",
                    'score': None,
                    'vector': sev.get('score'),
                    'rating': None
                })
            else:
                # Ecosystem-specific rating
                schema['severity'].append({
                    'source': 'OSV',
                    'scheme': sev_type,
                    'score': None,
                    'vector': None,
                    'rating': sev.get('score')
                })
        # 如果database_specific中有severity，也添加
        if db_specific.get('severity'):
            # 检查是否已经存在
            if not any(s['rating'] == db_specific['severity'] for s in schema['severity']):
                schema['severity'].append({
                    'source': "GitHub",
                    'scheme': 'Other',
                    'score': None,
                    'vector': None,
                    'rating': db_specific['severity']
                })
        # Severity
        severity_list = github_data.get('severity', [])
        for sev in severity_list:
            if sev.get('type') == 'CVSS_V3':
                schema['severity'].append({
                    'source': 'GitHub',
                    'scheme': 'CVSS:3.1',
                    'score': None,
                    'vector': sev.get('score'),
                    'rating': None
                })

        # Affected
        affected_list = github_data.get('affected', [])
        for affected_item in affected_list:
            package = affected_item.get('package', {})
            ranges = affected_item.get('ranges', [])

            version_ranges = []
            repo_url = None

            for range_item in ranges:
                events = range_item.get('events', [])
                range_dict = {
                    'scheme': range_item.get('type', 'ECOSYSTEM').lower(),
                    'introduced': None,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': 'affected'
                }

                for event in events:
                    if 'introduced' in event:
                        range_dict['introduced'] = event['introduced']
                    if 'fixed' in event:
                        range_dict['fixed'] = event['fixed']
                    if 'last_affected' in event:
                        range_dict['last_affected'] = event['last_affected']
                    if 'limit' in event:
                        range_dict['limit'] = event['limit']

                version_ranges.append(range_dict)

                # Extract repo URL from range if available
                if range_item.get('repo'):
                    repo_url = range_item.get('repo')

                # Extract ecosystem_specific data
            ecosystem_specific = affected_item.get('ecosystem_specific', {})

            # Extract affected_functions from ecosystem_specific
            affected_functions = []
            if ecosystem_specific:
                # affected_functions can be a list or dict
                funcs = ecosystem_specific.get('affected_functions', [])
                if isinstance(funcs, list):
                    affected_functions = funcs
                elif isinstance(funcs, dict):
                    # Sometimes it's a dict with function names as keys
                    affected_functions = list(funcs.keys())

            # Extract affects information (OS, arch, etc.)
            affects = ecosystem_specific.get('affects', {})
            os_list = affects.get('os', [])
            arch_list = affects.get('arch', [])

            # If os_list or arch_list are dicts, extract keys
            if isinstance(os_list, dict):
                os_list = list(os_list.keys())
            if isinstance(arch_list, dict):
                arch_list = list(arch_list.keys())

            # Extract affected functions from affects.functions if present
            affects_functions = affects.get('functions', {})
            if isinstance(affects_functions, dict):
                for func_name in affects_functions.keys():
                    if func_name not in affected_functions:
                        affected_functions.append(func_name)
            elif isinstance(affects_functions, list):
                for func_name in affects_functions:
                    if func_name not in affected_functions:
                        affected_functions.append(func_name)

            # print(version_ranges)
            schema['affected'].append({
                'vendor': None,
                'product': package.get('name'),
                'ecosystem': package.get('ecosystem'),
                'package': package.get('name'),
                'status': 'affected',
                'versions': affected_item.get('versions', []),
                'version_range': version_ranges,
                'repo': repo_url,
                'cpe': None,
                'purl': package.get('purl'),
                'os': os_list,
                'os_version': [],
                'arch': arch_list,
                'platform': [],
                'modules': [],
                'files': [],
                'functions': affected_functions
            })

        # References
        references = github_data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': None,
                'tags': [ref.get('type')] if ref.get('type') else []
            }
            for ref in references
        ]

        return schema

    def _map_mend(self, data: Dict, schema: Dict) -> Dict:
        def _construct_cvss_vector_mend(cvss: Dict) -> Optional[str]:
            """Construct CVSS vector string from IBM X-Force data"""
            # version = cvss.get('version', '3.0')
            av = cvss.get('Attack Vector (AV):', 'N')[0]
            ac = cvss.get('Attack Complexity (AC):', 'L')[0]
            pr = cvss.get('Privileges Required (PR):', 'N')[0]
            ui = cvss.get('User Interaction (UI):', 'N')[0]
            s = cvss.get('Scope (S):', 'U')[0]
            c = cvss.get('Confidentiality (C):', 'N')[0]
            i = cvss.get('Integrity (I):', 'N')[0]
            a = cvss.get('Availability (A):', 'N')[0]

            return f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        """Map Mend.io data to unified schema"""
        # ID
        schema['id'] = data.get('vul_id')

        # Source
        schema['source'] = {
            'provider': 'Mend.io',
            'reporter': None,
            'category': 'database-entry'
        }

        # Title and Description
        schema['description'] = [{
            'lang': 'en',
            'value': data.get('desc', ''),
            'format': 'text',
            'media': []
        }]
        # schema['title'] = data.get('desc', '')[:256]

        # Published
        schema['published'] = self._normalize_timestamp(data.get('date'))

        # Weaknesses
        cwe_ids = data.get('cwe_id', [])
        for cwe_id in cwe_ids:
            schema['weaknesses'].append({
                'id': cwe_id,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': 'Mend.io'
            })

        # Severity (CVSS)
        cvss_list = data.get('cvss', [])
        for cvss in cvss_list:
            cvss_type = cvss.get('cvss_type', 'CVSS v3.1')
            version = '3.1' if '3.1' in cvss_type.lower() else '2.0'
            cvss_data = cvss.get('cvss_data', {})

            schema['severity'].append({
                'source': 'Mend.io',
                'scheme': f"CVSS:{version}",
                'score': float(cvss_data.get('Base Score:', 0)),
                'vector': f"CVSS:{version}/" + _construct_cvss_vector_mend(cvss_data),
                'rating': None
            })

        # References
        related_resources = data.get('related_resources', [])
        schema['references'] = [
            {'url': url, 'name': None, 'tags': []}
            for url in related_resources
        ]

        # Remediation - upstream_fix
        upstream_fix = data.get('fix', [])
        if upstream_fix:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': f"Upstream fix: {upstream_fix}",
                'supportingMedia': []
            })

        return schema

    def _map_osv(self, data: Dict, schema: Dict) -> Dict:
        """Map OSV data to unified schema"""
        if 'osv_msg' in data:
            osv_data = json.loads(data['osv_msg']) if isinstance(data['osv_msg'], str) else data['osv_msg']
        else:
            osv_data = data

        # ID
        schema['id'] = osv_data.get('id')

        # Aliases
        schema['aliases'] = osv_data.get('aliases', [])

        # Related
        schema['related'] = osv_data.get('related', [])

        # Source - 使用OSV ID作为来源标识
        osv_id = osv_data.get('id', '')
        source_provider = 'OSV'

        # 根据ID前缀确定具体来源
        if osv_id.startswith('GHSA-'):
            source_provider = 'GitHub Security Advisory'
        elif osv_id.startswith('GO-'):
            source_provider = 'Go Vulnerability Database'
        elif osv_id.startswith('RUSTSEC-'):
            source_provider = 'RustSec'
        elif osv_id.startswith('PYSEC-'):
            source_provider = 'PyPA Advisory Database'
        elif osv_id.startswith('DSA-'):
            source_provider = 'Debian Security Advisory'
        else:
            source_provider = osv_id

        schema['source'] = {
            'provider': source_provider,
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = osv_data.get('summary')
        schema['description'] = [{
            'lang': 'en',
            'value': osv_data.get('details', ''),
            'format': 'text',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(osv_data.get('published'))
        schema['modified'] = self._normalize_timestamp(osv_data.get('modified'))
        schema['withdrawn'] = self._normalize_timestamp(osv_data.get('withdrawn'))

        # Weaknesses - 从database_specific中提取cwe_ids
        db_specific = osv_data.get('database_specific', {})
        cwe_ids = db_specific.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            schema['weaknesses'].append({
                'id': cwe_id,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': source_provider
            })

        # Severity
        severity_list = osv_data.get('severity', [])
        for sev in severity_list:
            sev_type = sev.get('type', '')
            if 'CVSS' in sev_type:
                version = '3.1' if 'V3' in sev_type else '2.0'
                schema['severity'].append({
                    'source': 'OSV',
                    'scheme': f"CVSS:{version}",
                    'score': None,
                    'vector': sev.get('score'),
                    'rating': None
                })
            else:
                # Ecosystem-specific rating
                schema['severity'].append({
                    'source': 'OSV',
                    'scheme': sev_type,
                    'score': None,
                    'vector': None,
                    'rating': sev.get('score')
                })
        # 如果database_specific中有severity，也添加
        if db_specific.get('severity'):
            # 检查是否已经存在
            if not any(s['rating'] == db_specific['severity'] for s in schema['severity']):
                schema['severity'].append({
                    'source': source_provider,
                    'scheme': 'Other',
                    'score': None,
                    'vector': None,
                    'rating': db_specific['severity']
                })

        # Affected
        affected_list = osv_data.get('affected', [])
        for affected_item in affected_list:
            package = affected_item.get('package', {})
            ranges = affected_item.get('ranges', [])

            version_ranges = []
            repo_url = None

            for range_item in ranges:
                events = range_item.get('events', [])
                range_dict = {
                    'scheme': range_item.get('type', 'ECOSYSTEM').lower(),
                    'introduced': None,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': 'affected'
                }

                for event in events:
                    if 'introduced' in event:
                        range_dict['introduced'] = event['introduced']
                    if 'fixed' in event:
                        range_dict['fixed'] = event['fixed']
                    if 'last_affected' in event:
                        range_dict['last_affected'] = event['last_affected']
                    if 'limit' in event:
                        range_dict['limit'] = event['limit']

                version_ranges.append(range_dict)

                # Extract repo URL from range if available
                if range_item.get('repo'):
                    repo_url = range_item.get('repo')

                # Extract ecosystem_specific data
            ecosystem_specific = affected_item.get('ecosystem_specific', {})

            # Extract affected_functions from ecosystem_specific
            affected_functions = []
            if ecosystem_specific:
                # affected_functions can be a list or dict
                funcs = ecosystem_specific.get('affected_functions', [])
                if isinstance(funcs, list):
                    affected_functions = funcs
                elif isinstance(funcs, dict):
                    # Sometimes it's a dict with function names as keys
                    affected_functions = list(funcs.keys())

            # Extract affects information (OS, arch, etc.)
            affects = ecosystem_specific.get('affects', {})
            os_list = affects.get('os', [])
            arch_list = affects.get('arch', [])

            # If os_list or arch_list are dicts, extract keys
            if isinstance(os_list, dict):
                os_list = list(os_list.keys())
            if isinstance(arch_list, dict):
                arch_list = list(arch_list.keys())

            # Extract affected functions from affects.functions if present
            affects_functions = affects.get('functions', {})
            if isinstance(affects_functions, dict):
                for func_name in affects_functions.keys():
                    if func_name not in affected_functions:
                        affected_functions.append(func_name)
            elif isinstance(affects_functions, list):
                for func_name in affects_functions:
                    if func_name not in affected_functions:
                        affected_functions.append(func_name)

            schema['affected'].append({
                'vendor': None,
                'product': package.get('name'),
                'ecosystem': package.get('ecosystem'),
                'package': package.get('name'),
                'status': 'affected',
                'versions': affected_item.get('versions', []),
                'version_range': version_ranges,
                'repo': repo_url,
                'cpe': None,
                'purl': package.get('purl'),
                'os': os_list,
                'os_version': [],
                'arch': arch_list,
                'platform': [],
                'modules': [],
                'files': [],
                'functions': affected_functions
            })

        # References
        references = osv_data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': None,
                'tags': [ref.get('type')] if ref.get('type') else []
            }
            for ref in references
        ]

        # Credits
        credits = osv_data.get('credits', [])
        schema['acknowledgements'] = [
            {
                'name': credit.get('name'),
                'type': None,
                'contact': credit.get('contact', []),
                'lang': None,
                'uuid': None
            }
            for credit in credits
        ]

        if db_specific:
            schema['tags'] = db_specific

        # Primary URLs - 从database_specific.source提取
        if db_specific.get('source'):
            schema['primary_urls'].append({
                'source': source_provider,
                'url': db_specific['source']
            })

        return schema

    def _map_ibm(self, data: Dict, schema: Dict) -> Dict:
        """Map IBM X-Force data to unified schema"""
        # ID
        stdcode = data.get('stdcode', [])
        schema['id'] = stdcode[0] if stdcode else None
        schema['aliases'] = stdcode[1:] if len(stdcode) > 1 else []

        # Source
        schema['source'] = {
            'provider': 'IBM X-Force',
            'reporter': None,
            'category': 'database-entry'
        }

        # Title and Description
        schema['title'] = data.get('title')
        schema['description'] = [{
            'lang': 'en',
            'value': data.get('description', ''),
            'format': 'text',
            'media': []
        }]

        # Published
        schema['published'] = self._normalize_timestamp(data.get('reported'))
        # # Updated (如果有updated字段，映射到modified)
        # schema['modified'] = self._normalize_timestamp(data.get('updated')) if data.get('updated') else None

        # Weaknesses - consequences字段作为weakness描述
        consequences = data.get('consequences')
        if consequences:
            schema['weaknesses'].append({
                'id': None,
                'taxonomy': 'Text',
                'name': consequences,
                'description': consequences,
                'source': 'IBM X-Force'
            })

        # Severity
        cvss = data.get('cvss', {})
        if cvss:
            version = cvss.get('version', '3.0')
            schema['severity'].append({
                'source': 'IBM X-Force',
                'scheme': f"CVSS:{version}",
                'score': data.get('risk_level'),
                'vector': self._construct_cvss_vector(cvss),
                'rating': None
            })

        # Exploitability - 添加到severity作为rating
        exploitability = data.get('exploitability')
        if exploitability:
            schema['severity'].append({
                'source': 'IBM X-Force',
                'scheme': 'Exploitability',
                'score': None,
                'vector': None,
                'rating': exploitability  # e.g., "High", "Medium", "Low", "Unproven"
            })
        # References
        references = data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('link_target'),
                'name': ref.get('link_name'),
                'tags': []
            }
            for ref in references
        ]

        # # Affected
        # platforms = data.get('platforms_affected', [])
        # for platform in platforms:
        #     schema['affected'].append({
        #         'vendor': None,
        #         'product': platform,
        #         'ecosystem': None,
        #         'package': None,
        #         'status': 'affected',
        #         'versions': [],
        #         'version_range': [],
        #         'repo': None,
        #         'cpe': None,
        #         'purl': None,
        #         'os': [],
        #         'os_version': [],
        #         'arch': [],
        #         'platform': [],
        #         'modules': [],
        #         'files': [],
        #         'functions': []
        #     })
        # Affected - platforms_affected (直接受影响的产品)
        # Affected - 处理platforms_affected和platforms_dependent，合并相同产品
        affected_dict = {}  # Key: (vendor, product), Value: affected_entry

        # 处理platforms_affected
        platforms_affected = data.get('platforms_affected', [])
        for platform in platforms_affected:
            product_info = self._parse_platform_string(platform)
            key = (product_info.get('vendor'), product_info.get('product'))

            if key not in affected_dict:
                affected_dict[key] = {
                    'vendor': product_info.get('vendor'),
                    'product': product_info.get('product'),
                    'ecosystem': None,
                    'package': None,
                    'status': 'affected',
                    'versions': [],
                    'version_range': [],
                    'repo': None,
                    'cpe': None,
                    'purl': None,
                    'os': [],
                    'os_version': [],
                    'arch': [],
                    'platform': [],
                    'modules': [],
                    'files': [],
                    'functions': []
                }

            # 添加版本和平台
            version = product_info.get('version')
            if version and version not in affected_dict[key]['versions']:
                affected_dict[key]['versions'].append(version)

            if platform not in affected_dict[key]['platform']:
                affected_dict[key]['platform'].append(platform)

        # 处理platforms_dependent
        platforms_dependent = data.get('platforms_dependent', [])
        for platform in platforms_dependent:
            product_info = self._parse_platform_string(platform)
            key = (product_info.get('vendor'), product_info.get('product'))

            if key not in affected_dict:
                affected_dict[key] = {
                    'vendor': product_info.get('vendor'),
                    'product': product_info.get('product'),
                    'ecosystem': None,
                    'package': None,
                    'status': 'affected',
                    'versions': [],
                    'version_range': [],
                    'repo': None,
                    'cpe': None,
                    'purl': None,
                    'os': [],
                    'os_version': [],
                    'arch': [],
                    'platform': [],
                    'modules': [],
                    'files': [],
                    'functions': []
                }

            # 添加版本和平台
            version = product_info.get('version')
            if version and version not in affected_dict[key]['versions']:
                affected_dict[key]['versions'].append(version)

            if platform not in affected_dict[key]['platform']:
                affected_dict[key]['platform'].append(platform)

        # 将合并后的affected条目添加到schema
        schema['affected'] = list(affected_dict.values())

        # 对versions进行排序（可选）
        for affected_entry in schema['affected']:
            if affected_entry['versions']:
                try:
                    # 尝试按版本号排序
                    affected_entry['versions'].sort(key=lambda v: [int(x) if x.isdigit() else x for x in v.split('.')])
                except:
                    # 如果排序失败，保持原顺序
                    pass

        # Remediation
        remedy = data.get('remedy')
        if remedy:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': remedy,
                'supportingMedia': []
            })

        # Tags
        # Report confidence
        report_confidence = data.get('report_confidence')
        if report_confidence:
            schema['tags'].append({
                'description': f"confidence-{report_confidence.lower()}",
                'source': 'IBM X-Force'
            })


        return schema

    def _parse_platform_string(self, platform: str) -> Dict[str, str]:
        """
        Parse platform string to extract vendor, product, and version
        Examples:
        - "Ruby on Rails Active Support 3.0" -> vendor: None, product: "Ruby on Rails Active Support", version: "3.0"
        - "IBM License Metric Tool 9.0" -> vendor: "IBM", product: "License Metric Tool", version: "9.0"
        """
        import re

        result = {
            'vendor': None,
            'product': None,
            'version': None
        }

        # 尝试匹配版本号（数字开头，可能包含点号）
        version_match = re.search(r'\b(\d+(?:\.\d+)*(?:\.\w+)?)\s*$', platform)
        if version_match:
            result['version'] = version_match.group(1)
            # 移除版本号，剩余部分是产品名
            product_part = platform[:version_match.start()].strip()
        else:
            product_part = platform.strip()

        # 尝试识别常见厂商名
        vendor_patterns = [
            (r'^IBM\b', 'IBM'),
            (r'^Microsoft\b', 'Microsoft'),
            (r'^Oracle\b', 'Oracle'),
            (r'^Red\s+Hat\b', 'Red Hat'),
            (r'^Apache\b', 'Apache'),
            (r'^Cisco\b', 'Cisco'),
            (r'^Google\b', 'Google'),
            (r'^Amazon\b', 'Amazon'),
        ]

        for pattern, vendor_name in vendor_patterns:
            if re.match(pattern, product_part, re.IGNORECASE):
                result['vendor'] = vendor_name
                # 移除厂商名，剩余部分是产品名
                result['product'] = re.sub(pattern, '', product_part, flags=re.IGNORECASE).strip()
                break

        if not result['vendor']:
            # 没有识别到厂商，整个作为产品名
            result['product'] = product_part

        return result

    def _map_debian(self, data: Dict, schema: Dict) -> Dict:
        """Map Debian Security Tracker data to unified schema"""
        # ID
        schema['id'] = data.get('cve_id')

        # Source
        schema['source'] = {
            'provider': 'Debian',
            'reporter': None,
            'category': 'advisory'
        }

        # Description
        schema['description'] = [{
            'lang': 'en',
            'value': data.get('description', ''),
            'format': 'text',
            'media': []
        }]
        # schema['title'] = data.get('description', '')[:256]

        # Affected packages
        package = data.get('package')
        releases = data.get('releases', {})
        for release_name, release_info in releases.items():
            status_map = {
                'resolved': 'resolved',
                'vulnerable': 'affected',
                'undetermined': 'unknown'
            }

            schema['affected'].append({
                'vendor': 'Debian',
                'product': package,
                'ecosystem': 'deb',
                'package': package,
                'status': status_map.get(release_info.get('status'), 'unknown'),
                'versions': [],
                'version_range': [{
                    'scheme': 'deb',
                    'introduced': None,
                    'last_affected': None,
                    'fixed': release_info.get('fixed_version'),
                    'limit': None,
                    'status': status_map.get(release_info.get('status'), 'unknown')
                }],
                'repo': None,
                'cpe': None,
                'purl': f"pkg:deb/debian/{package}",
                'os': ['Debian'],
                'os_version': [release_name],
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            })

        return schema

    def _map_edb(self, data: Dict, schema: Dict) -> Dict:
        """Map Exploit-DB data to unified schema"""

        # 从codes字段提取CVE ID和其他标识符
        codes = data.get('codes', '')
        aliases_list = []
        cve_ids = []  # 存储所有CVE ID

        if codes and isinstance(codes, str) and codes.strip():
            # codes格式: "CVE-2015-3222;OSVDB-123222" 或 "OSVDB-12616;CVE-2004-1054"
            code_list = [c.strip() for c in codes.split(';') if c.strip()]

            for code in code_list:
                if code.startswith('CVE-'):
                    cve_ids.append(code)  # 收集所有CVE
                else:
                    # OSVDB, BID等其他标识符作为别名
                    aliases_list.append(code)

        # 处理aliases字段（CSV中的aliases列）
        aliases_field = data.get('aliases', '')
        if aliases_field and isinstance(aliases_field, str) and aliases_field.strip():
            alias_items = [a.strip() for a in aliases_field.split(',') if a.strip()]
            for alias in alias_items:
                if alias and alias not in aliases_list:
                    aliases_list.append(alias)

        # ID选择逻辑
        edb_id = data.get('id')
        if edb_id:
            edb_id = str(edb_id)

        if len(cve_ids) > 0:
            # 如果有CVE，使用第一个CVE作为主ID
            schema['id'] = cve_ids[0]
            # 其他CVE加入aliases
            for cve in cve_ids[1:]:
                if cve not in aliases_list:
                    aliases_list.append(cve)
            # EDB ID也加入aliases
            if edb_id:
                aliases_list.append(f"EDB-{edb_id}")
        elif edb_id:
            # 没有CVE，使用EDB ID作为主ID
            schema['id'] = f"EDB-{edb_id}"
        else:
            # 既没有CVE也没有EDB ID（理论上不应该发生）
            schema['id'] = None

        # Aliases
        schema['aliases'] = aliases_list

        # Source
        author = data.get('author', '')
        # 处理空值和NaN
        if not author or str(author).strip() == 'nan' or str(author).strip() == '':
            author = None

        schema['source'] = {
            'provider': 'Exploit-DB',
            'reporter': author,
            'category': 'exploit'
        }

        # Title - 直接使用description
        description = data.get('description', '')
        if not description or str(description).strip() == 'nan' or str(description).strip() == '':
            description = None

        # schema['title'] = description

        # Description - 构建详细描述
        exploit_type = data.get('type', '')
        platform = data.get('platform', '')
        port = data.get('port', '')
        file_path = data.get('file', '')

        detail_parts = []
        if description:
            detail_parts.append(description)

        if file_path and str(file_path).strip() != 'nan' and str(file_path).strip():
            detail_parts.append(f"\nExploit File: {file_path}")

        if exploit_type and str(exploit_type).strip() != 'nan' and str(exploit_type).strip():
            detail_parts.append(f"Type: {exploit_type}")

        if platform and str(platform).strip() != 'nan' and str(platform).strip():
            detail_parts.append(f"Platform: {platform}")

        if port and str(port).strip() != 'nan' and str(port).strip():
            detail_parts.append(f"Port: {port}")

        schema['description'] = [{
            'lang': 'en',
            'value': '\n'.join(detail_parts) if detail_parts else 'No description available',
            'format': 'text',
            'media': []
        }]

        # Timestamps
        date_published = data.get('date_published')
        date_added = data.get('date_added')
        date_updated = data.get('date_updated')

        # 处理日期格式
        def parse_edb_date(date_str):
            if not date_str or str(date_str).strip() == 'nan' or pd.isna(date_str):
                return None
            try:
                date_str = str(date_str).strip()
                if not date_str:
                    return None

                # 尝试解析 "2015/6/11" 或 "2003/5/23" 格式
                if '/' in date_str:
                    parts = date_str.split('/')
                    if len(parts) == 3:
                        year, month, day = parts
                        return f"{year}-{month.zfill(2)}-{day.zfill(2)}T00:00:00Z"

                return self._normalize_timestamp(date_str)
            except:
                return None

        schema['published'] = parse_edb_date(date_published) or parse_edb_date(date_added)
        schema['modified'] = parse_edb_date(date_updated)

        # Exploitation
        exploit_text = "Public exploit available"
        if edb_id:
            exploit_text += f" (EDB-{edb_id})"
        if file_path and str(file_path).strip() != 'nan' and str(file_path).strip():
            exploit_text += f" - File: {file_path}"

        exploit_links = []
        source_url = data.get('source_url', '')
        if source_url and str(source_url).strip() != 'nan' and str(source_url).strip():
            exploit_links.append(str(source_url).strip())

        schema['exploitation']['exploits'].append({
            'source': 'Exploit-DB',
            'lang': 'en',
            'text': exploit_text,
            'links': exploit_links
        })

        # References
        if source_url and str(source_url).strip() != 'nan' and str(source_url).strip():
            schema['references'].append({
                'url': str(source_url).strip(),
                'name': 'External Reference',
                'tags': ['exploit']
            })

        # Application URL
        application_url = data.get('application_url', '')
        if application_url and str(application_url).strip() != 'nan' and str(application_url).strip():
            schema['references'].append({
                'url': str(application_url).strip(),
                'name': 'Vulnerable Application',
                'tags': []
            })

        # Screenshot URL
        screenshot_url = data.get('screenshot_url', '')
        if screenshot_url and str(screenshot_url).strip() != 'nan' and str(screenshot_url).strip():
            schema['references'].append({
                'url': str(screenshot_url).strip(),
                'name': 'Screenshot',
                'tags': []
            })


        # Affected - 从platform和description推断
        if platform and str(platform).strip() != 'nan' and str(platform).strip():
            platform = str(platform).strip()

            # 尝试从description中提取产品名称和版本
            affected_items = []

            if description:
                affected_items = self._parse_edb_affected(description, platform)

            # 如果无法解析，创建一个基本的affected条目
            if not affected_items:
                affected_items = [{
                    'product': description[:100] if description else None,
                    'versions': []
                }]

            # 清理platform值
            valid_os_platforms = ['linux', 'windows', 'osx', 'bsd', 'solaris', 'aix', 'hp-ux', 'unix',
                                  'android', 'ios']
            is_os_platform = platform.lower() in valid_os_platforms

            for item in affected_items:
                schema['affected'].append({
                    'vendor': item.get('vendor'),
                    'product': item.get('product'),
                    'ecosystem': None,
                    'package': None,
                    'status': 'affected',
                    'versions': item.get('versions', []),
                    'version_range': [],
                    'repo': None,
                    'cpe': None,
                    'purl': None,
                    'os': [platform] if is_os_platform else [],
                    'os_version': [],
                    'arch': [],
                    'platform': [platform],
                    'modules': [],
                    'files': [],
                    'functions': []
                })

        # Tags
        tags_field = data.get('tags', '')
        if tags_field and str(tags_field).strip() != 'nan' and isinstance(tags_field, str) and tags_field.strip():
            tag_list = [t.strip() for t in tags_field.split(',') if t.strip()]
            for tag in tag_list:
                schema['tags'].append({
                    'description': tag.lower(),
                    'source': 'Exploit-DB'
                })

        # Type tag
        if exploit_type and str(exploit_type).strip() != 'nan' and str(exploit_type).strip():
            schema['tags'].append({
                'description': f"type-{str(exploit_type).strip().lower()}",
                'source': 'Exploit-DB'
            })

        # Platform tag
        if platform and str(platform).strip() != 'nan' and str(platform).strip():
            schema['tags'].append({
                'description': f"platform-{str(platform).strip().lower()}",
                'source': 'Exploit-DB'
            })

        # Verified tag
        verified = data.get('verified')
        if verified in ['1', 1, True, 'true']:
            schema['tags'].append({
                'description': 'verified',
                'source': 'Exploit-DB'
            })
        elif verified in ['0', 0, False, 'false']:
            schema['tags'].append({
                'description': 'unverified',
                'source': 'Exploit-DB'
            })

        # Primary URL
        if edb_id:
            schema['primary_urls'].append({
                'source': 'Exploit-DB',
                'url': f"https://www.exploit-db.com/exploits/{edb_id}"
            })

        return schema

    def _map_redhat(self, data: Dict, schema: Dict) -> Dict:
        """Map Red Hat Security Advisories to unified schema"""
        if 'data' in data:
            rh_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
        else:
            rh_data = data

        # ID
        schema['id'] = data.get('cve_id')

        # Source
        schema['source'] = {
            'provider': 'RedHat',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        details = rh_data.get('details', [])
        if details:
            schema['description'] = [{
                'lang': 'en',
                'value': details[0] if isinstance(details, list) else details,
                'format': 'text',
                'media': []
            }]
            desc_text = details[0] if isinstance(details, list) else details
            # schema['title'] = desc_text[:256]

        # Published
        schema['published'] = self._normalize_timestamp(rh_data.get('public_date'))

        # Weakness
        cwe = rh_data.get('cwe')
        if cwe:
            # Extract CWE IDs from string like "CWE-79"
            import re
            cwe_ids = re.findall(r'CWE-\d+', cwe)
            for cwe_id in cwe_ids:
                schema['weaknesses'].append({
                    'id': cwe_id,
                    'taxonomy': 'CWE',
                    'name': None,
                    'description': None,
                    'source': 'RedHat'
                })

        # Severity
        threat_severity = rh_data.get('threat_severity')
        cvss3 = rh_data.get('cvss3', {})

        if threat_severity:
            schema['severity'].append({
                'source': 'RedHat',
                'scheme': 'RedHat:ThreatSeverity',
                'score': None,
                'vector': None,
                'rating': threat_severity
            })

        if cvss3 and cvss3.get('cvss3_base_score'):
            schema['severity'].append({
                'source': 'RedHat',
                'scheme': 'CVSS:3.1',
                'score': float(cvss3.get('cvss3_base_score')),
                'vector': cvss3.get('cvss3_scoring_vector'),
                'rating': None
            })

        # Affected - from affected_release
        affected_releases = rh_data.get('affected_release', [])
        if affected_releases:
            # Group by product to merge versions
            affected_dict = {}

            for release in affected_releases:
                product_name = release.get('product_name')
                package = release.get('package')
                cpe = release.get('cpe')

                key = (product_name, package)

                if key not in affected_dict:
                    affected_dict[key] = {
                        'vendor': 'Red Hat',
                        'product': product_name,
                        'ecosystem': 'rpm',
                        'package': package,
                        'status': 'affected',
                        'versions': [],
                        'version_range': [],
                        'repo': None,
                        'cpe': cpe,
                        'purl': None,
                        'os': ['Red Hat Enterprise Linux'],
                        'os_version': [],
                        'arch': [],
                        'platform': [],
                        'modules': [],
                        'files': [],
                        'functions': []
                    }

                # Extract version from package if present
                # e.g., "tpm2-tss-0:2.3.2-5.el8" -> "2.3.2-5.el8"
                if package and ':' in package:
                    version = package.split(':', 1)[1]
                    if version and version not in affected_dict[key]['versions']:
                        affected_dict[key]['versions'].append(version)

            schema['affected'].extend(affected_dict.values())

        # Package state (products not affected or won't be fixed)
        package_states = rh_data.get('package_state', [])
        if package_states:
            # Group by product to merge packages
            state_dict = {}

            for pkg_state in package_states:
                product_name = pkg_state.get('product_name')
                package_name = pkg_state.get('package_name')
                fix_state = pkg_state.get('fix_state', '')
                cpe = pkg_state.get('cpe')

                # Map fix_state to status
                status_map = {
                    'Not affected': 'unaffected',
                    'Will not fix': 'affected',
                    'Fix deferred': 'affected',
                    'Out of support scope': 'affected'
                }
                status = status_map.get(fix_state, 'unknown')

                key = (product_name, package_name, status)

                if key not in state_dict:
                    state_dict[key] = {
                        'vendor': 'Red Hat',
                        'product': product_name,
                        'ecosystem': 'rpm',
                        'package': package_name,
                        'status': status,
                        'versions': [],
                        'version_range': [],
                        'repo': None,
                        'cpe': cpe,
                        'purl': None,
                        'os': ['Red Hat Enterprise Linux'],
                        'os_version': [],
                        'arch': [],
                        'platform': [],
                        'modules': [],
                        'files': [],
                        'functions': []
                    }

            schema['affected'].extend(state_dict.values())

        # Remediation - upstream_fix
        upstream_fix = rh_data.get('upstream_fix')
        if upstream_fix:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': f"Upstream fix: {upstream_fix}",
                'supportingMedia': []
            })

        # References
        references = rh_data.get('references', [])
        if references:
            for ref_url in references:
                # Split by newline if multiple URLs
                urls = ref_url.strip().split('\n')
                for url in urls:
                    url = url.strip()
                    if url:
                        schema['references'].append({
                            'url': url,
                            'name': None,
                            'tags': []
                        })

        # Vendor Comments - statement字段
        statement = rh_data.get('statement')
        if statement:
            schema['vendor_comments'].append({
                'source': 'Red Hat',
                'comment': statement,
                'time': None
            })

        # Acknowledgements - acknowledgement字段
        acknowledgement = rh_data.get('acknowledgement')
        if acknowledgement:
            schema['acknowledgements'].append({
                'name': acknowledgement,
                'type': 'other',
                'contact': [],
                'lang': 'en',
                'uuid': None
            })

        # References
        references = rh_data.get('references', [])
        if references:
            for ref_url in references:
                schema['references'].append({
                    'url': ref_url,
                    'name': None,
                    'tags': []
                })

        return schema

    def _parse_edb_affected(self, description: str, platform: str) -> List[Dict]:
        """
        Parse EDB description to extract affected products and versions

        Examples:
        - "IBM AIX 4.2.1 / Sun Solaris 7.0 - LC_MESSAGES libc Buffer Overflow (3)"
          -> [{'vendor': 'IBM', 'product': 'AIX', 'versions': ['4.2.1']},
              {'vendor': 'Sun', 'product': 'Solaris', 'versions': ['7.0']}]

        - "AIX 4.3/5.1 - diagrpt Arbitrary Privileged Program Execution"
          -> [{'vendor': None, 'product': 'AIX', 'versions': ['4.3', '5.1']}]

        - "OSSEC 2.7 < 2.8.1 - 'diff' Local Privilege Escalation"
          -> [{'vendor': None, 'product': 'OSSEC', 'versions': ['2.7', '2.8.1']}]

        - "Mailman 1.x > 2.1.23 - Cross Site Scripting (XSS)"
          -> [{'vendor': None, 'product': 'Mailman', 'versions': ['1.x', '2.1.23']}]
        """
        import re

        affected_items = []

        if not description or ' - ' not in description:
            return affected_items

        # 提取产品部分（第一个'-'之前）
        product_part = description.split(' - ')[0].strip()

        # Pattern 1: "IBM AIX 4.2.1 / Sun Solaris 7.0" - 多个产品用斜杠分隔
        if ' / ' in product_part:
            products = product_part.split(' / ')
            for prod in products:
                prod = prod.strip()
                item = self._extract_single_product(prod)
                if item:
                    affected_items.append(item)
        else:
            # Pattern 2: 单个产品
            item = self._extract_single_product(product_part)
            if item:
                affected_items.append(item)

        return affected_items

    def _extract_single_product(self, product_str: str) -> Optional[Dict]:
        """
        Extract vendor, product, and versions from a single product string

        Examples:
        - "IBM AIX 4.2.1" -> {'vendor': 'IBM', 'product': 'AIX', 'versions': ['4.2.1']}
        - "AIX 4.3/5.1" -> {'vendor': None, 'product': 'AIX', 'versions': ['4.3', '5.1']}
        - "AIX 4.3/5.1 < 5.3" -> {'vendor': None, 'product': 'AIX', 'versions': ['4.3', '5.1 to 5.3']}
        - "OSSEC 2.7 < 2.8.1" -> {'vendor': None, 'product': 'OSSEC', 'versions': ['2.7 to 2.8.1']}
        - "Mailman 1.x > 2.1.23" -> {'vendor': None, 'product': 'Mailman', 'versions': ['1.x to 2.1.23']}
        """
        import re

        if not product_str:
            return None

        result = {
            'vendor': None,
            'product': None,
            'versions': []
        }

        # 识别常见厂商名
        vendor_patterns = [
            (r'^IBM\s+', 'IBM'),
            (r'^Sun\s+', 'Sun'),
            (r'^Microsoft\s+', 'Microsoft'),
            (r'^Oracle\s+', 'Oracle'),
            (r'^Red\s+Hat\s+', 'Red Hat'),
            (r'^Apache\s+', 'Apache'),
            (r'^Cisco\s+', 'Cisco'),
        ]

        remaining_text = product_str
        for pattern, vendor_name in vendor_patterns:
            match = re.match(pattern, remaining_text, re.IGNORECASE)
            if match:
                result['vendor'] = vendor_name
                remaining_text = remaining_text[match.end():].strip()
                break

        # 提取版本号 - 支持多种复杂格式
        version_patterns = [
            # Pattern: "AIX 4.3/5.1 < 5.3" - 多版本 + 范围上限
            # 匹配: 产品名 版本1/版本2/... < 上限版本
            (r'^([A-Za-z\s]+?)\s+([\d.x]+(?:/[\d.x]+)+)\s*<\s*([\d.x]+)', 'multi_version_with_upper'),

            # Pattern: "AIX 4.3/5.1 > 5.0" - 多版本 + 范围下限（理论情况）
            (r'^([A-Za-z\s]+?)\s+([\d.x]+(?:/[\d.x]+)+)\s*>\s*([\d.x]+)', 'multi_version_with_lower'),

            # Pattern: "OSSEC 2.7 < 2.8.1" - 版本范围（小于）
            (r'^([A-Za-z\s]+?)\s+([\d.x]+)\s*<\s*([\d.x]+)', 'range_less_than'),

            # Pattern: "Mailman 1.x > 2.1.23" - 版本范围（大于，表示从1.x到2.1.23）
            (r'^([A-Za-z\s]+?)\s+([\d.x]+)\s*>\s*([\d.x]+)', 'range_greater_than'),

            # Pattern: "AIX 4.3/5.1" - 斜杠分隔的多版本
            (r'^([A-Za-z\s]+?)\s+([\d.x]+(?:/[\d.x]+)+)', 'slash_versions'),

            # Pattern: "AIX 4.2.1" - 单个版本
            (r'^([A-Za-z\s]+?)\s+([\d.x]+)', 'single_version'),

            # Pattern: "AIX" - 无版本号
            (r'^([A-Za-z\s]+?)$', 'no_version'),
        ]

        for pattern, pattern_type in version_patterns:
            match = re.match(pattern, remaining_text)
            if match:
                if pattern_type == 'multi_version_with_upper':
                    # "AIX 4.3/5.1 < 5.3"
                    # 解析为: 4.3, 5.1 to 5.3
                    result['product'] = match.group(1).strip()
                    versions_str = match.group(2)  # "4.3/5.1"
                    upper_bound = match.group(3)  # "5.3"

                    versions_list = [v.strip() for v in versions_str.split('/')]
                    # 最后一个版本形成范围
                    if len(versions_list) > 1:
                        result['versions'] = versions_list[:-1] + [f"{versions_list[-1]} to {upper_bound}"]
                    else:
                        result['versions'] = [f"{versions_list[0]} to {upper_bound}"]

                elif pattern_type == 'multi_version_with_lower':
                    # "AIX 4.3/5.1 > 5.0" (理论情况，较少见)
                    result['product'] = match.group(1).strip()
                    versions_str = match.group(2)
                    lower_bound = match.group(3)

                    versions_list = [v.strip() for v in versions_str.split('/')]
                    # 第一个版本形成范围
                    if len(versions_list) > 1:
                        result['versions'] = [f"{lower_bound} to {versions_list[0]}"] + versions_list[1:]
                    else:
                        result['versions'] = [f"{lower_bound} to {versions_list[0]}"]

                elif pattern_type == 'range_less_than':
                    # "OSSEC 2.7 < 2.8.1" -> "2.7 to 2.8.1"
                    result['product'] = match.group(1).strip()
                    lower = match.group(2).strip()
                    upper = match.group(3).strip()
                    result['versions'] = [f"{lower} to {upper}"]

                elif pattern_type == 'range_greater_than':
                    # "Mailman 1.x > 2.1.23" -> "1.x to 2.1.23"
                    result['product'] = match.group(1).strip()
                    lower = match.group(2).strip()
                    upper = match.group(3).strip()
                    result['versions'] = [f"{lower} to {upper}"]

                elif pattern_type == 'slash_versions':
                    # "AIX 4.3/5.1" -> ["4.3", "5.1"]
                    result['product'] = match.group(1).strip()
                    versions_str = match.group(2)
                    result['versions'] = [v.strip() for v in versions_str.split('/')]

                elif pattern_type == 'single_version':
                    # "AIX 4.2.1" -> ["4.2.1"]
                    result['product'] = match.group(1).strip()
                    result['versions'] = [match.group(2).strip()]

                elif pattern_type == 'no_version':
                    # "AIX" -> []
                    result['product'] = match.group(1).strip()
                    result['versions'] = []
                break

        # 如果没有匹配到，整个字符串作为产品名
        if not result['product']:
            result['product'] = remaining_text.strip()

        return result if result['product'] else None

    def _map_snyk(self, data: Dict, schema: Dict) -> Dict:
        """Map Snyk data to unified schema"""
        if 'data' in data:
            snyk_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
            snyk_data = snyk_data.get('data', [{}])[0]
        else:
            snyk_data = data

        # ID
        schema['id'] = data.get('cve_id') or snyk_data.get('id')
        schema['aliases'] = [snyk_data.get('id')]

        # Source
        schema['source'] = {
            'provider': 'Snyk',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = snyk_data.get('title')

        description_html = snyk_data.get('description', '')
        # Parse HTML to extract text
        import re
        description_text = re.sub(r'<[^>]+>', '', description_html)
        schema['description'] = [{
            'lang': 'en',
            'value': description_text,
            'format': 'text',
            'media': []
        }]

        # Published
        schema['published'] = self._normalize_timestamp(snyk_data.get('publicationTime'))
        schema['modified'] = self._normalize_timestamp(snyk_data.get('modificationTime'))

        # Severity
        cvss_details = snyk_data.get('cvssDetails', [])
        for cvss in cvss_details:
            schema['severity'].append({
                'source': cvss.get('assigner', 'Snyk'),
                'scheme': f"CVSS:{cvss.get('cvssV3Vector').split('CVSS:')[-1].split('/')[0]}",
                'score': cvss.get('cvssV3BaseScore'),
                'vector': cvss.get('cvssV3Vector'),
                'rating': cvss.get('severity')
            })

        # Weaknesses
        identifiers = snyk_data.get('identifiers', {})
        cwe_ids = identifiers.get('CWE', [])
        for cwe_id in cwe_ids:
            schema['weaknesses'].append({
                'id': cwe_id,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': 'Snyk'
            })

        # Affected - 按照正确的 schema
        package_name = snyk_data.get('packageName')
        package_manager = snyk_data.get('packageManager', '')
        vulnerable_versions = snyk_data.get('vulnerableVersions', '')
        if not vulnerable_versions:
            vulnerable_versions = snyk_data.get("semver", '')

        if package_name:
            affected_entry = {
                'vendor': None,
                'product': package_name,
                'ecosystem': None,
                'package': package_name,
                'distribution': None,
                'status': 'affected',
                'versions': [],
                'version_range': [],
                'repo': None,
                'cpe': None,
                'purl': None,
                'os': [],
                'os_version': [],
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            }

            # 解析 packageManager 来确定 ecosystem 和 distribution
            if ':' in package_manager:
                # 格式: "rhel:7", "debian:10" 等
                parts = package_manager.split(':', 1)
                distro_name = parts[0].lower()
                distro_version = parts[1]

                # 设置 ecosystem
                if distro_name in ['rhel', 'centos', 'fedora', 'rocky', 'alma']:
                    affected_entry['ecosystem'] = 'rpm'
                elif distro_name in ['debian', 'ubuntu', 'alpine']:
                    affected_entry['ecosystem'] = 'deb'
                else:
                    affected_entry['ecosystem'] = distro_name

                # 设置 distribution (首字母大写)
                distro_display = distro_name.upper() if distro_name == 'rhel' else distro_name.capitalize()
                affected_entry['distribution'] = f"{distro_display}:{distro_version}"

                # 设置 os 和 os_version
                affected_entry['os'] = [distro_display]
                affected_entry['os_version'] = [distro_version]

            else:
                # 非发行版包（如 npm, pypi）
                ecosystem_map = {
                    'npm': 'npm',
                    'pypi': 'pypi',
                    'maven': 'maven',
                    'rubygems': 'rubygems',
                    'packagist': 'packagist',
                    'nuget': 'nuget',
                    'cargo': 'crates.io',
                    'go': 'go',
                    'composer': 'packagist',
                    'hex': 'hex',
                    'pub': 'pub'
                }
                affected_entry['ecosystem'] = ecosystem_map.get(package_manager.lower(), package_manager.lower())
                affected_entry['distribution'] = 'upstream'

            # 解析 vulnerableVersions 到 version_range
            if vulnerable_versions:
                version_range_entry = self._parse_snyk_version_range(
                    vulnerable_versions,
                    affected_entry['ecosystem']
                )
                if version_range_entry and isinstance(version_range_entry, list):
                    for version_range in version_range_entry:
                        if version_range.get('introduced') is None and version_range.get(
                                'last_affected') is None and version_range.get('fixed') is None:
                            pass
                        else:
                            affected_entry['version_range'].append(version_range)
                elif version_range_entry:
                    if version_range_entry.get('introduced') is None and version_range_entry.get(
                            'last_affected') is None and version_range_entry.get('fixed') is None:
                        pass
                    else:
                        affected_entry['version_range'].append(version_range_entry)

            # 构建 purl (Package URL)
            if affected_entry['ecosystem'] and package_name:
                purl = self._build_purl(
                    affected_entry['ecosystem'],
                    package_name,
                    affected_entry.get('distribution')
                )
                affected_entry['purl'] = purl

            schema['affected'].append(affected_entry)

        # EPSS
        epss_details = snyk_data.get('epssDetails', {})
        if epss_details:
            schema['exploitation']['epss'].append({
                'source': 'Snyk',
                'cve_id': data.get('cve_id'),
                'score': epss_details.get('probability'),
                'percentile': epss_details.get('percentile'),
                'last_updated': epss_details.get('modelVersion', '')[:10]
            })

        # References
        references = snyk_data.get('references', [])
        if isinstance(references, str):
            # Parse HTML references
            import re
            urls = re.findall(r'href="([^"]+)"', references)
            schema['references'] = [{'url': url, 'name': None, 'tags': []} for url in urls]

        # Remediation
        remediation = snyk_data.get('remediation', '')
        if remediation:
            remediation_text = re.sub(r'<[^>]+>', '', remediation)
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': remediation_text,
                'supportingMedia': []
            })

        return schema

    def _parse_snyk_version_range(self, version_range_str: str, ecosystem: str) -> List[Dict]:
        """
        解析 Snyk 的版本范围字符串（支持多个范围）

        Snyk 格式示例:
        - "[,1.17.3)"                                    # 单个范围
        - "(,2.11.3]", "[2.12.0,2.12.2]"                # 多个范围（数组）
        - "[,2.7.2) , [2.8.0,2.8.1) , [2.9.0,2.9.1)"   # 多个范围（逗号分隔）
        - "*"                                            # 所有版本
        - ">=1.0.319,<1.0.474 , >=1.1.0,<1.1.10"       # semver 风格

        Args:
            version_range_str: 版本范围字符串（可能包含多个范围）
            ecosystem: 生态系统名称

        Returns:
            version_range entries 列表（可能多个）
        """
        import re

        # 确定版本方案
        scheme_map = {
            'rpm': 'rpm',
            'deb': 'deb',
            'pypi': 'semver',
            'npm': 'semver',
            'rubygems': 'semver',
            'crates.io': 'semver',
            'go': 'semver',
            'maven': 'maven',
            'nuget': 'semver',
            'packagist': 'semver'
        }
        scheme = scheme_map.get(ecosystem, 'ecosystem')

        # 清理 HTML 实体
        version_range_str = version_range_str.replace('&#8239;', ' ')
        version_range_str = version_range_str.replace('&lt;', '<')
        version_range_str = version_range_str.replace('&gt;', '>')
        version_range_str = version_range_str.strip()

        # 特殊情况：所有版本
        if version_range_str == '*':
            return [{
                'scheme': scheme,
                'introduced': None,
                'last_affected': None,
                'fixed': None,
                'limit': None,
                'status': 'affected'
            }]

        # 分割多个范围（用逗号分隔，但要注意区分 Maven 格式中的逗号）
        ranges = self._split_version_ranges(version_range_str)

        results = []
        for range_str in ranges:
            range_str = range_str.strip()
            if not range_str:
                continue

            parsed = self._parse_single_version_range(range_str, scheme)
            if parsed:
                results.append(parsed)

        return results if results else None

    def _split_version_ranges(self, version_range_str: str) -> List[str]:
        """
        分割多个版本范围（智能处理逗号）

        Args:
            version_range_str: 版本范围字符串

        Returns:
            版本范围列表
        """
        import re

        # 如果包含 Maven 格式的括号，需要特殊处理
        # 例如: "[,2.7.2) , [2.8.0,2.8.1)"
        # 不能简单按逗号分割，因为括号内的逗号是语法的一部分

        ranges = []
        current = ""
        bracket_depth = 0

        for char in version_range_str:
            if char in '([':
                bracket_depth += 1
                current += char
            elif char in ')]':
                bracket_depth -= 1
                current += char
            elif char == ',' and bracket_depth == 0:
                # 这是范围分隔符
                if current.strip():
                    ranges.append(current.strip())
                current = ""
            else:
                current += char

        # 添加最后一个
        if current.strip():
            ranges.append(current.strip())

        return ranges

    def _parse_single_version_range(self, range_str: str, scheme: str) -> Dict:
        """
        解析单个版本范围

        Args:
            range_str: 单个版本范围字符串
            scheme: 版本方案

        Returns:
            version_range entry 或 None
        """
        import re

        version_range = {
            'scheme': scheme,
            'introduced': None,
            'last_affected': None,
            'fixed': None,
            'limit': None,
            'status': 'affected'
        }

        range_str = range_str.strip()

        # === Maven 风格范围: [min, max), (min, max], [min, max], (min, max) ===

        # 模式 1: "[,version)" 或 "(,version)" - 无下界，有上界（不含）
        match = re.match(r'^[\[\(],\s*([^\]\)]+)\)$', range_str)
        if match:
            version_range['fixed'] = match.group(1)
            return version_range

        # 模式 2: "[,version]" 或 "(,version]" - 无下界，有上界（含）
        match = re.match(r'^[\[\(],\s*([^\]\)]+)\]$', range_str)
        if match:
            version_range['last_affected'] = match.group(1)
            return version_range

        # 模式 3: "[version,)" 或 "(version,)" - 有下界，无上界
        match = re.match(r'^([\[\(])([^\],\)]+),\s*\)$', range_str)
        if match:
            bracket = match.group(1)
            version = match.group(2)
            if bracket == '[':
                # 包含下界
                version_range['introduced'] = version
            else:
                # 不包含下界
                version_range['introduced'] = version
                version_range['limit'] = f"> {version}"
            return version_range

        # 模式 4: "[version1, version2)" - 含下界，不含上界
        match = re.match(r'^\[([^,]+),\s*([^\]]+)\)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['fixed'] = match.group(2)
            return version_range

        # 模式 5: "(version1, version2)" - 不含下界，不含上界
        match = re.match(r'^\(([^,]+),\s*([^\]]+)\)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['limit'] = f"> {match.group(1)}"
            version_range['fixed'] = match.group(2)
            return version_range

        # 模式 6: "[version1, version2]" - 含下界，含上界
        match = re.match(r'^\[([^,]+),\s*([^\]]+)\]$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['last_affected'] = match.group(2)
            return version_range

        # 模式 7: "(version1, version2]" - 不含下界，含上界
        match = re.match(r'^\(([^,]+),\s*([^\]]+)\]$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['limit'] = f"> {match.group(1)}"
            version_range['last_affected'] = match.group(2)
            return version_range

        # === Semver 风格: <, <=, >, >=, 组合 ===

        # 模式 8: ">=version1 <version2" 或 ">=version1,<version2"
        match = re.match(r'^>=\s*([^\s,]+)[\s,]+<\s*(.+)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['fixed'] = match.group(2)
            return version_range

        # 模式 9: ">version1 <version2" 或 ">version1,<version2"
        match = re.match(r'^>\s*([^\s,]+)[\s,]+<\s*(.+)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['limit'] = f"> {match.group(1)}"
            version_range['fixed'] = match.group(2)
            return version_range

        # 模式 10: ">=version1 <=version2"
        match = re.match(r'^>=\s*([^\s,]+)[\s,]+<=\s*(.+)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['last_affected'] = match.group(2)
            return version_range

        # 模式 11: "<version"
        match = re.match(r'^<\s*(.+)$', range_str)
        if match:
            version_range['fixed'] = match.group(1)
            return version_range

        # 模式 12: "<=version"
        match = re.match(r'^<=\s*(.+)$', range_str)
        if match:
            version_range['last_affected'] = match.group(1)
            return version_range

        # 模式 13: ">version"
        match = re.match(r'^>\s*(.+)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            version_range['limit'] = f"> {match.group(1)}"
            return version_range

        # 模式 14: ">=version"
        match = re.match(r'^>=\s*(.+)$', range_str)
        if match:
            version_range['introduced'] = match.group(1)
            return version_range

        # 无法解析
        return None

    def _build_purl(self, ecosystem: str, package_name: str, distribution: str = None) -> str:
        """
        构建 Package URL (purl)

        Format: pkg:type/namespace/name@version?qualifiers#subpath

        Args:
            ecosystem: 生态系统
            package_name: 包名
            distribution: 发行版信息

        Returns:
            purl 字符串
        """
        # purl type mapping
        type_map = {
            'npm': 'npm',
            'pypi': 'pypi',
            'maven': 'maven',
            'nuget': 'nuget',
            'crates.io': 'cargo',
            'rubygems': 'gem',
            'go': 'golang',
            'packagist': 'composer',
            'rpm': 'rpm',
            'deb': 'deb'
        }

        purl_type = type_map.get(ecosystem, ecosystem)

        # 基本格式
        purl = f"pkg:{purl_type}/{package_name}"

        # 添加 qualifiers (如 distro)
        if distribution and distribution != 'upstream':
            # 例如: pkg:rpm/eap7-hibernate-envers?distro=rhel-7
            distro_qualifier = distribution.replace(':', '-').lower()
            purl += f"?distro={distro_qualifier}"

        return purl

    def _map_gitlab(self, data: Dict, schema: Dict) -> Dict:
        """Map GitLab Gemnasium data to unified schema"""
        if 'data' in data:
            gitlab_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
        else:
            gitlab_data = data

        # Check if this is a .gitlab-ci.yml file or actual vulnerability data
        if 'stages' in gitlab_data or 'include' in gitlab_data:
            # This is CI/CD configuration, not vulnerability data
            schema['id'] = data.get('cve_id', 'Unknown')
            schema['source'] = {
                'provider': 'GitLab',
                'reporter': None,
                'category': 'scanner'
            }
            return schema

        # ID
        schema['id'] = gitlab_data.get('identifier') or data.get('cve_id')

        # Aliases
        identifiers = gitlab_data.get('identifiers', [])
        schema['aliases'] = [i for i in identifiers if i != schema['id']]

        # Source
        schema['source'] = {
            'provider': 'GitLab',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = gitlab_data.get('title')
        schema['description'] = [{
            'lang': 'en',
            'value': gitlab_data.get('description', ''),
            'format': 'text',
            'media': []
        }]

        # Published
        schema['published'] = self._normalize_timestamp(gitlab_data.get('pubdate'))
        schema['modified'] = self._normalize_timestamp(gitlab_data.get('date'))

        # Severity
        cvss_v2 = gitlab_data.get('cvss_v2')
        cvss_v3 = gitlab_data.get('cvss_v3')

        if cvss_v2:
            schema['severity'].append({
                'source': 'GitLab',
                'scheme': 'CVSS:2.0',
                'score': None,
                'vector': cvss_v2,
                'rating': None
            })

        if cvss_v3:
            schema['severity'].append({
                'source': 'GitLab',
                'scheme': cvss_v3.split('CVSS:')[-1].split('/')[0],
                'score': None,
                'vector': cvss_v3,
                'rating': None
            })

        # Weaknesses
        cwe_ids = gitlab_data.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            schema['weaknesses'].append({
                'id': cwe_id,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': 'GitLab'
            })

        # Affected
        package_slug = gitlab_data.get('package_slug', '')
        affected_range = gitlab_data.get('affected_range', '')
        fixed_versions = gitlab_data.get('fixed_versions', [])

        if package_slug:
            schema['affected'].append({
                'vendor': None,
                'product': package_slug.split('/')[-1] if '/' in package_slug else package_slug,
                'ecosystem': package_slug.split('/')[0] if '/' in package_slug else None,
                'package': package_slug,
                'status': 'affected',
                'versions': gitlab_data.get('affected_versions', '').split(','),
                # 'version_range': [{
                #     'scheme': 'semver',
                #     'introduced': None,
                #     'last_affected': None,
                #     'fixed': fixed_versions[0] if fixed_versions else None,
                #     'limit': None,
                #     'status': 'affected'
                # }],
                'version_range':[],
                'repo': None,
                'cpe': None,
                'purl': None,
                'os': [],
                'os_version': [],
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            })

        # References
        urls = gitlab_data.get('urls', [])
        schema['references'] = [
            {'url': url, 'name': None, 'tags': []}
            for url in urls
        ]

        # Remediation
        solution = gitlab_data.get('solution')
        if solution:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': solution,
                'supportingMedia': []
            })

        # Remediation - upstream_fix
        if fixed_versions:
            schema['remediation']['solutions'].append({
                    'lang': 'en',
                    'value': f"Upstream fix: {fixed_versions}",
                    'supportingMedia': []
                })
        # Credits/Acknowledgements
        credit = gitlab_data.get('credit', [])
        schema['acknowledgements'] = [
            {
                'name': credit,
                'type': 'other',
                'contact': [],
                'lang': 'en',
                'uuid': None
            }
        ]
        return schema

    def _map_rustsec(self, data: Dict, schema: Dict) -> Dict:
        """Map RustSec Advisory Database to unified schema"""
        if 'data' in data:
            rustsec_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
        else:
            rustsec_data = data

        # ID
        schema['id'] = rustsec_data.get('id')

        # Aliases
        schema['aliases'] = rustsec_data.get('aliases', [])

        # Related
        schema['related'] = rustsec_data.get('related', [])

        # Source
        schema['source'] = {
            'provider': 'RustSec',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = rustsec_data.get('summary')
        schema['description'] = [{
            'lang': 'en',
            'value': rustsec_data.get('details', ''),
            'format': 'text',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(rustsec_data.get('published'))
        schema['modified'] = self._normalize_timestamp(rustsec_data.get('modified'))
        schema['withdrawn'] = self._normalize_timestamp(rustsec_data.get('withdrawn'))

        # Severity
        severity_list = rustsec_data.get('severity', [])
        for sev in severity_list:
            schema['severity'].append({
                'source': 'RustSec',
                'scheme': sev.get('score').split('CVSS:')[-1].split('/')[0],
                'score': sev.get('score'),
                'vector': None,
                'rating': None
            })

        # Weaknesses (categories in RustSec)
        db_specific = rustsec_data.get('database_specific', {})
        # Severity
        severity_list = db_specific.get('cvss', '')
        cvss_temp = {
                'source': 'RustSec',
                'scheme': severity_list.split('CVSS:')[-1].split('/')[0],
                'score': severity_list,
                'vector': None,
                'rating': None
            }
        if cvss_temp not in schema['severity'] and severity_list:
            schema['severity'].append(cvss_temp)

        categories = db_specific.get('categories', [])
        for category in categories:
            schema['weaknesses'].append({
                'id': category,
                'taxonomy': 'RustSecCategory',
                'name': None,
                'description': None,
                'source': 'RustSec'
            })

        # Affected
        affected_list = rustsec_data.get('affected', [])
        for affected_item in affected_list:
            package = affected_item.get('package', {})
            ranges = affected_item.get('ranges', [])

            version_ranges = []
            for range_item in ranges:
                events = range_item.get('events', [])
                range_dict = {
                    'scheme': range_item.get('type', 'SEMVER').lower(),
                    'introduced': None,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': 'affected'
                }

                for event in events:
                    if 'introduced' in event:
                        range_dict['introduced'] = event['introduced']
                    if 'fixed' in event:
                        range_dict['fixed'] = event['fixed']
                    if 'last_affected' in event:
                        range_dict['last_affected'] = event['last_affected']

                version_ranges.append(range_dict)

            # Extract ecosystem-specific data
            ecosystem_specific = affected_item.get('ecosystem_specific', {})

            schema['affected'].append({
                'vendor': None,
                'product': package.get('name'),
                'ecosystem': package.get('ecosystem', 'crates.io'),
                'package': package.get('name'),
                'status': 'affected',
                'versions': affected_item.get('versions', []),
                'version_range': version_ranges,
                'repo': None,
                'cpe': None,
                'purl': package.get('purl'),
                'os': ecosystem_specific.get('affects', {}).get('os', []),
                'os_version': [],
                'arch': ecosystem_specific.get('affects', {}).get('arch', []),
                'platform': [],
                'modules': [],
                'files': [],
                'functions': ecosystem_specific.get('affects', {}).get('functions', [])
            })

        # References
        references = rustsec_data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': None,
                'tags': [ref.get('type')] if ref.get('type') else []
            }
            for ref in references
        ]

        # Copyright
        db_specific_license = db_specific.get('license')
        if db_specific_license:
            schema['copyrights'].append({
                'source': 'RustSec',
                'message': None,
                'notice': None,
                'license': db_specific_license,
                'license_url': None
            })

        return schema

    def _map_cert(self, data: Dict, schema: Dict) -> Dict:
        """Map CERT Vulnerability Notes to unified schema"""
        # ID
        cveids = data.get('cveids', [])
        schema['id'] = cveids[0] if cveids else f"VU#{data.get('id')}"
        schema['aliases'] = cveids[1:] if len(cveids) > 1 else []

        # Source
        schema['source'] = {
            'provider': 'CERT',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = data.get('name')

        clean_desc = data.get('clean_desc', '')
        overview = data.get('overview', '')
        full_desc = f"{overview}\n\n{clean_desc}" if overview else clean_desc

        schema['description'] = [{
            'lang': 'en',
            'value': full_desc,
            'format': 'text',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(data.get('original_release_date'))
        schema['modified'] = self._normalize_timestamp(data.get('last_revised'))

        # Impact
        impact = data.get('impact')
        if impact:
            schema['impacts'].append({
                'source': 'CERT',
                'lang': 'en',
                'text': impact,
                'capec_id': None
            })

        # Remediation
        resolution = data.get('resolution')
        if resolution:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': resolution,
                'supportingMedia': []
            })

        workarounds = data.get('workarounds')
        if workarounds:
            schema['remediation']['workarounds'].append({
                'lang': 'en',
                'value': workarounds,
                'supportingMedia': []
            })

        # References
        references = data.get('references', [])
        schema['references'] = [
            {'url': url, 'name': None, 'tags': []}
            for url in references
        ]

        # Vendor Information
        vendor_info = data.get('vendor_information', [])
        for vendor in vendor_info:
            if vendor.get('statement'):
                schema['vendor_comments'].append({
                    'source': "Cert",
                    'comment': f"The status of vendor is {vendor.get("status")}; and the vendor is {vendor.get('vendor')}; and the statement about this vendor is {vendor.get('statement')}",
                    'time': vendor.get("date_updated") or vendor.get("date_added")
                })

        return schema


    # === 新增三个数据库的映射函数 ===

    def _map_curl(self, data: Dict, schema: Dict) -> Dict:
        """Map Curl vulnerability database to unified schema"""
        # ID
        aliases = data.get('aliases', [])
        schema['id'] = data.get('id').split('CURL-')[-1]
        schema['aliases'] = [aliase for aliase in aliases if aliases != schema['id']]
        schema['aliases'].append(schema['id'])

        # Source
        schema['source'] = {
            'provider': 'Curl',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        schema['title'] = data.get('summary')
        schema['description'] = [{
            'lang': 'en',
            'value': data.get('details', ''),
            'format': 'text',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(data.get('published'))
        schema['modified'] = self._normalize_timestamp(data.get('modified'))

        # Database specific information
        db_specific = data.get('database_specific', {})

        # Weakness (CWE)
        cwe_info = db_specific.get('CWE', {})
        if cwe_info:
            cwe_id = cwe_info.get('id')
            cwe_desc = cwe_info.get('desc')
            if cwe_id:
                schema['weaknesses'].append({
                    'id': cwe_id,
                    'taxonomy': 'CWE',
                    'name': None,
                    'description': cwe_desc,
                    'source': 'Curl'
                })

        # Severity
        severity = db_specific.get('severity')
        if severity:
            schema['severity'].append({
                'source': 'Curl',
                'scheme': 'Other',
                'score': None,
                'vector': None,
                'rating': severity
            })

        # Affected
        affected_list = data.get('affected', [])
        for affected_item in affected_list:
            ranges = affected_item.get('ranges', [])

            version_ranges = []
            for range_item in ranges:
                range_type = range_item.get('type', '').upper()
                events = range_item.get('events', [])
                repo_url = range_item.get('repo')

                range_dict = {
                    'scheme': range_type.lower() if range_type else 'semver',
                    'introduced': None,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': 'affected'
                }

                for event in events:
                    if 'introduced' in event:
                        range_dict['introduced'] = event['introduced']
                    if 'fixed' in event:
                        range_dict['fixed'] = event['fixed']
                    if 'last_affected' in event:
                        range_dict['last_affected'] = event['last_affected']

                version_ranges.append(range_dict)

            schema['affected'].append({
                'vendor': None,
                'product': 'curl',
                'ecosystem': 'C/C++',
                'package': db_specific.get('package', 'curl'),
                'status': 'affected',
                'versions': affected_item.get('versions', []),
                'version_range': version_ranges,
                'repo': repo_url,
                'cpe': None,
                'purl': None,
                'os': [],
                'os_version': [],
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            })

        # Credits
        credits = data.get('credits', [])
        schema['acknowledgements'] = [
            {
                'name': credit.get('name'),
                'type': credit.get('type'),
                'contact': [],
                'lang': None,
                'uuid': None
            }
            for credit in credits
        ]

        # References
        issue_url = db_specific.get('issue')
        www_url = db_specific.get('www')
        url = db_specific.get('URL')

        if issue_url:
            schema['references'].append({
                'url': issue_url,
                'name': 'Issue Report',
                'tags': ['issue']
            })
        if www_url:
            schema['references'].append({
                'url': www_url,
                'name': 'Vulnerability Details',
                'tags': []
            })
        if url:
            schema['references'].append({
                'url': url,
                'name': 'Advisory JSON',
                'tags': []
            })

        # Primary URL
        if www_url:
            schema['primary_urls'].append({
                'source': 'Curl',
                'url': www_url
            })

        # Tags
        if db_specific.get('award'):
            award = db_specific['award']
            schema['tags'].append({
                'description': f"bounty-{award.get('amount', 0)}-{award.get('currency', 'USD')}",
                'source': 'Curl'
            })

        last_affected = db_specific.get('last_affected')
        if last_affected:
            schema['tags'].append({
                'description': f"last-affected-{last_affected}",
                'source': 'Curl'
            })

        return schema

    def _map_hunter(self, data: Dict, schema: Dict) -> Dict:
        """Map Hunter (huntr.com) vulnerability database to unified schema"""
        # ID - 从aliases提取CVE ID
        cve_id = data.get('cve')
        if cve_id:
            schema['id'] = cve_id
        else:
            schema['id'] = data.get('id')

        # Source
        schema['source'] = {
            'provider': 'Hunter',
            'reporter': data.get('authorFound'),
            'category': 'bug-bounty'
        }

        # Title and Description
        schema['title'] = data.get('title')

        # Description包含markdown格式的PoC内容
        pocmd = data.get('pocmd', '')
        # 清理HTML标签获取纯文本
        import re
        description_text = re.sub(r'<[^>]+>', '', pocmd)

        # schema['description'] = [{
        #     'lang': 'en',
        #     'value': description_text,
        #     'format': 'markdown',
        #     'media': []
        # }]
        schema['description'] = []

        # Timestamps - 从time字段解析
        time_str = data.get('time', '')  # Format: "Jul 18th 2023"
        published_date = self._parse_hunter_date(time_str)
        schema['published'] = published_date

        # Vulnerability status
        status = data.get('status', '').lower()
        status_map = {
            'fixed': 'published',
            'open': 'analyzing',
            'closed': 'rejected'
        }
        schema['vuln_status'] = status_map.get(status, 'published')

        # Weakness (CWE)
        cwe = data.get('cwe')
        if cwe:
            schema['weaknesses'].append({
                'id': cwe,
                'taxonomy': 'CWE',
                'name': None,
                'description': None,
                'source': 'Hunter'
            })

        # Severity
        severity_str = data.get('severity', '')  # Format: "Critical (9.8)" or "Medium (5.1)"
        if severity_str:
            # 解析severity字符串
            severity_match = re.match(r'(\w+)\s*\(([0-9.]+)\)', severity_str)
            if severity_match:
                rating = severity_match.group(1)
                score = float(severity_match.group(2))

                schema['severity'].append({
                    'source': 'Hunter',
                    'scheme': '',  # 假设使用CVSS 3.1
                    'score': score,
                    'vector': None,
                    'rating': rating
                })

        # Affected - 从repo和versions提取
        repo = data.get('repo', '')
        versions = data.get('versions', '')

        if repo:
            # repo格式: "/repos/jgraph/drawio"
            repo_parts = repo.strip('/').split('/')
            if len(repo_parts) >= 3:
                vendor = repo_parts[1]
                product = repo_parts[2]
            else:
                vendor = None
                product = repo.strip('/')

            schema['affected'].append({
                'vendor': vendor,
                'product': product,
                'ecosystem': None,
                'package': None,
                'status': 'affected',
                'versions': [versions] if versions and versions != '*' else [],
                'version_range': [],
                'repo': f"https://github.com{repo}" if repo else None,
                'cpe': None,
                'purl': None,
                'os': [],
                'os_version': [],
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            })

        # Exploitation - PoC available
        schema['exploitation']['exploits'].append({
            'source': 'Hunter',
            'lang': 'en',
            'text': 'Public proof-of-concept available: ' + pocmd,
            'links': [data.get('source')] if data.get('source') else []
        })

        # Remediation - patch links
        patches = data.get('patch', [])
        if patches:
            schema['remediation']['solutions'].append({
                'lang': 'en',
                'value': f"Patch available: {', '.join(patches)}",
                'supportingMedia': []
            })

        # References
        source_url = data.get('source')
        if source_url:
            schema['references'].append({
                'url': source_url,
                'name': 'Hunter Bounty Report',
                'tags': ['exploit', 'third-party-advisory']
            })

        for patch_url in patches:
            schema['references'].append({
                'url': patch_url,
                'name': 'Patch Commit',
                'tags': ['patch']
            })

        # Primary URL
        if source_url:
            schema['primary_urls'].append({
                'source': 'Hunter',
                'url': source_url
            })

        # Acknowledgements
        author_found = data.get('authorFound')
        author_fixed = data.get('authorFixed')

        if author_found:
            # Format: "Mizu@kevin-mizu"
            name_parts = author_found.split('@')
            schema['acknowledgements'].append({
                'name': name_parts[0] if name_parts else author_found,
                'type': 'FINDER',
                'contact': [f"@{name_parts[1]}"] if len(name_parts) > 1 else [],
                'lang': None,
                'uuid': None
            })

        if author_fixed:
            name_parts = author_fixed.split('@')
            schema['acknowledgements'].append({
                'name': name_parts[0] if name_parts else author_fixed,
                'type': 'REMEDIATION_DEVELOPER',
                'contact': [f"@{name_parts[1]}"] if len(name_parts) > 1 else [],
                'lang': None,
                'uuid': None
            })

        # Tags
        visibility = data.get('visibility', '')
        if visibility:
            schema['tags'].append({
                'description': f"visibility-{visibility.lower()}",
                'source': 'Hunter'
            })

        if status:
            schema['tags'].append({
                'description': f"status-{status}",
                'source': 'Hunter'
            })

        return schema

    def _parse_hunter_date(self, date_str: str) -> Optional[str]:
        """
        Parse Hunter date format: "Jul 18th 2023" or "Sep 30th 2021"

        Returns ISO 8601 format: "2023-07-18T00:00:00Z"
        """
        if not date_str:
            return None

        try:
            from datetime import datetime

            # 移除序数词后缀 (1st, 2nd, 3rd, 4th, etc.)
            date_str = date_str.replace('st ', ' ').replace('nd ', ' ').replace('rd ', ' ').replace('th ', ' ')

            # 解析日期
            date_obj = datetime.strptime(date_str.strip(), '%b %d %Y')

            return date_obj.strftime('%Y-%m-%dT00:00:00Z')
        except:
            return None

    def _map_ubuntu(self, data: Dict, schema: Dict) -> Dict:
        """Map Ubuntu Security Advisories to unified schema"""
        if 'data' in data:
            ubuntu_data = json.loads(data['data']) if isinstance(data['data'], str) else data['data']
        else:
            ubuntu_data = data

        # ID
        schema['id'] = ubuntu_data.get('id').split('UBUNTU-')[-1]

        # Aliases
        ubuntu_id = ubuntu_data.get('id')
        if ubuntu_id:
            schema['aliases'].append(ubuntu_id)

        # Related - upstream字段包含相关CVE
        upstream = ubuntu_data.get('upstream', [])
        if upstream:
            # upstream通常包含原始CVE ID，过滤掉与主ID相同的
            schema['related'] = [cve for cve in upstream if cve != schema['id']]
        upstream = ubuntu_data.get('related', [])
        if upstream:
            # upstream通常包含原始CVE ID，过滤掉与主ID相同的
            if not schema.get('related'):
                schema['related'] = [cve for cve in upstream if cve != schema['id']]
            else:
                for cve in upstream:
                    if cve not in schema['related']:
                        schema['related'].append(cve)

        # Source
        schema['source'] = {
            'provider': 'Ubuntu',
            'reporter': None,
            'category': 'advisory'
        }

        # Title and Description
        details = ubuntu_data.get('details', '')
        schema['description'] = [{
            'lang': 'en',
            'value': details,
            'format': 'text',
            'media': []
        }]

        # Timestamps
        schema['published'] = self._normalize_timestamp(ubuntu_data.get('published'))
        schema['modified'] = self._normalize_timestamp(ubuntu_data.get('modified'))
        schema['withdrawn'] = self._normalize_timestamp(ubuntu_data.get('withdrawn'))

        # Severity
        severity_list = ubuntu_data.get('severity', [])
        for sev in severity_list:
            sev_type = sev.get('type', 'Ubuntu')
            score = sev.get('score', '')

            schema['severity'].append({
                'source': sev_type,
                'scheme': 'Ubuntu',
                'score': score,
                'vector': None,
                'rating': None
            })

        # Affected packages
        affected_list = ubuntu_data.get('affected', [])
        for affected_item in affected_list:
            package = affected_item.get('package', {})
            ranges = affected_item.get('ranges', [])
            versions = affected_item.get('versions', [])

            # Extract ecosystem info from package
            ecosystem = package.get('ecosystem', '')  # Format: "Ubuntu:14.04:LTS"
            package_name = package.get('name')
            purl = package.get('purl')

            # Parse ecosystem
            os_name = 'Ubuntu'
            os_version = []
            if ':' in ecosystem:
                parts = ecosystem.split(':')
                if len(parts) >= 2:
                    os_name = parts[0]
                    os_version = [':'.join(parts[1:])]  # "14.04:LTS"

            # Parse version ranges
            version_ranges = []
            range_type = 'ECOSYSTEM'
            for range_item in ranges:
                range_type = range_item.get('type', 'ECOSYSTEM')
                events = range_item.get('events', [])

                range_dict = {
                    'scheme': range_type,
                    'introduced': None,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': 'affected'
                }

                for event in events:
                    if 'introduced' in event:
                        range_dict['introduced'] = event['introduced']
                    if 'fixed' in event:
                        range_dict['fixed'] = event['fixed']
                    if 'last_affected' in event:
                        range_dict['last_affected'] = event['last_affected']

                version_ranges.append(range_dict)

            # Extract ecosystem_specific
            ecosystem_specific = affected_item.get('ecosystem_specific', {})
            binaries = ecosystem_specific.get('binaries', [])
            availability = ecosystem_specific.get('availability')

            schema['affected'].append({
                'vendor': 'Canonical',
                'product': package_name,
                'ecosystem': 'deb',
                'package': package_name,
                'status': 'affected',
                'versions': versions,
                'version_range': version_ranges,
                'repo': None,
                'cpe': None,
                'purl': purl,
                'os': [os_name],
                'os_version': os_version,
                'arch': [],
                'platform': [],
                'modules': [],
                'files': [],
                'functions': []
            })

            # Add binaries as additional affected entries
            for binary in binaries:
                binary_name = binary.get('binary_name')
                binary_version = binary.get('binary_version')
                if binary_version:
                    range_dict = {
                        'scheme': range_type,
                        'introduced': None,
                        'last_affected': None,
                        'fixed': binary_version,
                        'limit': None,
                        'status': 'affected'
                    }

                if binary_name:
                    schema['affected'].append({
                        'vendor': 'Canonical',
                        'product': binary_name,
                        'ecosystem': 'deb',
                        'package': binary_name,
                        'status': 'affected',
                        # 'versions': [binary_version] if binary_version else [],
                        'versions': None,
                        'version_range': [range_dict] if range_dict else [],
                        'repo': None,
                        'cpe': None,
                        'purl': f"pkg:deb/ubuntu/{binary_name}",
                        'os': [os_name],
                        'os_version': os_version,
                        'arch': [],
                        'platform': [],
                        'modules': [],
                        'files': [],
                        'functions': []
                    })

        # References
        references = ubuntu_data.get('references', [])
        schema['references'] = [
            {
                'url': ref.get('url'),
                'name': None,
                'tags': [ref.get('type')] if ref.get('type') else []
            }
            for ref in references
        ]

        # # Tags
        # if ubuntu_data.get('schema_version'):
        #     schema['tags'].append({
        #         'description': f"schema-{ubuntu_data['schema_version']}",
        #         'source': 'Ubuntu'
        #     })

        return schema



    # Helper methods

    def _normalize_timestamp(self, timestamp: Optional[str]) -> Optional[str]:
        """Normalize timestamp to ISO 8601 UTC format"""
        if not timestamp:
            return None

        try:
            # Handle various formats
            if 'T' not in timestamp:
                # Date only
                return f"{timestamp}T00:00:00Z"
            elif not timestamp.endswith('Z'):
                # Has time but no timezone
                return f"{timestamp}Z"
            else:
                return timestamp
        except:
            return timestamp

    def _extract_version_ranges(self, versions: List[Dict]) -> List[Dict]:
        """Extract version ranges from CVE versions array"""
        ranges = []
        for v in versions:
            status = v.get('status', 'affected')
            version = v.get('version')

            if v.get('lessThan'):
                ranges.append({
                    'scheme': v.get('versionType', 'custom'),
                    'introduced': version,
                    'last_affected': None,
                    'fixed': v.get('lessThan'),
                    'limit': None,
                    'status': status
                })
            else:
                ranges.append({
                    'scheme': v.get('versionType', 'custom'),
                    'introduced': version,
                    'last_affected': None,
                    'fixed': None,
                    'limit': None,
                    'status': status
                })

        return ranges

    def _extract_cpe_nodes(self, nodes: List[Dict]) -> List[Dict]:
        """Extract CPE configuration nodes recursively"""
        result_nodes = []
        for node in nodes:
            result_node = {
                'operator': node.get('operator', 'OR'),
                'negate': node.get('negate', False),
                'cpeMatch': []
            }

            # Extract CPE matches
            cpe_matches = node.get('cpeMatch', [])
            for match in cpe_matches:
                result_node['cpeMatch'].append({
                    'vulnerable': match.get('vulnerable', True),
                    'criteria': match.get('criteria'),
                    'matchCriteriaId': match.get('matchCriteriaId'),
                    'versionStartIncluding': match.get('versionStartIncluding'),
                    'versionStartExcluding': match.get('versionStartExcluding'),
                    'versionEndIncluding': match.get('versionEndIncluding'),
                    'versionEndExcluding': match.get('versionEndExcluding'),
                    'provider': None
                })

            # Handle nested nodes
            if 'nodes' in node:
                result_node['nodes'] = self._extract_cpe_nodes(node['nodes'])

            result_nodes.append(result_node)

        return result_nodes

    def _construct_cvss_vector(self, cvss: Dict) -> Optional[str]:
        """Construct CVSS vector string from IBM X-Force data"""
        version = cvss.get('version', '3.0')
        av = cvss.get('access_vector', 'N')[0]
        ac = cvss.get('access_complexity', 'L')[0]
        pr = cvss.get('privilegesrequired', 'N')[0]
        ui = cvss.get('userinteraction', 'N')[0]
        s = cvss.get('scope', 'U')[0]
        c = cvss.get('confidentiality_impact', 'N')[0]
        i = cvss.get('integrity_impact', 'N')[0]
        a = cvss.get('availability_impact', 'N')[0]

        return f"CVSS:{version}/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    def extract_and_map(self, cve_id: str, source_name: str, output_dir: str = 'output') -> bool:
        """Extract and map data from a specific source"""
        print(f"\n提取 {cve_id} 从 {source_name}...")

        # Extract raw data
        raw_data = self.extract_cve_data(cve_id, source_name)
        if not raw_data:
            print(f"  ✗ 未找到数据")
            return False

        print(f"  ✓ 找到原始数据")

        # Map to unified schema
        unified_data = self.map_to_unified_schema(raw_data, source_name)

        # Save result
        output_path = Path(output_dir) / source_name
        output_path.mkdir(parents=True, exist_ok=True)

        output_file = output_path / f"{cve_id}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(unified_data, f, indent=2, ensure_ascii=False)

        print(f"  ✓ 已保存到: {output_file}")

        # Print summary
        non_empty_fields = sum(1 for k, v in unified_data.items() if self._is_non_empty(v))
        print(f"  📊 提取了 {non_empty_fields}/24 个字段")

        return True

    def _is_non_empty(self, value: Any) -> bool:
        """Check if a value is non-empty"""
        if value is None:
            return False
        if isinstance(value, (list, dict, str)) and not value:
            return False
        if isinstance(value, dict):
            return any(self._is_non_empty(v) for v in value.values())
        return True

    def load_cve_from_csv(csv_file: str, cve_id: str, source_name: str = None) -> Dict:
        """
        从CSV文件中加载特定CVE的JSON数据

        Args:
            csv_file: CSV文件路径（可以是单一大文件或特定数据库的CSV）
            cve_id: 要查找的CVE ID
            source_name: 数据库名称（如果是单一大文件需要指定）

        Returns:
            解析后的JSON数据
        """
        import pandas as pd
        import json

        df = pd.read_csv(csv_file)

        # 查找CVE
        row = df[df['CVE_ID'] == cve_id]

        if row.empty:
            return None

        if source_name:
            # 从大文件中读取特定列
            json_str = row[source_name].iloc[0]
        else:
            # 从数据库专用文件中读取data列
            json_str = row['data'].iloc[0]

        return json.loads(json_str)
    def batch_extract_to_csv0(self, cve_list_file: str, output_csv: str = 'cve_database_results.csv') -> pd.DataFrame:
        """
        批量提取CVE数据并将JSON结果存储到CSV

        Args:
            cve_list_file: CVE列表文件路径（每行一个CVE ID）
            output_csv: 输出CSV文件路径

        Returns:
            DataFrame containing the JSON results
        """
        import pandas as pd
        from pathlib import Path
        import json

        print("\n" + "=" * 70)
        print("Batch Extraction to CSV (JSON Results)")
        print("=" * 70)

        # 读取CVE列表
        print(f"\n📖 Reading CVE list from: {cve_list_file}")
        with open(cve_list_file, 'r', encoding='utf-8') as f:
            cve_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"   Found {len(cve_list):,} CVEs to process")

        # 准备数据结构
        all_sources = list(self.data_sources_more.keys())

        # 创建结果列表：每行是 [cve_id, source1_json, source2_json, ...]
        data_rows = []

        # 批量提取
        print(f"\n🔄 Processing CVEs...")

        for idx, cve_id in enumerate(cve_list, 1):
            print("=============" + cve_id + "===================")
            if idx % 100 == 0:
                print(f"   Progress: {idx}/{len(cve_list)} ({idx / len(cve_list) * 100:.1f}%)")

            row = {'CVE_ID': cve_id}

            # 对每个数据源尝试提取
            for source_name in all_sources:
                try:
                    raw_data = self.extract_cve_data(cve_id, source_name)

                    if raw_data:
                        # 映射到统一schema
                        try:
                            unified_data = self.map_to_unified_schema(raw_data, source_name)
                            # 将JSON转为字符串存储
                            row[source_name] = json.dumps(unified_data, ensure_ascii=False)
                        except Exception as e:
                            row[source_name] = json.dumps({
                                'error': 'mapping_failed',
                                'message': str(e)
                            })
                    else:
                        row[source_name] = json.dumps({'error': 'not_found'})

                except Exception as e:
                    row[source_name] = json.dumps({
                        'error': 'extraction_failed',
                        'message': str(e)
                    })

            data_rows.append(row)

        print(f"\n✓ Processing complete!")

        # 转换为DataFrame
        print(f"\n📊 Creating CSV with JSON results...")
        df = pd.DataFrame(data_rows)

        # 确保列顺序：CVE_ID在前，然后按数据库顺序
        columns = ['CVE_ID'] + all_sources
        df = df[columns]

        # 保存CSV
        df.to_csv(output_csv, index=False)
        print(f"   ✓ Saved to: {output_csv}")
        print(f"   Size: {Path(output_csv).stat().st_size / 1024 / 1024:.2f} MB")

        # 打印统计信息
        print(f"\n" + "=" * 70)
        print("Statistics")
        print("=" * 70)

        # 统计成功率
        print(f"\nExtraction Success Rate:")
        for source in all_sources:
            # 解析JSON检查是否有error字段
            success_count = 0
            for json_str in df[source]:
                try:
                    data = json.loads(json_str)
                    if 'error' not in data:
                        success_count += 1
                except:
                    pass

            percentage = success_count / len(df) * 100
            print(f"   {source:15s}: {success_count:5,}/{len(df):,} ({percentage:5.1f}%)")

        # 总体统计
        total_cells = len(df) * len(all_sources)
        total_success = sum(
            1 for col in all_sources for json_str in df[col]
            if 'error' not in json.loads(json_str)
        )
        print(f"\nOverall:")
        print(f"   Total cells: {total_cells:,}")
        print(f"   Successful extractions: {total_success:,} ({total_success / total_cells * 100:.1f}%)")

        return df

    def batch_extract_to_csv(self, cve_list_file: str, output_csv: str = 'cve_database_results.csv') -> pd.DataFrame:
        """
        批量提取CVE数据并将JSON结果存储到CSV（支持增量更新和流式写入）

        Args:
            cve_list_file: CVE列表文件路径（每行一个CVE ID）
            output_csv: 输出CSV文件路径

        Returns:
            DataFrame containing the JSON results
        """
        import pandas as pd
        from pathlib import Path
        import json

        print("\n" + "=" * 70)
        print("Batch Extraction to CSV (JSON Results - Incremental)")
        print("=" * 70)

        # 读取CVE列表
        print(f"\n📖 Reading CVE list from: {cve_list_file}")
        with open(cve_list_file, 'r', encoding='utf-8') as f:
            cve_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"   Found {len(cve_list):,} CVEs to process")

        # 准备数据结构
        all_sources = list(self.data_sources_more.keys())

        # === 1. 检查现有文件，读取已处理的CVE ID ===
        existing_cves = set()
        file_exists = Path(output_csv).exists()

        if file_exists:
            print(f"\n📂 Existing file found: {output_csv}")
            try:
                # 只读取CVE_ID列，节省内存
                existing_df = pd.read_csv(output_csv, usecols=['CVE_ID'])
                existing_cves = set(existing_df['CVE_ID'].tolist())
                print(f"   Already processed: {len(existing_cves):,} CVEs")
            except Exception as e:
                print(f"   ⚠ Warning: Could not read existing file: {e}")
                print(f"   Will create new file")
                file_exists = False
        else:
            print(f"\n📄 Creating new file: {output_csv}")

        # 过滤出需要处理的CVE
        cves_to_process = [cve for cve in cve_list if cve not in existing_cves]

        if not cves_to_process:
            print(f"\n✅ All CVEs already processed! Nothing to do.")
            return pd.read_csv(output_csv)

        print(f"   Need to process: {len(cves_to_process):,} CVEs")
        print(f"   Skipping: {len(cve_list) - len(cves_to_process):,} CVEs (already done)")

        # === 2. 边解析边写入 ===
        print(f"\n🔄 Processing CVEs (streaming mode)...")

        processed_count = 0
        success_stats = {source: 0 for source in all_sources}

        # 打开文件准备追加
        mode = 'a' if file_exists else 'w'
        write_header = not file_exists

        with open(output_csv, mode, encoding='utf-8', newline='') as f:
            import csv

            # 创建CSV writer
            columns = ['CVE_ID'] + all_sources
            writer = csv.DictWriter(f, fieldnames=columns)

            # 如果是新文件，写入表头
            if write_header:
                writer.writeheader()

            # 逐个处理CVE
            for idx, cve_id in enumerate(cves_to_process, 1):
                # 每10个CVE显示一次进度
                if idx % 10 == 0 or idx == 1:
                    print(
                        f"   Progress: {idx}/{len(cves_to_process)} ({idx / len(cves_to_process) * 100:.1f}%) - {cve_id}")

                row = {'CVE_ID': cve_id}

                # 对每个数据源尝试提取
                for source_name in all_sources:
                    try:
                        raw_data = self.extract_cve_data(cve_id, source_name)

                        if raw_data:
                            # 映射到统一schema
                            try:
                                unified_data = self.map_to_unified_schema(raw_data, source_name)
                                # 将JSON转为字符串存储
                                row[source_name] = json.dumps(unified_data, ensure_ascii=False)
                                success_stats[source_name] += 1
                            except Exception as e:
                                row[source_name] = json.dumps({
                                    'error': 'mapping_failed',
                                    'message': str(e)
                                })
                        else:
                            row[source_name] = json.dumps({'error': 'not_found'})

                    except Exception as e:
                        row[source_name] = json.dumps({
                            'error': 'extraction_failed',
                            'message': str(e)
                        })

                # 立即写入CSV（不缓存）
                writer.writerow(row)
                f.flush()  # 强制刷新到磁盘
                processed_count += 1

                # 每100个CVE保存一次检查点
                if idx % 100 == 0:
                    print(f"   ✓ Checkpoint: {processed_count} CVEs written to disk")

        print(f"\n✓ Processing complete!")
        print(f"   Newly processed: {processed_count:,} CVEs")
        print(f"   Total in file: {len(existing_cves) + processed_count:,} CVEs")

        # === 3. 读取完整文件并统计 ===
        print(f"\n📊 Loading final results...")
        df = pd.read_csv(output_csv)

        print(f"   ✓ Loaded: {len(df):,} rows")
        print(f"   Size: {Path(output_csv).stat().st_size / 1024 / 1024:.2f} MB")

        # 打印统计信息（仅针对新处理的CVE）
        print(f"\n" + "=" * 70)
        print("Statistics (Newly Processed CVEs)")
        print("=" * 70)

        print(f"\nExtraction Success Rate:")
        for source in all_sources:
            total_new = len(cves_to_process)
            success = success_stats[source]
            percentage = success / total_new * 100 if total_new > 0 else 0
            print(f"   {source:15s}: {success:5,}/{total_new:,} ({percentage:5.1f}%)")

        # 总体统计
        total_cells_new = len(cves_to_process) * len(all_sources)
        total_success_new = sum(success_stats.values())
        print(f"\nOverall (New):")
        print(f"   Total cells: {total_cells_new:,}")
        print(f"   Successful extractions: {total_success_new:,} ({total_success_new / total_cells_new * 100:.1f}%)")

        return df

    def batch_extract_to_csv_with_resume(self, cve_list_file: str, output_csv: str = 'cve_database_results.csv',
                                         checkpoint_interval: int = 50) -> pd.DataFrame:
        """
        批量提取CVE数据并将JSON结果存储到CSV（支持断点续传）

        特性：
        1. 自动跳过已处理的CVE
        2. 边解析边写入，内存占用小
        3. 定期保存检查点
        4. 可以随时中断，下次继续

        Args:
            cve_list_file: CVE列表文件路径（每行一个CVE ID）
            output_csv: 输出CSV文件路径
            checkpoint_interval: 检查点间隔（每N个CVE保存一次）

        Returns:
            DataFrame containing the JSON results
        """
        import pandas as pd
        from pathlib import Path
        import json
        import csv
        from datetime import datetime

        print("\n" + "=" * 70)
        print("Batch Extraction to CSV (Resumable Mode)")
        print("=" * 70)

        # 读取CVE列表
        print(f"\n📖 Reading CVE list from: {cve_list_file}")
        with open(cve_list_file, 'r', encoding='utf-8') as f:
            cve_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"   Found {len(cve_list):,} CVEs to process")

        # 准备数据结构
        all_sources = list(self.data_sources_more.keys())
        columns = ['CVE_ID'] + all_sources

        # 检查现有进度
        existing_cves = set()
        file_exists = Path(output_csv).exists()

        if file_exists:
            print(f"\n📂 Resuming from existing file: {output_csv}")
            try:
                existing_df = pd.read_csv(output_csv, usecols=['CVE_ID'])
                existing_cves = set(existing_df['CVE_ID'].tolist())
                print(f"   Already processed: {len(existing_cves):,} CVEs")

                # 验证文件完整性
                file_size = Path(output_csv).stat().st_size / 1024 / 1024
                print(f"   File size: {file_size:.2f} MB")
            except Exception as e:
                print(f"   ⚠ Error reading file: {e}")
                backup_name = f"{output_csv}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                print(f"   Creating backup: {backup_name}")
                Path(output_csv).rename(backup_name)
                file_exists = False
                existing_cves = set()

        # 计算需要处理的CVE
        cves_to_process = [cve for cve in cve_list if cve not in existing_cves]

        if not cves_to_process:
            print(f"\n✅ All {len(cve_list):,} CVEs already processed!")
            return pd.read_csv(output_csv)

        print(f"\n📋 Task summary:")
        print(f"   Total CVEs: {len(cve_list):,}")
        print(f"   Already done: {len(existing_cves):,} ({len(existing_cves) / len(cve_list) * 100:.1f}%)")
        print(f"   To process: {len(cves_to_process):,} ({len(cves_to_process) / len(cve_list) * 100:.1f}%)")

        # 开始处理
        print(f"\n🔄 Starting extraction (checkpoint every {checkpoint_interval} CVEs)...")
        start_time = datetime.now()

        processed_count = 0
        success_stats = {source: 0 for source in all_sources}
        error_log = []

        # 流式写入模式
        mode = 'a' if file_exists else 'w'
        write_header = not file_exists

        try:
            with open(output_csv, mode, encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=columns)

                if write_header:
                    writer.writeheader()

                for idx, cve_id in enumerate(cves_to_process, 1):
                    # 进度显示
                    if idx % 10 == 0 or idx == 1:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        speed = idx / elapsed if elapsed > 0 else 0
                        eta = (len(cves_to_process) - idx) / speed if speed > 0 else 0
                        print(
                            f"   [{idx}/{len(cves_to_process)}] {cve_id} - {speed:.1f} CVE/s - ETA: {eta / 60:.1f}min")

                    row = {'CVE_ID': cve_id}
                    cve_has_error = False

                    # 提取数据
                    for source_name in all_sources:
                        try:
                            raw_data = self.extract_cve_data(cve_id, source_name)

                            if raw_data:
                                try:
                                    unified_data = self.map_to_unified_schema(raw_data, source_name)
                                    row[source_name] = json.dumps(unified_data, ensure_ascii=False)
                                    success_stats[source_name] += 1
                                except Exception as e:
                                    row[source_name] = json.dumps({
                                        'error': 'mapping_failed',
                                        'message': str(e)
                                    })
                                    cve_has_error = True
                            else:
                                row[source_name] = json.dumps({'error': 'not_found'})

                        except Exception as e:
                            row[source_name] = json.dumps({
                                'error': 'extraction_failed',
                                'message': str(e)
                            })
                            cve_has_error = True

                    # 写入
                    writer.writerow(row)
                    processed_count += 1

                    # 检查点
                    if idx % checkpoint_interval == 0:
                        f.flush()  # 刷新到磁盘
                        print(f"   💾 Checkpoint: {processed_count} CVEs saved")

                    # 记录有错误的CVE
                    if cve_has_error:
                        error_log.append(cve_id)

            print(f"\n✅ Extraction complete!")

        except KeyboardInterrupt:
            print(f"\n⚠️  Interrupted by user!")
            print(f"   Processed: {processed_count}/{len(cves_to_process)} CVEs")
            print(f"   Progress saved to: {output_csv}")
            print(f"   You can resume by running the same command again")
            raise

        except Exception as e:
            print(f"\n❌ Error occurred: {e}")
            print(f"   Processed: {processed_count}/{len(cves_to_process)} CVEs before error")
            print(f"   Progress saved to: {output_csv}")
            raise

        # 完成统计
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n⏱️  Time elapsed: {elapsed / 60:.1f} minutes")
        print(f"   Average speed: {processed_count / elapsed:.2f} CVE/s")
        print(f"   Newly processed: {processed_count:,} CVEs")

        # 加载最终结果
        print(f"\n📊 Loading final results...")
        df = pd.read_csv(output_csv)

        file_size = Path(output_csv).stat().st_size / 1024 / 1024
        print(f"   Total CVEs: {len(df):,}")
        print(f"   File size: {file_size:.2f} MB")

        # 详细统计
        print(f"\n" + "=" * 70)
        print("Detailed Statistics")
        print("=" * 70)

        print(f"\n[Newly Processed - {len(cves_to_process):,} CVEs]")
        print(f"{'Database':<15} {'Success':<10} {'Rate':<10}")
        print("-" * 70)

        for source in all_sources:
            success = success_stats[source]
            rate = success / len(cves_to_process) * 100 if cves_to_process else 0
            print(f"{source:<15} {success:<10,} {rate:<10.1f}%")

        total_success_new = sum(success_stats.values())
        total_cells_new = len(cves_to_process) * len(all_sources)
        print(f"\n{'Overall':<15} {total_success_new:<10,} {total_success_new / total_cells_new * 100:<10.1f}%")

        # 错误报告
        if error_log:
            print(f"\n⚠️  CVEs with errors: {len(error_log)}")
            print(f"   (See details in the CSV file)")

        return df



    def batch_extract_detailed(self, cve_list_file: str, output_dir: str = 'batch_output') -> Dict[
        str, Dict[str, bool]]:
        """
        批量提取CVE数据并保存详细的JSON文件

        Args:
            cve_list_file: CVE列表文件路径
            output_dir: 输出目录

        Returns:
            Dict mapping CVE_ID -> {source_name: success_status}
        """
        from pathlib import Path

        print("\n" + "=" * 70)
        print("Batch Detailed Extraction")
        print("=" * 70)

        # 读取CVE列表
        print(f"\n📖 Reading CVE list from: {cve_list_file}")
        with open(cve_list_file, 'r', encoding='utf-8') as f:
            cve_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"   Found {len(cve_list):,} CVEs to process")

        # 创建输出目录
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # 批量提取
        all_sources = list(self.data_sources_more.keys())
        results = {}

        print(f"\n🔄 Extracting data for {len(cve_list)} CVEs across {len(all_sources)} sources...")

        for idx, cve_id in enumerate(cve_list, 1):
            if idx % 50 == 0:
                print(f"   Progress: {idx}/{len(cve_list)} ({idx / len(cve_list) * 100:.1f}%)")

            results[cve_id] = {}

            for source_name in all_sources:
                success = self.extract_and_map(cve_id, source_name, output_dir=output_dir)
                results[cve_id][source_name] = success

        print(f"\n✓ Extraction complete!")

        # 保存摘要
        summary_file = output_path / 'extraction_summary.json'
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"   ✓ Summary saved to: {summary_file}")

        return results


def main0():
    """主函数"""
    import sys

    mapper = VulnerabilityDataMapper()

    # 检查命令行参数
    if len(sys.argv) > 1:
        mode = sys.argv[1]

        if mode == 'single':
            # 单个CVE提取模式
            if len(sys.argv) < 4:
                print("Usage: python extract_vuln_data.py single <CVE_ID> <SOURCE_NAME>")
                print("\nAvailable sources:")
                for source in mapper.data_sources_more.keys():
                    print(f"  - {source}")
                print("\nExample: python extract_vuln_data.py single CVE-2013-2824 CVE")
                return

            cve_id = sys.argv[2]
            source_name = sys.argv[3]

            if source_name not in mapper.data_sources_more:
                print(f"错误: 未知数据源 '{source_name}'")
                print("可用数据源:", ', '.join(mapper.data_sources_more.keys()))
                return

            mapper.extract_and_map(cve_id, source_name)

        elif mode == 'batch':
            # 批量提取模式
            if len(sys.argv) < 3:
                print("Usage: python extract_vuln_data.py batch <CVE_LIST_FILE> [OUTPUT_CSV]")
                print("\nExample: python extract_vuln_data.py batch layer1_high_quality_core.txt cve_matrix.csv")
                return

            cve_list_file = sys.argv[2]
            output_csv = sys.argv[3] if len(sys.argv) > 3 else 'cve_database_matrix.csv'

            # 执行批量提取
            df = mapper.batch_extract_and_aggregate(cve_list_file, output_csv)

            # 可选：也生成详细的JSON文件
            generate_detailed = input("\n生成详细的JSON文件? (y/n): ").lower() == 'y'
            if generate_detailed:
                mapper.batch_extract_detailed(cve_list_file, output_dir='batch_output')

        elif mode == 'batch-detailed':
            # 仅生成详细JSON模式
            if len(sys.argv) < 3:
                print("Usage: python extract_vuln_data.py batch-detailed <CVE_LIST_FILE> [OUTPUT_DIR]")
                return

            cve_list_file = sys.argv[2]
            output_dir = sys.argv[3] if len(sys.argv) > 3 else 'batch_output'

            mapper.batch_extract_detailed(cve_list_file, output_dir)

        else:
            print(f"错误: 未知模式 '{mode}'")
            print("可用模式: single, batch, batch-detailed")

    else:
        # 默认：演示单个CVE
        print("=" * 70)
        print("Demo: Single CVE Extraction")
        print("=" * 70)

        cve_id = "CVE-1999-0767"
        source_name = "EDB"

        print(f"\nExtracting {cve_id} from {source_name}...")
        mapper.extract_and_map(cve_id, source_name)

        print("\n" + "=" * 70)
        print("For batch processing, use:")
        print("  python extract_vuln_data.py batch layer1_high_quality_core.txt")
        print("=" * 70)

# 使用示例函数
def resume_extraction_example():
        """演示如何使用断点续传功能"""
        mapper = VulnerabilityDataMapper()

        # 第一次运行（或继续之前的进度）
        try:
            # df = mapper.batch_extract_to_csv_with_resume(
            #     cve_list_file='./multiDBs/sampling_results/layer1_high_quality_core.txt',
            #     output_csv='./multiDBs/output/cve_results.csv',
            #     checkpoint_interval=50  # 每50个CVE保存一次
            # )
            df = mapper.batch_extract_to_csv_with_resume(
                cve_list_file='./sampling_results_more/layer1_high_quality_core_more_16.txt',
                output_csv='./output/cve_results_core_more_16.csv',
                checkpoint_interval=50  # 每50个CVE保存一次
            )
            # df = mapper.batch_extract_to_csv_with_resume(
            #     cve_list_file='./multiDBs/sampling_results_more/single_db_total.txt',
            #     output_csv='./multiDBs/output/cve_results_dbs.csv',
            #     checkpoint_interval=50  # 每50个CVE保存一次
            # )
            print("\n✅ All done!")

        except KeyboardInterrupt:
            print("\n⏸️  Paused. Run again to resume.")

        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("   Fix the error and run again to resume.")
def main():
    import sys

    mapper = VulnerabilityDataMapper()

    # # Example usage
    # if len(sys.argv) < 3:
    #     print("Usage: python extract_vuln_data.py <CVE_ID> <SOURCE_NAME>")
    #     print("\nAvailable sources:")
    #     for source in mapper.data_sources.keys():
    #         print(f"  - {source}")
    #     print("\nExample: python extract_vuln_data.py CVE-2013-2824 CVE")
    #     return
    #
    # cve_id = sys.argv[1]
    # source_name = sys.argv[2]


    # single
    # cve_id = "CVE-1999-0767"
    # source_name = "EDB"
    #
    # if source_name not in mapper.data_sources:
    #     print(f"错误: 未知数据源 '{source_name}'")
    #     print("可用数据源:", ', '.join(mapper.data_sources.keys()))
    #     return
    #
    # mapper.extract_and_map(cve_id, source_name)

    # mode == 'batch'
    cve_list_file = "sampling_results/layer1_high_quality_core.txt"
    # cve_list_file = "sampling_results/test.txt"
    output_csv = "output/cve_matrix.csv"

    # 执行批量提取
    df = mapper.batch_extract_to_csv(cve_list_file, output_csv)
    print("\n" + "=" * 70)
    print("✅ Extraction complete!")
    print("=" * 70)
    print(f"\n📄 CSV file: {output_csv}")
    print(f"   Rows: {len(df):,}")
    print(f"   Columns: {len(df.columns)}")


if __name__ == '__main__':
    # main()
    resume_extraction_example()


    # examples

    # cve_id = 'CVE-2025-10966'
    # source_name = 'Curl'
    # mapper = VulnerabilityDataMapper()
    # raw_data = mapper.extract_cve_data(cve_id, source_name)
    # print(raw_data)
    #
    # unified_data = mapper.map_to_unified_schema(raw_data, source_name)
    # row = json.dumps(unified_data, ensure_ascii=False)
    # print(row)