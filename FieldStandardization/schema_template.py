"""
Schema Template for Vulnerability Data

Defines the complete 24-field vulnerability data structure with default values.
Based on the unified vulnerability schema specification.
"""

from typing import Dict, Any
import copy

# Complete vulnerability schema template with default values (24 fields)
SCHEMA_TEMPLATE: Dict[str, Any] = {
    # 1. Identifiers
    "id": None,
    
    # 2. Source metadata
    "source": {
        "provider": None,
        "reporter": None,
        "category": None
    },
    
    # 3-4. Basic information
    "title": None,
    "description": [],
    
    # 5-9. Timeline
    "timeline": [],
    "published": None,
    "modified": None,
    "withdrawn": None,
    "vuln_status": "published",
    
    # 10-11. Related identifiers
    "aliases": [],
    "related": [],
    
    # 12-13. Classification
    "weaknesses": [],
    "severity": [],
    
    # 14-15. Impact and exploitation
    "impacts": [],
    "exploitation": {
        "exploits": [],
        "epss": []
    },
    
    # 16-17. References
    "references": [],
    "primary_urls": [],
    
    # 18-19. Affected systems
    "affected": [],
    "cpe_configurations": [],
    
    # 20. Remediation
    "remediation": {
        "solutions": [],
        "workarounds": [],
        "fixed_versions": []
    },
    
    # 21-24. Metadata
    "vendor_comments": [],
    "acknowledgements": [],
    "tags": [],
    "copyrights": []
}


def get_empty_schema() -> Dict[str, Any]:
    """
    Get a fresh copy of the empty schema template.
    
    Returns:
        Deep copy of schema template with all default values
    """
    return copy.deepcopy(SCHEMA_TEMPLATE)


# Field names list for reference
ALL_FIELD_NAMES = list(SCHEMA_TEMPLATE.keys())
