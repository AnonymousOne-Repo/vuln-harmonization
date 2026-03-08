"""
Stage 1: Field Definitions for Text Mapping

Simplified descriptions of all 24 fields for identifying which text segments
correspond to which fields.
"""

from typing import Dict, Any

# Stage 1: All 24 fields with simplified descriptions for text segmentation
STAGE1_FIELD_DEFINITIONS = {
    "id": {
        "description": "Unique vulnerability identifier (CVE, GHSA, RUSTSEC, OSV, etc.)",
        "keywords": ["CVE-", "GHSA-", "RUSTSEC-", "OSV-", "DSA-", "USN-", "ID:", "identifier"],
        "examples": ["CVE-2024-38077", "GHSA-232P-VWFF-86MP", "RUSTSEC-2024-0001"]
    },
    
    "source": {
        "description": "Data source metadata: provider, reporter, document category",
        "keywords": ["reported by", "source:", "provider:", "disclosed by", "advisory", "database", "reporter:"],
        "examples": ["Source: NVD", "Reported by Microsoft", "Vendor advisory"]
    },
    
    "title": {
        "description": "Short summary describing the vulnerability (1 sentence)",
        "keywords": ["vulnerability in", "allows", "flaw", "issue", "security", "title:"],
        "examples": ["Remote code execution in Windows Server", "SQL injection in login API"]
    },
    
    "description": {
        "description": "Detailed explanation of the vulnerability (cause, impact, context)",
        "keywords": ["vulnerability", "allows", "attacker", "exploit", "affects", "caused by", "description:", "details:"],
        "examples": ["A SQL injection vulnerability exists in...", "The flaw allows attackers to..."]
    },
    
    "timeline": {
        "description": "Key lifecycle events with timestamps and descriptions",
        "keywords": ["disclosed", "discovered", "patched", "updated", "event", "milestone"],
        "examples": ["Public disclosure on 2024-07-10", "Patch released on 2024-07-15"]
    },
    
    "published": {
        "description": "First public disclosure date/time (ISO 8601 UTC)",
        "keywords": ["published", "disclosed", "released", "public", "publication date"],
        "examples": ["Published: 2024-07-09 17:15:42", "2024-07-09T17:15:42Z"]
    },
    
    "modified": {
        "description": "Last modification date/time (ISO 8601 UTC)",
        "keywords": ["modified", "updated", "revised", "last update", "last modified"],
        "examples": ["Modified: 2024-12-01", "Last updated: 2024-12-01T10:00:00Z"]
    },
    
    "withdrawn": {
        "description": "Withdrawal/retraction date/time if applicable",
        "keywords": ["withdrawn", "retracted", "revoked", "cancelled", "deprecated"],
        "examples": ["Withdrawn: 2024-05-12", "Retracted on 2024-05-12T09:30:00Z"]
    },
    
    "vuln_status": {
        "description": "Lifecycle status (published, rejected, analyzing, modified, unknown)",
        "keywords": ["status:", "published", "rejected", "analyzing", "modified", "under review"],
        "examples": ["Status: Published", "Status: Rejected", "Analyzing"]
    },
    
    "aliases": {
        "description": "Alternative identifiers for the same vulnerability",
        "keywords": ["also known as", "alias", "equivalent", "same as", "identified as", "aka"],
        "examples": ["Also known as GHSA-xxxx", "Aliases: CVE-2024-1234", "= GHSA-xxxx"]
    },
    
    "related": {
        "description": "Related (but not equivalent) vulnerability identifiers",
        "keywords": ["related to", "linked to", "associated with", "see also", "similar to"],
        "examples": ["Related to CVE-2024-1235", "See also GHSA-yyyy"]
    },
    
    "weaknesses": {
        "description": "Weakness classifications (CWE IDs, categories, OWASP)",
        "keywords": ["CWE-", "weakness", "category", "OWASP", "type", "classification"],
        "examples": ["CWE-79: Cross-site Scripting", "Weakness: SQL Injection", "CWE-89"]
    },
    
    "severity": {
        "description": "Severity scores and ratings (CVSS vectors, vendor ratings)",
        "keywords": ["CVSS:", "severity:", "score:", "rating:", "critical", "high", "medium", "low", "base score"],
        "examples": ["CVSS:3.1/AV:N/AC:L/...", "Severity: Critical", "Score: 9.8", "CVSS Base Score: 9.8"]
    },
    
    "impacts": {
        "description": "Description of potential impact or consequences",
        "keywords": ["impact:", "allows attacker", "results in", "consequences", "effect", "can achieve"],
        "examples": ["Allows remote code execution", "Complete system compromise", "Loss of confidentiality"]
    },
    
    "exploitation": {
        "description": "Exploitation information: available exploits, PoCs, EPSS scores",
        "keywords": ["exploit", "PoC", "proof of concept", "EPSS", "exploitation probability", "metasploit", "exploit-db"],
        "examples": ["Public exploit available", "EPSS score: 0.00053", "PoC code published"]
    },
    
    "references": {
        "description": "External links and resources (advisories, patches, vendor pages)",
        "keywords": ["http://", "https://", "reference:", "see:", "more info:", "advisory:", "link:"],
        "examples": ["https://msrc.microsoft.com/advisory", "Reference: https://...", "See: https://..."]
    },
    
    "primary_urls": {
        "description": "Primary detail page URLs from each platform/source",
        "keywords": ["detail page", "advisory page", "full report", "view at", "source URL"],
        "examples": ["https://vulners.com/cve/CVE-2024-38077", "https://rustsec.org/advisories/..."]
    },
    
    "affected": {
        "description": "Affected products, versions, platforms, packages, OS, architectures",
        "keywords": ["affects", "vulnerable", "product:", "version:", "package:", "platform:", "OS:", "versions:"],
        "examples": ["Affects Windows Server 2019 < 10.0.17763.6054", "Product: example-server", "Package: npm/lodash"]
    },
    
    "cpe_configurations": {
        "description": "CPE configuration trees for precise product/version matching",
        "keywords": ["CPE:", "cpe:2.3:", "configuration", "match criteria", "vulnerable versions"],
        "examples": ["cpe:2.3:o:microsoft:windows_server_2019:*", "CPE Match Criteria"]
    },
    
    "remediation": {
        "description": "Solutions, workarounds, patches, fixed versions",
        "keywords": ["fix", "patch", "upgrade", "update to", "workaround:", "mitigation:", "solution:", "remediation:"],
        "examples": ["Upgrade to version 1.3.0", "Workaround: disable feature", "Fixed in 1.2.4", "Apply patch KB5021233"]
    },
    
    "vendor_comments": {
        "description": "Vendor statements, assessments, or comments",
        "keywords": ["vendor comment:", "vendor states", "statement:", "assessment:", "vendor analysis"],
        "examples": ["Red Hat: Not exploitable under default config", "Vendor statement: ..."]
    },
    
    "acknowledgements": {
        "description": "Credits to researchers, reporters, analysts, coordinators",
        "keywords": ["discovered by", "reported by", "credit:", "thanks to", "acknowledgement:", "finder:"],
        "examples": ["Discovered by Alice Chen", "Credit: Security Research Lab", "Thanks to: ..."]
    },
    
    "tags": {
        "description": "Keywords and classification tags (disputed, informational, etc.)",
        "keywords": ["tag:", "keyword:", "disputed", "informational", "label:", "unsupported"],
        "examples": ["Tag: disputed", "Keywords: ssl, encryption", "Label: informational"]
    },
    
    "copyrights": {
        "description": "Copyright notices, license information, attribution requirements",
        "keywords": ["copyright", "©", "license:", "attribution required", "usage terms"],
        "examples": ["Copyright © 2024 MITRE Corporation", "License: CC-BY-4.0"]
    }
}


# Export for backward compatibility
ALL_FIELD_NAMES = list(STAGE1_FIELD_DEFINITIONS.keys())
