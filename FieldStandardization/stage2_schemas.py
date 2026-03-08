"""
Stage 2: Detailed Field Schemas

Complete schema definitions for all 24 fields with sub-field structures.
Used in Stage 2 for detailed extraction of each field.
"""

# Due to length, schemas are defined as module-level constants

ID_SCHEMA = """Extract 'id' field:
{
  "id": string (required)
}

Type: string, Format: ^[A-Za-z0-9._:-]+$
Definition: Unique vulnerability identifier
Priority: CVE > GHSA > RUSTSEC > OSV > source-scoped ID
Rules:
- CVE ID available → use CVE ID
- Otherwise → use native ID (GHSA, RUSTSEC, OSV)
- Internal only → prefix with source (e.g., "wordfence:<uuid>")
Examples: "CVE-2024-38077", "GHSA-232P-VWFF-86MP", "wordfence:848ccbdc-c6f1..."
"""

SOURCE_SCHEMA = """Extract 'source' field:
{
  "source": {
    "provider": string or null,
    "reporter": string or null,
    "category": string or null
  }
}

Sub-fields:
provider: Primary data source - "CVE"|"NVD"|"OSV"|"RedHat"|"Wordfence"|"RustSec"|"Vulners"|"GitHub"|"Vendor"|"Internal" or null
reporter: Individual/org who reported (free text) or null
category: Document type - "advisory"|"cve-record"|"database-entry"|"bug-bounty"|"exploit"|"scanner"|"news"|"blog"|"info" or null
"""

TITLE_SCHEMA = """Extract 'title' field:
{
  "title": string or null
}

Type: string or null, Length: 1-256 chars
Definition: Short summary (1 sentence) describing vulnerability
If not explicit: generate from description
Use null if cannot generate
"""

DESCRIPTION_SCHEMA = """Extract 'description' field:
{
  "description": [
    {
      "lang": string (required, BCP47 code, default "en"),
      "value": string (required, ≤4096 chars, vulnerability explanation),
      "format": string (optional, "text"|"markdown"|"html", default "text"),
      "media": array (optional, supporting media, use [] if none)
    }
  ]
}

Minimum 1 entry required
media object: {"type": string (IANA), "base64": boolean, "value": string (≤16384)}
"""

TIMELINE_SCHEMA = """Extract 'timeline' field:
{
  "timeline": [
    {
      "time": string (required, ISO 8601 UTC),
      "description": string (required, event description),
      "source": string (optional, event source),
      "lang": string (optional, BCP47, default "en")
    }
  ]
}

Use empty array [] if no timeline events
"""

PUBLISHED_SCHEMA = """Extract 'published' field:
{
  "published": string or null
}

Format: ISO 8601 UTC (YYYY-MM-DDThh:mm:ssZ)
Normalize: Date-only → append T00:00:00Z
Example: "2024-07-09T17:15:42Z"
"""

MODIFIED_SCHEMA = """Extract 'modified' field:
{
  "modified": string or null
}

Format: ISO 8601 UTC (YYYY-MM-DDThh:mm:ssZ)
Same normalization as published
"""

WITHDRAWN_SCHEMA = """Extract 'withdrawn' field:
{
  "withdrawn": string or null
}

Format: ISO 8601 UTC (YYYY-MM-DDThh:mm:ssZ)
Use null if not withdrawn
"""

VULN_STATUS_SCHEMA = """Extract 'vuln_status' field:
{
  "vuln_status": string
}

Enum: "published"|"rejected"|"analyzing"|"modified"|"unknown"
Default: "published"
"""

ALIASES_SCHEMA = """Extract 'aliases' field:
{
  "aliases": [string, ...]
}

Array of alternative identifiers (CVE, GHSA, OSV, RUSTSEC, etc.)
Use empty array [] if none
"""

RELATED_SCHEMA = """Extract 'related' field:
{
  "related": [string, ...]
}

Array of related (not equivalent) vulnerability IDs
Use empty array [] if none
"""

WEAKNESSES_SCHEMA = """Extract 'weaknesses' field:
{
  "weaknesses": [
    {
      "id": string (required, e.g., "CWE-79", "crypto-failure", "A01:2021"),
      "taxonomy": string (required, "CWE"|"RustSecCategory"|"OWASP"|"Text"|"Other"),
      "name": string or null (weakness title),
      "description": string or null (explanation),
      "source": string or null ("CVE"|"NVD"|"RedHat"|"Wordfence"|"RustSec"|"Vulners"|"Internal")
    }
  ]
}

Use empty array [] if no weaknesses
"""

SEVERITY_SCHEMA = """Extract 'severity' field:
{
  "severity": [
    {
      "source": string (required, "CVE"|"NVD"|"OSV"|"RedHat"|"Wordfence"|"RustSec"|"Vulners"|"Ubuntu"|"Internal"),
      "scheme": string (required, "CVSS:2.0"|"CVSS:3.0"|"CVSS:3.1"|"CVSS:4.0"|"RedHat:ThreatSeverity"|"Ubuntu"|"Other"),
      "score": number or null (0.0-10.0 for CVSS, null for non-numeric),
      "vector": string or null (CVSS vector like "CVSS:3.1/AV:N/AC:L/..."),
      "rating": string or null ("NONE"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL" or vendor-specific)
    }
  ]
}

Use empty array [] if no severity ratings
"""

IMPACTS_SCHEMA = """Extract 'impacts' field:
{
  "impacts": [
    {
      "source": string (required, provider of impact description),
      "lang": string (required, BCP47, default "en"),
      "text": string (required, ≤4096 chars, impact description),
      "capec_id": string or null ("CAPEC-" + digits)
    }
  ]
}

Use empty array [] if none
"""

EXPLOITATION_SCHEMA = """Extract 'exploitation' field:
{
  "exploitation": {
    "exploits": [
      {
        "source": string (required),
        "lang": string (required, default "en"),
        "text": string (required, ≤4096 chars),
        "links": [string, ...] (URLs, use [] if none)
      }
    ],
    "epss": [
      {
        "source": string (required, e.g., "Vulners", "FIRST-EPSS"),
        "cve_id": string (required, ^CVE-[0-9]{4}-[0-9]{4,19}$),
        "score": number (required, 0.0-1.0),
        "percentile": number or null (0.0-1.0),
        "last_updated": string (required, YYYY-MM-DD)
      }
    ]
  }
}

Use empty arrays [] for both if none
"""

REFERENCES_SCHEMA = """Extract 'references' field:
{
  "references": [
    {
      "url": string (required, RFC3986 absolute URL),
      "name": string or null (human-readable title),
      "tags": [string, ...] or null ("exploit"|"patch"|"vendor-advisory"|"advisory"|"misc")
    }
  ]
}

Use empty array [] if none
"""

PRIMARY_URLS_SCHEMA = """Extract 'primary_urls' field:
{
  "primary_urls": [
    {
      "source": string (required, "CVE"|"NVD"|"OSV"|"RedHat"|"Wordfence"|"RustSec"|"Vulners"|"GitHub"|"Vendor"|"Other"),
      "url": string (required, primary detail page URL)
    }
  ]
}

Use empty array [] if none
"""

AFFECTED_SCHEMA = """Extract 'affected' field:
{
  "affected": [
    {
      "vendor": string or null (1-512 chars),
      "product": string or null (1-2048 chars),
      "ecosystem": string or null (Package ecosystem identifier: "upstream"|"npm"|"pypi"|"maven"|"nuget"|"crates.io"|"deb"|"rpm"|"docker"|"os"|"rust"|"wordpress-plugin"|"wordpress-theme"),
      "package": string or null,
      "distribution": string or null (Distribution-specific identifier (e.g., "Debian:9", "Ubuntu:20.04", "upstream")),
      "status": string (required, "affected"|"unaffected"|"unknown"),
      "versions": [string, ...] (Array of exact affected version numbers, use [] if none),
      "version_range": [
        {
          "scheme": string (required, "semver"|"rpm"|"deb"|"maven"|"git"|"ecosystem"|"custom"),
          "introduced": string or null,
          "last_affected": string or null,
          "fixed": string or null,
          "limit": string or null,
          "status": string (required, "affected"|"unaffected"|"unknown")
        }
      ],
      "repo": string or null (Git repo URL),
      "cpe": string or null (CPE 2.2 or 2.3),
      "purl": string or null (Package URL),
      "os": [string, ...] (OS names, use [] if none),
      "os_version": [string, ...] (use [] if none),
      "arch": [string, ...] (CPU archs, use [] if none),
      "platform": [string, ...] (runtime platforms, use [] if none),
      "modules": [string, ...] (affected modules, use [] if none),
      "files": [string, ...] (source files, use [] if none),
      "functions": [string, ...] (function/method names, use [] if none)
    }
  ]
}

Use empty array [] if no affected items

Example:
**versions vs version_range - Use BOTH when available:**

If text says: "Versions 2.1.3 and 2.1.4 are affected, all versions before 2.1.5"
Extract as:
  "versions": ["2.1.3", "2.1.4"],
  "version_range": [
        {
          "scheme": "semver",
          "introduced": "0",
          "last_affected": null,
          "fixed": "2.1.5",
          "limit": null,
          "status": "affected"
        }
      ]
If text says only:  "1.1.0 through 1.1.4 contain a vulnerability; 1.0 and earlier are not affected"
Extract as:
  "versions": [],
  "version_range": [
        {
          "scheme": "semver",
          "introduced": "1.1.0",
          "last_affected": "1.1.4",
          "fixed": null,
          "limit": null,
          "status": "affected"
        },
        {
          "scheme": "semver",
          "introduced": "0",
          "last_affected": "1.0",
          "fixed": null,
          "limit": null,
          "status": "unaffected"
        }
      ]

If text says only: "< 1.0 || >= 2.0, <= 2.5"
Extract as:
  "versions": [],
  "version_range": [
        {
          "scheme": "semver",
          "introduced": "0",
          "last_affected": null,
          "fixed": "1.0",
          "limit": null,
          "status": "affected"
        },
        {
          "scheme": "semver",
          "introduced": "2.0",
          "last_affected": "2.5",
          "fixed": null,
          "limit": null,
          "status": "affected"
        }
      ]

Description: "Mailman before 2.1.5 is affected. Note: Versions apply to upstream mailman 
only. Debian:9 mailman fixed in 2.1.4-5."
Correct extraction:
{
      "vendor": null,
      "product": "mailman",
      "ecosystem": "upstream",
      "package": "mailman",
      "status": "affected",
      "versions": [],
      "version_range": [
        {
          "scheme": "semver",
          "introduced": "0",
          "last_affected": null,
          "fixed": "2.1.5",
          "limit": null,
          "status": "affected"
        }
      ],
      ...
    },
{
      "vendor": null,
      "product": "mailman",
      "ecosystem": "Debian",
      "distribution": "Debian:9",
      "package": "mailman",
      "status": "affected",
      "versions": [],
      "version_range": [
        {
          "scheme": "ecosystem",
          "introduced": "0",
          "last_affected": null,
          "fixed": "2.1.4-5",
          "limit": null,
          "status": "affected"
        }
      ],
      ...
    }
"""

CPE_CONFIGURATIONS_SCHEMA = """Extract 'cpe_configurations' field:
{
  "cpe_configurations": [
    {
      "source": string (required, "cna"|"nvd"|"vulners"|other),
      "operator": string (required, "AND"|"OR"),
      "negate": boolean (required, false=normal, true=inverted),
      "nodes": [
        {
          "operator": string (required, "AND"|"OR"),
          "negate": boolean (required),
          "cpeMatch": [
            {
              "vulnerable": boolean (required, true=vulnerable, false=exclusion),
              "criteria": string (required, CPE 2.3),
              "matchCriteriaId": string (required, UUID or ID),
              "versionStartIncluding": string or null,
              "versionStartExcluding": string or null,
              "versionEndIncluding": string or null,
              "versionEndExcluding": string or null,
              "provider": string or null
            }
          ],
          "nodes": [nested nodes...] (optional)
        }
      ]
    }
  ]
}

Use empty array [] if none
Complex nested structure - extract carefully
"""

REMEDIATION_SCHEMA = """Extract 'remediation' field:
{
  "remediation": {
    "solutions": [
      {
        "lang": string (required, BCP47, default "en"),
        "value": string (required, ≤4096 chars, formal fix description),
        "supportingMedia": [
          {
            "type": string (required, IANA media type, 1-256 chars),
            "base64": boolean (required, default false),
            "value": string (required, ≤16384 chars)
          }
        ] (use [] if none)
      }
    ],
    "workarounds": [
      {
        "lang": string (required),
        "value": string (required, ≤4096 chars, temporary mitigation),
        "supportingMedia": [same structure as solutions]
      }
    ],
    "fixed_versions": [string, ...] (version specifiers like "1.2.4", ">=1.2.4", use [] if none)
  }
}

Use empty arrays [] for all if none
"""

VENDOR_COMMENTS_SCHEMA = """Extract 'vendor_comments' field:
{
  "vendor_comments": [
    {
      "source": string or null (org/individual name),
      "comment": string (required, vendor statement),
      "time": string or null (ISO 8601 UTC)
    }
  ]
}

Use empty array [] if none
"""

ACKNOWLEDGEMENTS_SCHEMA = """Extract 'acknowledgements' field:
{
  "acknowledgements": [
    {
      "name": string (required, person/org/tool name),
      "type": string or null ("finder"|"reporter"|"analyst"|"coordinator"|"remediation_developer"|"remediation_reviewer"|"remediation_verifier"|"tool"|"sponsor"|"other"),
      "contact": [string, ...] or null (emails, URLs, social handles),
      "lang": string or null (BCP47),
      "uuid": string or null (UUID v4)
    }
  ]
}

Use empty array [] if none
"""

TAGS_SCHEMA = """Extract 'tags' field:
{
  "tags": [
    {
      "description": string (required, 1-256 chars, tag text),
      "source": string (required, "CNA"|"NVD"|"OSV"|"RedHat"|"Wordfence"|"RustSec"|"Vulners"|"Internal"|other)
    }
  ]
}

Use empty array [] if none
Recommend lowercase or kebab-case
"""

COPYRIGHTS_SCHEMA = """Extract 'copyrights' field:
{
  "copyrights": [
    {
      "source": string (required, "MITRE"|"Wordfence"|"RustSec"|"Vendor"|other),
      "message": string or null (explanatory text),
      "notice": string or null (formal copyright notice),
      "license": string or null (SPDX Identifier or license name),
      "license_url": string or null (RFC3986 URL)
    }
  ]
}

Use empty array [] if none
"""

# Mapping from field name to schema
STAGE2_FIELD_SCHEMAS = {
    "id": ID_SCHEMA,
    "source": SOURCE_SCHEMA,
    "title": TITLE_SCHEMA,
    "description": DESCRIPTION_SCHEMA,
    "timeline": TIMELINE_SCHEMA,
    "published": PUBLISHED_SCHEMA,
    "modified": MODIFIED_SCHEMA,
    "withdrawn": WITHDRAWN_SCHEMA,
    "vuln_status": VULN_STATUS_SCHEMA,
    "aliases": ALIASES_SCHEMA,
    "related": RELATED_SCHEMA,
    "weaknesses": WEAKNESSES_SCHEMA,
    "severity": SEVERITY_SCHEMA,
    "impacts": IMPACTS_SCHEMA,
    "exploitation": EXPLOITATION_SCHEMA,
    "references": REFERENCES_SCHEMA,
    "primary_urls": PRIMARY_URLS_SCHEMA,
    "affected": AFFECTED_SCHEMA,
    "cpe_configurations": CPE_CONFIGURATIONS_SCHEMA,
    "remediation": REMEDIATION_SCHEMA,
    "vendor_comments": VENDOR_COMMENTS_SCHEMA,
    "acknowledgements": ACKNOWLEDGEMENTS_SCHEMA,
    "tags": TAGS_SCHEMA,
    "copyrights": COPYRIGHTS_SCHEMA
}
