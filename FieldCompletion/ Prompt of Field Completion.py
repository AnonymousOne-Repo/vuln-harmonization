def getInputSimple(fieldList, has_fields, nohas_fields):
    # Building known and missing information

    promptInput = defaultdict(dict)

    for vuln_id in has_fields:
        known_info = ""
        for field in has_fields[vuln_id]:
            known_info += f"And the information of {field} is ({has_fields[vuln_id].get(field, '')})."
            promptInput[vuln_id]['known_info'] = known_info
    return promptInput


def generate_prompt(fieldList, vuln_info_not_full):
    """
    Generate prompts to supplement missing fields based on vulnerability information.

    : paramfieldList: A list containing all field names
    : paramvuln_info_not_full: Contains vulnerability information from different databases (known and missing fields)
    : return: prompt in string format
    """
    has_fields = {}
    nohas_fields = {}

    # Extract existing information and missing fields from fields
    for vuln_id, vuln_data in vuln_info_not_full.items():
        has_fields[vuln_id] = vuln_data['has']
        nohas_fields[vuln_id] = vuln_data['nohas']

    promptInput = getInputSimple(fieldList, has_fields, nohas_fields)

    promptSet = {}
    for vuln_id in promptInput:
    prompt = f"""
    **Known Fields** ({promptInput[vuln_id]["known_info"]}) may include, but is not limited to, the following categories: Title, Weaknesses, Severity, AffectedComponents, impact_info, solution_info, exploit_info, PoC_info, and patch_info. Follow these steps:
    
    1. Categorize the text:
    Split the provided text into phrases, identifying the corresponding categories. 
    
    2. Extract Weakness and Severity:
    (1) For Weakness, extract the CWE ID exactly as mentioned in the text. If no CWE ID is found, leave Weakness as null.
    (2) For Severity, extract the severity level as mentioned in the text, with no assumptions or summarization. If not mentioned, leave Severity as null.
    
    3. Extract Affected Components:
    (1) List all components with their edition, releases, version, vendor, product, module, and ecosystem. More than one component could be mentioned. 
    (2) Different products, editions, or release should be listed as separate components. 
    (3) If no vendor, product, module, or ecosystem is explicitly mentioned, leave this field as null.
    Versions should be categorized as follows:
    (4) If a version range is provided, it should be expressed as an interval (e.g., ">=version1,<version2", "<version3") in affected_range. And handle terms like “to”, “through”, “and earlier/prior to”, “before” as valid intervals, ensuring they are converted to appropriate range format.
    (5) If there is a list of specific versions mentioned rather than a range of versions, it should be listed as an item in affected_version instead of affected_range.
    (6) Affected_range should only contain symbols and versions, while affected_version should only contain version numbers.
    
    4. Summarize Information:
    Summarize the following categories where applicable: Title, impact_info, solution_info, exploit_info, PoC_info, patch_info. If any of these categories are not explicitly mentioned, leave them as null.
    
    5. Verify
    (1) Check if Weakness and Severity actually appear in the text. If not, remove them and leave the fields as null.
    (2) Verify that versions and version ranges are correctly associated with their respective components.
    (3) If an affected_range is provided, ensure that the version range is in valid interval format. If not, convert them to valid interval format (e.g., ">=version1,<version2", "<version3"). If start version equals to end version, convert it to single version and add to "affected_versions".
    
    6. return the results in the following format:
    ```json
    {{
        "VulnFields": {{"Full": {fieldList}, "has": {list(has_fields[vuln_id].keys())}, "nohas": {list(nohas_fields[vuln_id].keys())}}}
        "Title": "Vulnerability Title",
        "Details": "Vulnerability Detailed Description",
        "Weakness": [("CWE ID", "Description")],
        "Severity": "Severity",
        "AffectedComponents": [
        {{
            "vendor": "Vendor Name",
            "product": "Affected Software or Product Name",
            "module": "Affected Specific Package or Library Name",
            "ecosystem": "Software Ecosystem Name",
            "version": {{
                "affected_range": [">=version1,<version2", "<version3"],
                "affected_version": ["version4", "version5"]
            }}
        }}, {{...}}
        ],
        "References": ["Reference Link 1", "Reference Link 2"],
        "Status": {{
            "impact_info": "Impact information",
            "solution_info": "Solution information", 
            "exploit_info": {{"exploits": "Exploit information", "exploit_url": ["Exploit Link 1", "Exploit Link 2"]}},
            "PoC_info": {{"PoC": "PoC information", "exploit_url": ["PoC Link 1", "PoC Link 2"]}},
            "patch_info",: {{"patch": "Patch information", "patch_url": ["Patch Link 1", "Patch Link 2"]}},
        }}
    }}
    """
    promptSet[vuln_id] = prompt
    print(prompt)
return promptSet