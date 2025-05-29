from collections import defaultdict

def build_known_info(field_list, has_fields):
    prompt_input = defaultdict(dict)
    for vuln_id in has_fields:
        known_info = ""
        for field in has_fields[vuln_id]:
            known_info += f"And the information of {field} is ({has_fields[vuln_id].get(field, '')}). "
        prompt_input[vuln_id]['known_info'] = known_info.strip()
    return prompt_input