from collections import OrderedDict
from privacyscore.analysis.default_checks import CHECKS

def categorize_result(result: dict, group_order: list) -> OrderedDict:
    if 'reachable' in result and not result['reachable']:
        return {}
    described_groups = OrderedDict()
    for group in group_order:
        if group not in CHECKS:
            continue
        described_groups[group] = analyse_group(group, result)
    return described_groups

def analyse_group(group: str, result: dict):
    descriptions = []
    for check, data in CHECKS[group].items():
        keys = {}
        for key in data['keys']:
            if key not in result:
                keys = None
                break
            keys[key] = result[key]
        if keys:
            res = data['category'](**keys)
        else:
            res = data['missing']
        if not res:
            descriptions.append((None, data.get('short_title'), None))
            continue

        descriptions.append((res['description'], data.get('short_title'), res['classification']))
    return descriptions
