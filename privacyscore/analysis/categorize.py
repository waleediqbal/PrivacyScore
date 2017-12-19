
"""
This module takes care of reading the json of scan results.

It checks for spicifc keys related to a check and returns if it is good or bad.

"""
from collections import OrderedDict
from typing import Tuple, Union

from privacyscore.analysis.default_checks import CHECKS
from privacyscore.evaluation.site_evaluation import UnrateableSiteEvaluation


def categorize_result(result: dict, group_order: list) -> Tuple[dict, OrderedDict]:
    """
    Evaluate and describe a complete result dictionary.

    As a result, a dictionary of the groups is returned. Each group has another
    dictionary specifying the amount of good, the amount of bad and the amount
    of neutral results as well as the overall group rating and the ratio of
    good results.
    """
    if 'reachable' in result and not result['reachable']:
        return UnrateableSiteEvaluation(), {}
    evaluated_groups = {}
    described_groups = OrderedDict()
    for group in group_order:
        if group not in CHECKS:
            continue
        evaluated_groups[group], described_groups[group] = analyse_group(
            group, result)
    return evaluated_groups, described_groups


def analyse_group(group: str, result: dict):
    """
    Evaluate all entries of a group. Returns the number of good results, bad
    results and the number of neutral/not rateable results.
    """
    classifications = []
    descriptions = []
    for check, data in CHECKS[group].items():
        keys = {}
        for key in data['keys']:
            if key not in result:
                keys = None
                break
            keys[key] = result[key]
        if keys:
            res = data['rating'](**keys)
        else:
            res = data['missing']
        if not res:
            classifications.append(None)
            descriptions.append((None, data.get('short_title'), None))
            continue
        
        classifications.append(res['classification'])
        descriptions.append((res['description'], data.get('short_title'), res['classification']))
    return classifications, descriptions
