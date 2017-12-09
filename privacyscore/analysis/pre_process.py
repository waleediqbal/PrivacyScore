
"""
This module takes care of pre-processing the categorized JSON results.

It schedules a background job for pre-processing and saves the result in database.

"""
from collections import OrderedDict
from typing import Tuple, Union
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS

def pre_process():
	sites = Site.objects.order_by('-id')
	if sites:
	    scan_results = sites.annotate_most_recent_scan_error_count() \
	        .annotate_most_recent_scan_start().annotate_most_recent_scan_end_or_null() \
	        .annotate_most_recent_scan_result() \
	        .select_related('last_scan')

	    group_json = {'items':[]}
	    analysis = []

	    for site in scan_results:
	        if site.last_scan__result:
	            analysis = site.analyse(DEFAULT_GROUP_ORDER)[1].items()
	        else:
	            analysis =  None
	        if analysis:
	            for group, result in zip(RESULT_GROUPS.values(), analysis):
	                for description, title, rating in result[1]:
	                    data = {}
	                    data['group'] = group['short_name'].replace(",", "")
	                    data['title'] = title
	                    data['category'] = rating
	                    data['country'] = site.last_scan__result['a_locations'][0] if site.last_scan__result['a_locations'] else None
	                    group_json.get('items').append(data)

