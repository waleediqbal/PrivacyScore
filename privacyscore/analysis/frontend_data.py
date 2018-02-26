import json
import re
import collections
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from collections import OrderedDict
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS
from privacyscore.analysis.default_checks import CHECKS
from privacyscore.backend.models import Scan, ScanList, Site, ScanResult, Analysis, AnalysisCategory
from pandas.io.json import json_normalize

def donut_chart(df = [], check_array=[], keys_array=[], check_group='') -> OrderedDict:
	donut_data = OrderedDict()
	for check, valid_key in zip(check_array, keys_array):
		query  = df.query('check == @check')
		pass_count = query[query['value'] == 'good']
		pass_per   = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

		fail_per   = query[query['value'] == 'bad']
		good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
		bad_count  = fail_per['count'].values[0] if fail_per['count'].values else 0
		title_array  = [CHECKS[check_group][valid_key]['frontend_title'].get('bad'), CHECKS[check_group][valid_key]['frontend_title'].get('good')]
		donut_data[check] = (title_array, [bad_count, good_count], pass_per)
	return donut_data

def donut_chart_single(df = [], check='', check_key='', check_group='') -> OrderedDict:
	query  = df.query('check == @check')
	pass_count = query[query['value'] == 'good']
	pass_per   = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

	fail_per   = query[query['value'] == 'bad']
	good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
	bad_count  = fail_per['count'].values[0] if fail_per['count'].values else 0
	title_array  = [CHECKS[check_group][check_key]['frontend_title'].get('bad'), CHECKS[check_group][check_key]['frontend_title'].get('good')]
	donut_data = (title_array, [bad_count, good_count], pass_per)

	return donut_data

def column_chart(df = [], checks=[]) -> OrderedDict:
	good_values  = []
	bad_values   = []
	check_titles = []
	for check in checks:
		query = df.query('check == @check')
		row1  = df.loc[(df['check'] == check) & (df['value'] == 'good')]
		row2  = df.loc[(df['check'] == check) & (df['value'] == 'bad')]
		count_good  = row1['count'].values[0] if row1['count'].values else 0
		count_bad   = row2['count'].values[0] if row2['count'].values else 0
		good_values.append((count_good))
		bad_values.append((count_bad))
		check = check.replace('Web server supports ', '')
		check = check.replace('Mail server supports ', '')
		check = check.replace('Web server Protected against ', '')
		check = check.replace('Mail server Protected against ', '')
		check = check.replace('Protected against ', '')
		check_titles.append(check)
	return (check_titles, good_values, bad_values)
