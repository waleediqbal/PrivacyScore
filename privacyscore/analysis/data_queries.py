import csv
import json
import re
import collections
import pandas as pd
import numpy as np
import Orange
import os

import time
import threading

from Orange.data import Domain, DiscreteVariable, ContinuousVariable
from orangecontrib.associate.fpgrowth import *
from tkinter import *
from collections import Counter, defaultdict
from collections import OrderedDict
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS
from privacyscore.analysis.default_checks import CHECKS
from privacyscore.backend.models import Scan, ScanList, Site, ScanResult, Analysis, AnalysisCategory
from pandas.io.json import json_normalize

#countries with most issues in each category
def country_category_list(myList = []) -> OrderedDict:
	#df = pd.DataFrame(myList, columns = ['group', 'country', 'category'])
	df = myList
	#df = df.dropna()
	#df.set_index('group', inplace=True)

	top_country_groups = OrderedDict()
    #issues in countries w.r.t category
	for group in DEFAULT_GROUP_ORDER:
		mydict = []

		for check, data in CHECKS[group].items():
			mydict.append(data.get('short_title'))

		#if 'Website scan succeeded' in mydict:
			#mydict.remove('Website scan succeeded')

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')

		melted_data = melted_data.groupby(['country', 'value'])['value'].count().reset_index(name="count")

		melted_data['value'] = melted_data['value'].map({'0': 'bad', '1': 'good'})

		new1 = melted_data[melted_data['value'] == 'bad'].sort_values(by=['count', 'country'], ascending=[False, True])

		new1['percentage'] = round(100 * new1['count']  / new1['count'].sum(), 2)

		new1 = new1.nlargest(10, columns=['percentage'])

        #d = json.loads(new1.unstack().to_json())
		d = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)
        #data_count = (sorted(d['0'].values(), reverse=True))[:10]
        #country_count = (sorted(d['0'], reverse=True, key=d['0'].__getitem__))[:10]
		data_count = list(d['percentage'].values())
		country_count = list(d['country'].values())

		my_array1 = {'items':[]}
		for cnt, ctry in zip(data_count, country_count):
			d1 = {}
			d1['name'] = ctry
			d1['y'] = cnt
			my_array1.get('items').append(d1)
		
		top_country_groups[group] = my_array1['items']

	return top_country_groups

def test_function(myList = []):
	df = myList

	title_array = []
	per_array = []
	described_groups = OrderedDict()
	for group in DEFAULT_GROUP_ORDER:
		mydict = []
		for check, data in CHECKS[group].items():
			mydict.append(data.get('short_title'))

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')
		melted_data = melted_data.groupby(['check', 'value'])['value'].count().reset_index(name="count")
		melted_data['value'] = melted_data['value'].map({'0': 'bad', '1': 'good'})

		new1 = melted_data[melted_data['value'] == 'good'].sort_values(by='count', ascending=False)

		new1['percentage'] = round(100 * new1['count']  / new1['count'].sum(), 1)
		new1 = new1.nlargest(10, columns=['percentage'])

#individual check failure, passing % in countries
def check_failure_country(myList = []) -> OrderedDict:
	df = myList

	described_country_groups = OrderedDict()
	for group in DEFAULT_GROUP_ORDER:
		mydict = []

		for check, data in CHECKS[group].items():
			mydict.append(data.get('short_title'))

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')
		melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()

		#melted_data = melted_data.groupby(by=['check', 'country', 'value'])['value'].count()

		melted_data1 = melted_data.groupby(by=['check', 'country', 'value'])['value'].count()
		my = round(melted_data1 / (melted_data1.groupby(level = [0, 1]).transform(sum)) * 100, 1).reset_index(name="percentage")
		my['value'] = my['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})

		melted_data = melted_data.groupby(by=['check', 'country'])['value'].count().reset_index(name='total_count')
		melted_data = melted_data.sort_values(by=['total_count'], ascending=[False])
		de1 = melted_data.set_index(['country'])

		de1 = de1.groupby('check')['total_count'].nlargest(5).reset_index()
		de1 = de1.sort_values(['check', 'country']).reset_index()

#		my = round(melted_data / (melted_data.groupby(level = [0]).transform(sum)) * 100, 1).reset_index(name="percentage")
#		my['value'] = my['value'].map({'0': 'bad', '1': 'good'})

#		de1 = ((my[my['value'] == 'bad']).sort_values(by=['percentage'], ascending=[False]))
#		de1 = de1.set_index(['country'])

#		de1 = de1.groupby('check')['percentage'].nlargest(5).reset_index()

		good_values = []
		bad_values = []
		neutral_values = []
		for row in de1.itertuples(index=True, name='Pandas'):
			row1 = my.loc[(my['check'] == getattr(row, "check")) & (my['country'] == getattr(row, "country")) & (my['value'] == 'good')]
			row2 = my.loc[(my['check'] == getattr(row, "check")) & (my['country'] == getattr(row, "country")) & (my['value'] == 'bad')]
			row3 = my.loc[(my['check'] == getattr(row, "check")) & (my['country'] == getattr(row, "country")) & (my['value'] == 'neutral')]

			myval = row1['percentage'].values[0] if row1['percentage'].values else 0.0
			myval2 = row2['percentage'].values[0] if row2['percentage'].values else 0.0
			myval3 = row3['percentage'].values[0] if row3['percentage'].values else 0.0

			bad_values.append(float(myval2))
			good_values.append(float(myval))
			neutral_values.append(float(myval3))

		dat2 = pd.DataFrame({'good': good_values, 'bad': bad_values, 'neutral': neutral_values })
		dat2 = de1.join(dat2)
		checks = dat2['check'].unique()

		combined_data = []
		for chk in checks:
			query = dat2.query('check == @chk')
			combined_data.append((chk, list(query['country'].values), [float(i) for i in query['bad'].values], [float(i) for i in query['good'].values], [float(i) for i in query['neutral'].values], list(query['total_count'].values)))
			#combined_data.append((chk, list(query['country'].values), [float(i) for i in query['percentage'].values], [float(i) for i in query['good'].values]))

		described_country_groups[group] = combined_data
	return described_country_groups

# top 10 countries with most issues with respect to individual categories
def country_issues_category_list(myList = []) -> OrderedDict:

	#df = pd.DataFrame(myList, columns = ['group', 'title', 'category', 'country'])
	df = myList
#	df = df.dropna()
#	df.set_index('group', inplace=True)

	described_country_groups = OrderedDict()
	for group in DEFAULT_GROUP_ORDER:
		mydict = []

		for check, data in CHECKS[group].items():
			mydict.append(data.get('short_title'))

		#if 'Website scan succeeded' in mydict:
		#	mydict.remove('Website scan succeeded')

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')
		melted_data = melted_data.groupby(by=['check', 'country', 'value'])['value'].count()

		my = round(melted_data / (melted_data.groupby(level = [0]).transform(sum)) * 100, 1).reset_index(name="percentage")
		my['value'] = my['value'].map({'0': 'bad', '1': 'good'})

		de1 = ((my[my['value'] == 'bad']).sort_values(by=['check', 'percentage'], ascending=[False, False]))

		de1.drop_duplicates('check', inplace = True)

		new1 = de1.nlargest(10, columns=['percentage'])

		mx = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)

		title_array = list(mx['check'].values())
		per_array = list(mx['percentage'].values())
		country_array = list(mx['country'].values())

		zipped = [list(t) for t in zip(title_array, country_array)]
		described_country_groups[group] = (zipped, per_array)

	return described_country_groups

# top 10 issues with respect to individual categories
def issues_category_list(myList = []) -> OrderedDict:
	#df = pd.DataFrame(myList, columns = ['group', 'title', 'category'])
	df = myList
	#df.set_index('group', inplace=True)

	title_array = []
	per_array = []
	described_groups = OrderedDict()
	for group in DEFAULT_GROUP_ORDER:
		mydict = []
		for check, data in CHECKS[group].items():
			mydict.append(data.get('short_title'))

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')
		melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()
		melted_data = melted_data.groupby(['check', 'value'])['value'].count()

		my = round(melted_data / (melted_data.groupby(level = [0]).transform(sum)) * 100, 1).reset_index(name="percentage")
		my['value'] = my['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})
		#my.value = my.value.fillna('neutral')

		#TO-DO
		de2 = ((my[my['value'] == 'good']).sort_values(by=['percentage'], ascending=[False]))
		#print(de2.nlargest(10, columns=['percentage']))

		de1 = ((my[my['value'] == 'bad']).sort_values(by=['percentage'], ascending=[False]))

		new1 = de1.nlargest(10, columns=['percentage']).reset_index()

		good_values = []
		neutral_values = []
		for row in new1.itertuples(index=True, name='Pandas'):
			row1 = my.loc[(my['check'] == getattr(row, "check")) & (my['value'] == 'good')]
			row2 = my.loc[(my['check'] == getattr(row, "check")) & (my['value'] == 'neutral')]

			myval = row1['percentage'].values[0] if row1['percentage'].values else 0.0
			myval1 = row2['percentage'].values[0] if row2['percentage'].values else 0.0
			good_values.append(float(myval))
			neutral_values.append(float(myval1))

		dat2 = pd.DataFrame({'good': good_values, 'neutral': neutral_values })
		dat2 = new1.join(dat2)

		dat2 = json.loads(dat2.to_json(), object_pairs_hook=OrderedDict)
		title_array = list(dat2['check'].values())
		per_array = list(dat2['percentage'].values())
		good_array = list(dat2['good'].values())
		neutral_array = list(dat2['neutral'].values())

		described_groups[group] = (title_array, per_array, good_array, neutral_array)

		#mx = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)

		#title_array = list(mx['check'].values())
		#per_array = list(mx['percentage'].values())

		#described_groups[group] = (title_array, per_array)

	return described_groups

def enc_web_results(myList = []) -> OrderedDict:
	df = myList
	described_groups = []
	described_vul = []
	mydict = []
	hsts_groups = OrderedDict()
	privacy_groups = OrderedDict()

	my_arr = ['SSL 2.0', 'SSL 3.0', 'Legacy TLS 1.0', 'TLS 1.1', 'TLS 1.2']

	for group in DEFAULT_GROUP_ORDER:
		if group == 'ssl' or group == 'security':
			for check, data in CHECKS[group].items():
				mydict.append(data.get('short_title'))

	melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')

	melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()

	melted_data1 = melted_data.groupby(by=['check', 'value'])['value'].count().reset_index(name='count')

	melted_data = melted_data.groupby(['check', 'value'])['value'].count()

	melted_data2 = melted_data.groupby(level = [0]).transform(sum).reset_index(name="total_count")
	melted_data2['count'] = melted_data1['count']

	#melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)
	melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})
	melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

	my_arr = ['SSL 2.0', 'SSL 3.0', 'Legacy TLS 1.0', 'TLS 1.1', 'TLS 1.2']

	web_vul = ["Protected against Heartbleed", "Protected against CCS attack", "Protected against Ticketbleed", "Protected against Secure Renegotiation",  "Protected against Secure Client-Initiated Renegotiation", "Protected against CRIME", "Protected against BREACH", "Protected against POODLE", "Protected against SWEET32", "Protected against FREAK", "Protected against DROWN", "Protected against LOGJAM", "Protected against BEAST", "Protected against LUCKY13"]

	valid_hsts = ['HSTS header duration sufficient', 'Server ready for HSTS preloading']

	other_checks = ['SSL certificate valid', 'Perfect Forward Secrecy offered', 'Insecure RC4 ciphers used', 'TLS_FALLBACK_SCSV used']

	privacy_checks = ['3rd party embeds', '3rd party embeds are trackers', 'First party cookies', 'Third party cookies', 'Google Analytics usage', 'Google Analytics privacy extension enabled']

	privacy_value = melted_data2.loc[melted_data2['check'].isin(privacy_checks)]

	CHECKS_TEXT = {
	    'ssl': OrderedDict(),
	}
	CHECKS_TEXT['ssl']['Valid Strict-Transport-Security (HSTS)'] = {
		'bad': 'Sites not using HSTS',
		'good': 'Sites using HSTS'
	}
	CHECKS_TEXT['ssl']['HSTS header duration sufficient'] = {
		'bad': 'Short duration',
		'good': 'Sufficiently long duration'
	}

	CHECKS_TEXT['ssl']['Server ready for HSTS preloading'] = {
		'bad': 'Not ready',
		'good': 'Ready'
	}
	CHECKS_TEXT['ssl']['Inclusion in Chrome HSTS preload list'] = {
		'bad': ['Not included'],
		'good': 'Included'
	}
	CHECKS_TEXT['ssl']['Server offers HTTPS'] = {
		'bad': 'Not deployed',
		'good': 'HTTPS deployed'
	}
	CHECKS_TEXT['ssl']['SSL certificate valid'] = {
		'bad': 'Invalid',
		'good': 'Valid'
	}
	CHECKS_TEXT['ssl']['Perfect Forward Secrecy offered'] = {
		'bad': 'Not offered',
		'good': 'Offered'
	}
	CHECKS_TEXT['ssl']['Insecure RC4 ciphers used'] = {
		'bad': 'RC4 ciphers not used',
		'good': 'RC4 ciphers used'
	}
	CHECKS_TEXT['ssl']['TLS_FALLBACK_SCSV used'] = {
		'bad': 'Not used',
		'good': 'Used'
	}

	# https check
	https_offered = 'Server offers HTTPS'
	query = melted_data2.query('check == @https_offered')
	pass_count = query[query['value'] == 'good']
	pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

	fail_per = query[query['value'] == 'bad']
	good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
	bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

	cat_array = [CHECKS_TEXT['ssl'][https_offered].get('bad'), CHECKS_TEXT['ssl'][https_offered].get('good')]
	https_data = (cat_array, [bad_count, good_count], pass_per)
	#############################################################################

	########################## Valid HSTS check #################################
	valid_hsts_check = 'Valid Strict-Transport-Security (HSTS)'
	query = melted_data2.query('check == @valid_hsts_check')
	pass_count = query[query['value'] == 'good']
	pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

	fail_per = query[query['value'] == 'bad']
	good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
	bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

	cat_array = [CHECKS_TEXT['ssl'][valid_hsts_check].get('bad'), CHECKS_TEXT['ssl'][valid_hsts_check].get('good')]
	#query['value'].replace(['bad','good'],[CHECKS_TEXT['ssl'][valid_hsts_check].get('bad'), CHECKS_TEXT['ssl'][valid_hsts_check].get('good')], inplace=True)

	hsts_valid_data = (cat_array, [bad_count, good_count], pass_per)
	# hsts_valid_data = (list(query['value']), list(query['count']), pass_per)
	#############################################################################

	hsts_included = 'Inclusion in Chrome HSTS preload list'
	query = melted_data2.query('check == @hsts_included')
	pass_count = query[query['value'] == 'good']
	pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

	fail_per = query[query['value'] == 'bad']
	good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
	bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

	cat_array = [CHECKS_TEXT['ssl'][hsts_included].get('bad'), CHECKS_TEXT['ssl'][hsts_included].get('good')]

	hsts_included_data = (cat_array, [bad_count, good_count], pass_per, hsts_included)
	#hsts_included_data = (list(query['value']), list(query['count']), pass_per, hsts_included)
	############################################################################

	hsts_valid = melted_data2.loc[melted_data2['check'].isin(valid_hsts)]

	for check in valid_hsts:
		query = melted_data2.query('check == @check')
		pass_count = query[query['value'] == 'good']
		pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

		fail_per = query[query['value'] == 'bad']
		good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
		bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

		#query['value'].replace(['bad','good'],[CHECKS_TEXT['ssl'][check].get('bad'), CHECKS_TEXT['ssl'][check].get('good')], inplace=True)
		cat_array = [CHECKS_TEXT['ssl'][check].get('bad'), CHECKS_TEXT['ssl'][check].get('good')]
		hsts_groups[check] = (cat_array, [bad_count, good_count], pass_per)

	for check in privacy_checks:
		query = melted_data2.query('check == @check')
		pass_per = query[query['value'] == 'good']
		pass_per = pass_per['percentage'].values[0] if pass_per['percentage'].values else 0

		privacy_groups[check] = (list(query['value']), list(query['count']), pass_per)

	################### Web Security ######################
	security_checks = ['Content Security Policy header set',
						'X-Frame-Options header set',
						'Secure XSS Protection header set',
						'Secure X-Content-Type-Options header set',
						'Referrer Policy header set']

	security_data = melted_data2.loc[melted_data2['check'].isin(security_checks)]

	security_groups = OrderedDict()
	for check in security_checks:
		query = melted_data2.query('check == @check')
		pass_count = query[query['value'] == 'good']
		pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

		fail_per = query[query['value'] == 'bad']
		good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
		bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

		#query['value'].replace(['bad','good'],[CHECKS_TEXT['ssl'][check].get('bad'), CHECKS_TEXT['ssl'][check].get('good')], inplace=True)
		#cat_array = [CHECKS_TEXT['security'][check].get('bad'), CHECKS_TEXT['security'][check].get('good')]
		cat_array = ['bad', 'good']
		security_groups[check] = (cat_array, [bad_count, good_count], pass_per)
	################ OTHER checks #####################
	other_groups = OrderedDict()
	for check in other_checks:
		query = melted_data2.query('check == @check')
		pass_count = query[query['value'] == 'good']
		pass_per = pass_count['percentage'].values[0] if pass_count['percentage'].values else 0

		fail_per = query[query['value'] == 'bad']
		good_count = pass_count['count'].values[0] if pass_count['count'].values else 0
		bad_count = fail_per['count'].values[0] if fail_per['count'].values else 0

		#query['value'].replace(['bad','good'],[CHECKS_TEXT['ssl'][check].get('bad'), CHECKS_TEXT['ssl'][check].get('good')], inplace=True)
		cat_array = [CHECKS_TEXT['ssl'][check].get('bad'), CHECKS_TEXT['ssl'][check].get('good')]
		other_groups[check] = (cat_array, [bad_count, good_count], pass_per)
	###################################################

	vul_data = melted_data2.loc[melted_data2['check'].isin(web_vul)]

	melted_data2 = melted_data2.loc[melted_data2['check'].isin(my_arr)]

	melted_data2['check'] = pd.Categorical(
	    melted_data2['check'],
	    categories=my_arr,
	    ordered=True
	)
	melted_data2 = melted_data2.sort_values('check')

	checks = melted_data2['check'].unique()
	vul_checks = vul_data['check'].unique()

	my = round(melted_data / (melted_data.groupby(level = [0]).transform(sum)) * 100, 1).reset_index(name="percentage")
	my['value'] = my['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})

	#my = my[my['check'].isin(my_arr)].reindex()
	my = my.loc[my['check'].isin(my_arr)]

	#checks = my['check'].unique()

	good_values = []
	bad_values = []

	combined_data = []
	for chk in checks:
		query = melted_data2.query('check == @chk')

		row1 = melted_data2.loc[(melted_data2['check'] == chk) & (melted_data2['value'] == 'good')]
		row2 = melted_data2.loc[(melted_data2['check'] == chk) & (melted_data2['value'] == 'bad')]
		myval = row1['count'].values[0] if row1['count'].values else 0
		myval1 = row2['count'].values[0] if row2['count'].values else 0
		good_values.append((myval))
		bad_values.append((myval1))

	described_groups = (list(checks), good_values, bad_values)

	good_values = []
	bad_values = []
	neutral_values = []

	combined_data = []
	for chk in vul_checks:
		query = vul_data.query('check == @chk')

		row1 = vul_data.loc[(vul_data['check'] == chk) & (vul_data['value'] == 'good')]
		row2 = vul_data.loc[(vul_data['check'] == chk) & (vul_data['value'] == 'bad')]
		row3 = vul_data.loc[(vul_data['check'] == chk) & (vul_data['value'] == 'neutral')]

		myval = row1['count'].values[0] if row1['count'].values else 0
		myval1 = row2['count'].values[0] if row2['count'].values else 0
		#myval2 = row3['count'].values[0] if row3['count'].values else 0
		good_values.append((myval))
		bad_values.append((myval1))
		#neutral_values.append((myval2))

	new_set = {x.replace('Protected against ', '') for x in list(vul_checks)}
	described_vul = (list(new_set), good_values, bad_values, neutral_values)

	return described_groups, described_vul, hsts_groups, hsts_valid_data, hsts_included_data, https_data, other_groups, security_groups

def enc_mail_results(myList = []) -> OrderedDict:
	df = myList
	tls_group = []
	vul_group = []
	mydict = []

	CHECKS_TEXT = {
	    'mx': OrderedDict(),
	}

	CHECKS_TEXT['mx']['Mail server supports encryption'] = {
		'bad': 'Not supported',
		'good': 'Supported'
	}

	# df1 = pd.DataFrame(df, columns=['url'])
	# df1.drop_duplicates('url', inplace = True)
	# web_count = df1.shape[0]

	for check, data in CHECKS['mx'].items():
		mydict.append(data.get('short_title'))

	melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')
	melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()

	melted_data_count = melted_data.groupby(by=['check', 'value'])['value'].count().reset_index(name='count')

	melted_data = melted_data.groupby(['check', 'value'])['value'].count()

	melted_data2 = melted_data.groupby(level = [0]).transform(sum).reset_index(name="total_count")
	melted_data2['count'] = melted_data_count['count']

	melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})
	melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

	################# check has_mx count ##################
	has_mx = 'Domain has Mail server'
	query = melted_data2.query('check == @has_mx')
	pass_per = query[query['value'] == 'good']
	has_mx_count = pass_per['count'].values[0]
	#######################################################

	############# check mx encryption support #############
	mx_support = 'Mail server supports encryption'

	query = melted_data2.query('check == @mx_support')
	pass_per = query[query['value'] == 'good']
	if not pass_per.empty:
		pass_per['percentage'].values[0] = round((pass_per['count'].values[0] / has_mx_count) * 100, 1) if pass_per['count'].values[0] else 0
		pass_percentage = pass_per['percentage'].values[0] if pass_per['percentage'].values else 0

		mx_enc_failed = has_mx_count - pass_per['count'].values[0]
		mx_enc_support = (mx_support, [CHECKS_TEXT['mx'][mx_support].get('bad'), CHECKS_TEXT['mx'][mx_support].get('good')], [mx_enc_failed, pass_per['count'].values[0]], pass_percentage)
	else:
		mx_enc_support = []
	#######################################################

	############## Check TLS/SSL support ##################
	tls_ssl = ['Mail server supports SSL 2.0',
				'Mail server supports SSL 3.0',
				'Mail server supports Legacy TLS 1.0',
				'Mail server supports TLS 1.1',
				'Mail server supports TLS 1.2'
				]
	tls_data = melted_data2.loc[melted_data2['check'].isin(tls_ssl)]

	tls_data['check'] = pd.Categorical(
	    tls_data['check'],
	    categories=tls_ssl,
	    ordered=True
	)
	tls_data = tls_data.sort_values('check')
	checks = tls_data['check'].unique()

	good_values = []
	bad_values  = []
	ssl_checks  = []

	for check in checks:
		query = tls_data.query('check == @check')
		row1  = tls_data.loc[(tls_data['check'] == check) & (tls_data['value'] == 'good')]
		row2  = tls_data.loc[(tls_data['check'] == check) & (tls_data['value'] == 'bad')]
		count_good = row1['count'].values[0] if row1['count'].values else 0
		count_bad  = row2['count'].values[0] if row2['count'].values else 0
		good_values.append((count_good))
		bad_values.append((count_bad))
		ssl_checks.append(check.replace('Mail server supports ', ''))

	tls_group = ((ssl_checks), good_values, bad_values)
	#######################################################

	############## Check vulnerabilities ##################
	vul_checks = ['Mail server Protected against CRIME',
					'Mail server Protected against Heartbleed',
					'Mail server Protected against BEAST',
					'Mail server Protected against LOGJAM',
					'Mail server Protected against DROWN',
					'Mail server Protected against CCS attack',
					'Mail server Protected against LUCKY13',
					'Mail server Protected against FREAK',
					'Mail server Protected against BREACH',
					'Mail server Protected against Ticketbleed',
					'Mail server Protected against POODLE',
					'Mail server Protected against SWEET32',
					'Mail server Protected against Secure Client-Initiated Renegotiation',
					'Mail server Protected against Secure Renegotiation']

	vul_data = melted_data2.loc[melted_data2['check'].isin(vul_checks)]
	good_values = []
	bad_values  = []
	vul_rep_checks  = []

	for check in vul_checks:
		query = vul_data.query('check == @check')
		row1  = vul_data.loc[(vul_data['check'] == check) & (vul_data['value'] == 'good')]
		row2  = vul_data.loc[(vul_data['check'] == check) & (vul_data['value'] == 'bad')]
		count_good = row1['count'].values[0] if row1['count'].values else 0
		count_bad  = row2['count'].values[0] if row2['count'].values else 0
		good_values.append((count_good))
		bad_values.append((count_bad))
		vul_rep_checks.append(check.replace('Mail server Protected against ', ''))

	vul_group = ((vul_rep_checks), good_values, bad_values)
	#######################################################

	return mx_enc_support, tls_group, vul_group

def web_privacy_results(myList = []) -> OrderedDict:
	df = myList
	mydict = []
	privacy_groups = OrderedDict()
	google_group = OrderedDict()
	df.drop('country', axis=1, inplace=True)
	df.drop('mx_country', axis=1, inplace=True)
	df.drop('url', axis=1, inplace=True)

	for check, data in CHECKS['privacy'].items():
		mydict.append(data.get('short_title'))

	result = df.reindex(columns=mydict)
	#result = result.apply(lambda x: pd.value_counts(x, normalize=True)).replace(to_replace='None', value=np.nan).dropna()
	#result = result.apply(pd.value_counts).replace(to_replace='None', value=np.nan).dropna()
	result = result.apply(pd.value_counts).fillna(0)
	result[mydict] = result[mydict].astype(int)
	if 'None' in result.index:
		result.drop('None', inplace=True) #drop None index

	# privacy_checks = ['Sites using third party embeds', 'Sites using trackers', 'Sites setting first party cookies', 'Sites setting third party cookies']
	for check in result.columns:
		if check in result.columns:
			query      = result[check]
			pass_count = query[1] if '1' in result.index else 0
			fail_count = query[0] if '0' in result.index else 0
			pass_per   = round((pass_count / (pass_count + fail_count)) * 100, 1)
			check = check.replace("&", "and")
			privacy_groups[check] = (['bad', 'good'], [fail_count, pass_count], float(pass_per))
	########################################################
	mydict = []
	for check, data in CHECKS['security'].items():
		mydict.append(data.get('short_title'))

	result = df.reindex(columns=mydict)

	security_checks = ['Unintentional information leaks']

	return privacy_groups, google_group

def association(myList = [], min_supp = 0.1, confidence=0.1):
	df = myList
	df = df.drop('url', axis=1)
	df = df.drop('country', axis=1)
	df = df.drop('mx_country', axis=1)
	#df = df.replace('None', '0')
	df = df.replace('None', np.nan)

	#df = df[df['Server offers HTTPS'] == '1']

	print("Total rows before : ", int(df.shape[0]))

	df['missing_val'] = df.isnull().sum(axis=1)
	#df = df[df['missing_val'] <= np.ceil(df['missing_val'].mean())]

	print("Average missing values in each transaction = ", float(np.ceil(df['missing_val'].mean())))
	print("Total rows after dropping avg. missing value rows : ", int(df.shape[0]))
	df = df.drop('missing_val', axis=1)

	df = df.replace(np.nan, '0')
	df = df.iloc[:, :-50]
	df = df.iloc[30000:]

	print("Total rows = ", int(df.shape[0]))
	print("Total columns = ", int(df.shape[1]))

	# restricted_columns = ['Sites setting first party cookies', 'Google Analytics privacy extension enabled', 'HTTP URL also reachable via HTTPS',
	# 'Automatic HTTPS redirection', 'Server prevents using HTTPS', 'HSTS header duration sufficient', 'Server ready for HSTS preloading',
	# 'Inclusion in Chrome HSTS preload list', 'No Mixed Content on HTTPS sites', 'Domain has Mail server', 'Web & mail servers in same country',
	# 'Mail server supports SSL 2.0', 'SSL 2.0', 'Mail server supports SSL 3.0', 'SSL 3.0']

	# for column in restricted_columns:
	# 	if column in df.columns:
	# 		df.drop([column], axis=1, inplace=True)
	input_assoc_rules = df

	domain_checks = Domain([DiscreteVariable.make(name=check,values=['0', '1']) for check in input_assoc_rules.columns])
	data_gro_1 = Orange.data.Table.from_numpy(domain=domain_checks, X=input_assoc_rules.as_matrix(),Y= None)
	data_gro_1_en, mapping = OneHot.encode(data_gro_1, include_class=False)
	min_support = float(min_supp)
	print("num of required transactions = ", int(input_assoc_rules.shape[0]*min_support))
	num_trans = input_assoc_rules.shape[0]*min_support
	itemsets = dict(frequent_itemsets(data_gro_1_en, min_support=min_support))
	print(len(itemsets))

	confidence = float(confidence)

	rules_df = pd.DataFrame()
	rules = [(P, Q, supp, conf)
	for P, Q, supp, conf in association_rules(itemsets, confidence)
		if len(Q) > 1 ]

	print("Step 1: Rules generated")

	names = {item: '{}={}'.format(var.name, val)
		for item, var, val in OneHot.decode(mapping, data_gro_1, mapping)}

	print("Step 2: Decoded")

	eligible_ante = [v for k,v in names.items()] #allowed both 0 and 1
	N = input_assoc_rules.shape[0] * 0.5
	rule_stats = list(rules_stats(rules, itemsets, N))

	print("Step 3: Stats for rules generated")
	rule_list_df = []
	for ex_rule_frm_rule_stat in rule_stats:
		ante = ex_rule_frm_rule_stat[0]
		cons = ex_rule_frm_rule_stat[1]
		#named_cons = names[next(iter(cons))]

		named_cons = [names[i] for i in cons if names[i] in eligible_ante]
		named_cons = ', '.join(named_cons)
		#if named_cons in eligible_ante:
		rule_lhs = [names[i] for i in ante if names[i] in eligible_ante]
		ante_rule = ', '.join(rule_lhs)
		if ante_rule and len(rule_lhs)>2 :
			rule_dict = {'support' : ex_rule_frm_rule_stat[2],
			             'confidence' : ex_rule_frm_rule_stat[3],
		                 'coverage' : ex_rule_frm_rule_stat[4],
		                 'strength' : ex_rule_frm_rule_stat[5],
		                 'lift' : ex_rule_frm_rule_stat[6],
		                 'leverage' : ex_rule_frm_rule_stat[7],
		                 'antecedent': ante_rule,
		                 'consequent':named_cons }
			rule_list_df.append(rule_dict)
	rules_df = pd.DataFrame(rule_list_df)
	print("Raw rules data frame of {} rules generated".format(rules_df.shape[0]))
	if not rules_df.empty:
		pruned_rules_df = rules_df.groupby(['antecedent','consequent']).max().reset_index()
		result = pruned_rules_df[['antecedent','consequent', 'support','confidence','lift']].groupby('consequent').max().reset_index().sort_values(['support','confidence'], ascending=False)
		#result.to_csv("association_"+time.ctime()+".csv", sep='\t', index=False)
		result.to_csv(os.path.join('/home/sysop/', "association_"+time.ctime()+".csv") , sep='\t', index=False)
		print(result.to_csv(sep=' ', index=False, header=False))
	else:
		print("Unable to generate any rule")

def association_thread(min_supp, min_conf):
	analyse = Analysis.objects.exclude(end__isnull=True).order_by('-end')[0]
	if analyse:
		analyse_cat = analyse.category.values('result')
		df = json_normalize(analyse_cat, record_path='result')
		thread = threading.Thread(target=association,args=(df, min_supp, min_conf))
		thread.daemon = True
		thread.start()
