import csv
import json
import re
import collections
import pandas as pd
import numpy as np
import Orange
import os
import random

import time
import threading

#from fancyimpute import KNN, MICE
from Orange.data import Domain, DiscreteVariable, ContinuousVariable
from orangecontrib.associate.fpgrowth import *
from tkinter import *
from collections import Counter, defaultdict
from collections import OrderedDict
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS
from privacyscore.analysis.default_checks import CHECKS
from privacyscore.analysis.frontend_data import donut_chart, column_chart, donut_chart_single
from privacyscore.backend.models import Scan, ScanList, Site, ScanResult, Analysis, AnalysisCategory, AnalysisTimeSeries
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
	ssl_support = []
	web_vul = []
	valid_hsts = []
	other_checks = []
	security_checks = []

	for group in DEFAULT_GROUP_ORDER:
		if group == 'ssl' or group == 'security':
			for check, data in CHECKS[group].items():
				mydict.append(data.get('short_title'))

	melted_data = pd.melt(df, id_vars=['url'], value_vars=mydict, var_name='check', value_name='value')

	melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()

	melted_data1 = melted_data.groupby(by=['check', 'value'])['value'].count().reset_index(name='count')

	melted_data = melted_data.groupby(['check', 'value'])['value'].count()

	melted_data2 = melted_data.groupby(level = [0]).transform(sum).reset_index(name="total_count")
	melted_data2['count'] = melted_data1['count']

	#melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)
	melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})
	melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

	ssl_support_keys = ['web_insecure_protocols_sslv2', 'web_insecure_protocols_sslv3', 'web_secure_protocols_tls1',
	'web_secure_protocols_tls1_1', 'web_secure_protocols_tls1_2']

	for key in ssl_support_keys:
		ssl_support.append(CHECKS['ssl'][key]['short_title'])

	web_vul_keys = ['web_vuln_heartbleed', 'web_vuln_ccs', 'web_vuln_ticketbleed', 'web_vuln_secure_renego',
	'web_vuln_secure_client_renego', 'web_vuln_crime', 'web_vuln_breach', 'web_vuln_poodle', 'web_vuln_sweet32',
	'web_vuln_freak', 'web_vuln_drown', 'web_vuln_logjam']
	for key in web_vul_keys:
		web_vul.append(CHECKS['ssl'][key]['short_title'])

	valid_hsts_keys = ['web_hsts_header_duration', 'web_hsts_preload_prepared']
	for key in valid_hsts_keys:
		valid_hsts.append(CHECKS['ssl'][key]['short_title'])

	other_checks_keys = ['web_cert', 'web_pfs', 'web_vuln_rc4', 'web_vuln_fallback_scsv']
	for key in other_checks_keys:
		other_checks.append(CHECKS['ssl'][key]['short_title'])

	security_checks_keys = ['header_csp', 'header_xfo', 'header_xssp', 'header_xcto', 'header_ref']
	for key in security_checks_keys:
		security_checks.append(CHECKS['security'][key]['short_title'])

	########################## HTTPS check #####################################
	https_offered = CHECKS['ssl']['https_scan_finished']['short_title']
	https_data = donut_chart_single(melted_data2, https_offered, 'https_scan_finished', 'ssl')

	#############################################################################

	########################## Valid HSTS check #################################
	valid_hsts_check = CHECKS['ssl']['web_hsts_header']['short_title']
	hsts_valid_data = donut_chart_single(melted_data2, valid_hsts_check, 'web_hsts_header', 'ssl')

	#############################################################################

	hsts_included = CHECKS['ssl']['web_hsts_preload_listed']['short_title']
	hsts_included_data = donut_chart_single(melted_data2, hsts_included, 'web_hsts_preload_listed', 'ssl')
	############################################################################

	hsts_valid  = melted_data2.loc[melted_data2['check'].isin(valid_hsts)]
	hsts_groups = donut_chart(melted_data2, valid_hsts, valid_hsts_keys, 'ssl')

	############################################################################

	############################ Web Security ##################################
	security_data = melted_data2.loc[melted_data2['check'].isin(security_checks)]

	security_groups = OrderedDict()
	security_groups = donut_chart(security_data, security_checks, security_checks_keys, 'security')

	########################### OTHER checks ###################################
	other_groups = OrderedDict()
	other_groups = donut_chart(melted_data2, other_checks, other_checks_keys, 'ssl')

	############################################################################


	vul_data = melted_data2.loc[melted_data2['check'].isin(web_vul)]

	melted_data2 = melted_data2.loc[melted_data2['check'].isin(ssl_support)]

	melted_data2['check'] = pd.Categorical(
	    melted_data2['check'],
	    categories=ssl_support,
	    ordered=True
	)
	melted_data2 = melted_data2.sort_values('check')

	checks = melted_data2['check'].unique()
	vul_checks = vul_data['check'].unique()

	my = round(melted_data / (melted_data.groupby(level = [0]).transform(sum)) * 100, 1).reset_index(name="percentage")
	my['value'] = my['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})

	#my = my[my['check'].isin(ssl_support)].reindex()
	my = my.loc[my['check'].isin(ssl_support)]

	######################## SSL support #############################
	described_groups = column_chart(melted_data2, checks)

	################# Protection against attacks #####################
	described_vul = column_chart(vul_data, vul_checks)

	return described_groups, described_vul, hsts_groups, hsts_valid_data, hsts_included_data, https_data, other_groups, security_groups

def enc_mail_results(myList = []) -> OrderedDict:
	df = myList
	tls_group = []
	vul_group = []
	mydict = []

	for check, data in CHECKS['mx'].items():
		mydict.append(data.get('short_title'))

	melted_data = pd.melt(df, id_vars=['url'], value_vars=mydict, var_name='check', value_name='value')
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
		mx_enc_support = (mx_support, [CHECKS['mx']['mx_scan_finished']['frontend_title'].get('bad'), CHECKS['mx']['mx_scan_finished']['frontend_title'].get('good')], [mx_enc_failed, pass_per['count'].values[0]], pass_percentage)
	else:
		mx_enc_support = []
	#######################################################

	############## Check TLS/SSL support ##################
	tls_ssl = []
	ssl_support_keys = ['mx_insecure_protocols_sslv2', 'mx_insecure_protocols_sslv3', 'mx_secure_protocols_tls1',
	'mx_secure_protocols_tls1_1', 'mx_secure_protocols_tls1_2']

	for key in ssl_support_keys:
		tls_ssl.append(CHECKS['mx'][key]['short_title'])

	tls_data = melted_data2.loc[melted_data2['check'].isin(tls_ssl)]

	tls_data['check'] = pd.Categorical(
	    tls_data['check'],
	    categories=tls_ssl,
	    ordered=True
	)
	tls_data = tls_data.sort_values('check')
	checks = tls_data['check'].unique()

	tls_group = column_chart(tls_data, checks)

	############## Check vulnerabilities ##################
	vul_checks = []
	vul_keys = ['mx_vuln_heartbleed', 'mx_vuln_ccs', 'mx_vuln_ticketbleed', 'mx_vuln_secure_renego',
	'mx_vuln_secure_client_renego', 'mx_vuln_crime', 'mx_vuln_breach', 'mx_vuln_poodle', 'mx_vuln_sweet32',
	'mx_vuln_freak', 'mx_vuln_drown', 'mx_vuln_logjam']

	for key in vul_keys:
		vul_checks.append(CHECKS['mx'][key]['short_title'])

	vul_data = melted_data2.loc[melted_data2['check'].isin(vul_checks)]
	vul_group = column_chart(vul_data, vul_checks)

	return mx_enc_support, tls_group, vul_group

def web_privacy_results(myList = []) -> OrderedDict:
	df = myList
	mydict = []
	check_keys = []
	privacy_groups = OrderedDict()
	google_group = OrderedDict()
	df.drop('country', axis=1, inplace=True)
	df.drop('mx_country', axis=1, inplace=True)
	df.drop('url', axis=1, inplace=True)

	for check, data in CHECKS['privacy'].items():
		check_keys.append(check)
		mydict.append(data.get('short_title'))

	result = df.reindex(columns=mydict)
	#result = result.apply(lambda x: pd.value_counts(x, normalize=True)).replace(to_replace='None', value=np.nan).dropna()
	#result = result.apply(pd.value_counts).replace(to_replace='None', value=np.nan).dropna()
	result = result.apply(pd.value_counts).fillna(0)
	result[mydict] = result[mydict].astype(int)
	if 'None' in result.index:
		result.drop('None', inplace=True) #drop None index

	for check, check_key in zip(result.columns, check_keys):
		query      = result[check]
		pass_count = query[1] if '1' in result.index else 0
		fail_count = query[0] if '0' in result.index else 0
		pass_per   = round((pass_count / (pass_count + fail_count)) * 100, 1)
		check = check.replace("&", "and")
		title_array = [CHECKS['privacy'][check_key]['frontend_title'].get('bad'), CHECKS['privacy'][check_key]['frontend_title'].get('good')]
		privacy_groups[check] = (title_array, [fail_count, pass_count], float(pass_per))

	return privacy_groups, google_group

def association(myList = [], min_supp = 0.1, confidence=0.1):
    df = myList
    df = df.drop('url', axis=1)
    df = df.drop('country', axis=1)
    df = df.drop('mx_country', axis=1)
    df = df.replace('None', np.nan)

    print("Total rows before : ", int(df.shape[0]))

    df['missing_val'] = df.isnull().sum(axis=1)
#       df = df[df['missing_val'] <= np.ceil(df['missing_val'].mean())]

    print("Average missing values in each transaction = ", float(np.ceil(df['missing_val'].mean())))
#       print("Total rows after dropping avg. missing value rows : ", int(df.shape[0]))
    df = df.drop('missing_val', axis=1)

#       df = df.iloc[:, :-30]
#       df = df.iloc[30000:]

    df =df[(df['Server offers HTTPS'] == '1') & (df['Mail server supports encryption'] == '1')]

    restricted_columns = ['Sites setting first party cookies', 'Sites setting third party cookies' ,
    'Google Analytics privacy extension enabled', 'HTTP URL also reachable via HTTPS',
    'HSTS header duration sufficient', 'Server ready for HSTS preloading', 'Web server Protected against Secure Renegotiation',
    'Included in Chrome HSTS preload list', 'Web server supports SSL 2.0', 'Server offers HTTPS', 'Mail server supports encryption',
    'Mail server supports SSL 2.0', 'Mail server Protected against Secure Renegotiation',
    'Mail server Protected against Heartbleed', 'Web server Protected against Heartbleed', 'Web server Protected against BEAST', 'Mail server Protected against BEAST',
    'Mail server Protected against LOGJAM', 'Web server Protected against LOGJAM', 'Web server Protected against LUCKY13', 'Mail server Protected against LUCKY13',
    'Mail server Protected against CRIME', 'Web server Protected against CRIME', 'Mail server Protected against CCS attack',
    'Web server Protected against CCS attack', 'Mail server Protected against DROWN', 'Web server Protected against DROWN',
    'Mail server Protected against FREAK', 'Web server Protected against FREAK', 'Mail server Protected against BREACH', 'Domain has Mail server',
    'Mail server Protected against Ticketbleed', 'Web server Protected against Ticketbleed', 'Valid Public Key Pins']

    for column in restricted_columns:
            if column in df.columns:
                    df.drop([column], axis=1, inplace=True)
    print(df.isnull().sum())

    df = df.apply(lambda x: x.fillna(random.choice(['0', '1'])), axis=1)

    input_assoc_rules = df
    print(df.columns)

    print("Total rows = ", int(df.shape[0]))
    print("Total columns = ", int(df.shape[1]))
    total_rows = int(df.shape[0])

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
        if len(Q) == 1 and Q]

    restricted_ante = ['Mail server supports SSL 3.0=0', 'Web server supports SSL 3.0=0', 'Web server supports TLS 1.1=1', 'Web server supports TLS 1.2=1',
    'Mail server supports TLS 1.1=1', 'Mail server supports TLS 1.2=1', 'Mail server Protected against BREACH=1',
    'Mail server supports Legacy TLS 1.0=1', 'Web server supports Legacy TLS 1.0']

    print("Step 1: Rules generated")

    names = {item: '{}={}'.format(var.name, val)
            for item, var, val in OneHot.decode(mapping, data_gro_1, mapping)}

    print("Step 2: Decoded")

    eligible_ante = [v for k,v in names.items()] #allowed both 0 and 1
    N = input_assoc_rules.shape[0]
    print(N)
    rule_stats = list(rules_stats(rules, itemsets, N))

    print("Step 3: Stats for rules generated")
    rule_list_df = []

    rule_list_df = []
    for ex_rule_frm_rule_stat in rule_stats:
        ante = ex_rule_frm_rule_stat[0]
        cons = ex_rule_frm_rule_stat[1]
        named_cons = names[next(iter(cons))]

        #named_cons = [names[i] for i in cons if names[i] in eligible_ante]
        #named_cons = ', '.join(named_cons)
        #if named_cons in eligible_ante:
        rule_lhs = [names[i] for i in ante if names[i] in eligible_ante]
        ante_rule = ', '.join(rule_lhs)
        if ante_rule and named_cons not in restricted_ante and len(rule_lhs)>1:
            rule_dict = {'support' : ex_rule_frm_rule_stat[2],
                         'confidence' : ex_rule_frm_rule_stat[3],
                     'lift' : ex_rule_frm_rule_stat[6],
                     'antecedent': ante_rule,
                     'consequent':named_cons }
            rule_list_df.append(rule_dict)
    rules_df = pd.DataFrame(rule_list_df)
    print("Raw rules data frame of {} rules generated".format(rules_df.shape[0]))
#       rules_df = rules_df[['antecedent','consequent', 'support','confidence','lift']].sort_values(['support','confidence'], ascending=False).groupby('consequent').head(10).to_csv(sep=' ', index=False, $
    #print(rules_df.to_csv(sep=' ', index=False, header=False))
    if not rules_df.empty:
        rules_df['support'] = rules_df['support'].apply(lambda x: x/total_rows)
        rules_df = rules_df[rules_df['lift']>= 1]
        #pruned_rules_df = rules_df.groupby(['antecedent','consequent']).max().reset_index()
        rules_df = rules_df[['antecedent','consequent', 'support','confidence', 'lift']].sort_values(['lift'], ascending=False)
#        rules_df = rules_df[['antecedent','consequent', 'support','confidence','lift']].sort_values(['lift'], ascending=False).groupby('consequent').head(10)
        rules_df.to_csv(os.path.join('/repos/djangoapp/', "association_"+time.ctime()+".csv") , sep='\t', index=False)
#        print(rules_df.to_csv(sep=' ', index=False, header=False))
    else:
        print("Unable to generate any rule")

def association_without_TLS(myList = [], min_supp = 0.1, confidence=0.1):
    df = myList
    df = df.drop('url', axis=1)
    df = df.drop('country', axis=1)
    df = df.drop('mx_country', axis=1)
    df = df.replace('None', np.nan)

    print("Total rows before : ", int(df.shape[0]))

    allowed_columns = ['Sites using third party embeds', 'Sites using trackers', 'Sites using Google Analytics',
    'Google Analytics privacy extension enabled', 'Web & mail servers in same country',
    'Content Security Policy header set', 'X-Frame-Options header set', 'Secure XSS Protection header set',
    'Secure X-Content-Type-Options header set', 'Referrer Policy header set', 'Server offers HTTPS',
    'Mail server supports encryption', 'Unintentional information leaks']

    for column in df.columns:
        if column not in allowed_columns:
                df.drop([column], axis=1, inplace=True)
    print("Sum of missing values:")
    print(df.isnull().sum())

    df = df.apply(lambda x: x.fillna(random.choice(['0', '1'])), axis=1)

    input_assoc_rules = df
    print(df.columns)

#    file_df = pd.read_csv(os.path.join('/repos/djangoapp/', "association_Sun_Mar.csv") , sep='\t')
 #   print(file_df.to_csv(sep=' ', index=False))

    print("Total rows = ", int(df.shape[0]))
    print("Total columns = ", int(df.shape[1]))
    total_rows = int(df.shape[0])

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
        if len(Q) == 1 and Q]

    restricted_ante = ['Mail server supports encryption=1', 'Server offers HTTPS=1']

    print("Step 1: Rules generated")

    names = {item: '{}={}'.format(var.name, val)
            for item, var, val in OneHot.decode(mapping, data_gro_1, mapping)}

    print("Step 2: Decoded")

    eligible_ante = [v for k,v in names.items()] #allowed both 0 and 1
    N = input_assoc_rules.shape[0]
    print(N)
    rule_stats = list(rules_stats(rules, itemsets, N))

    print("Step 3: Stats for rules generated")
    rule_list_df = []

    rule_list_df = []
    for ex_rule_frm_rule_stat in rule_stats:
        ante = ex_rule_frm_rule_stat[0]
        cons = ex_rule_frm_rule_stat[1]
        named_cons = names[next(iter(cons))]

        #named_cons = [names[i] for i in cons if names[i] in eligible_ante]
        #named_cons = ', '.join(named_cons)
        #if named_cons in eligible_ante:
        rule_lhs = [names[i] for i in ante if names[i] in eligible_ante]
        ante_rule = ', '.join(rule_lhs)
        if ante_rule and named_cons not in restricted_ante and len(rule_lhs)>0:
            rule_dict = {'support' : ex_rule_frm_rule_stat[2],
                         'confidence' : ex_rule_frm_rule_stat[3],
                         'lift' : ex_rule_frm_rule_stat[6],
                     'antecedent': ante_rule,
                     'consequent':named_cons }
            rule_list_df.append(rule_dict)
    rules_df = pd.DataFrame(rule_list_df)

    print("Raw rules data frame of {} rules generated".format(rules_df.shape[0]))

    if not rules_df.empty:
        rules_df['support'] = rules_df['support'].apply(lambda x: x/total_rows)
        rules_df = rules_df[rules_df['lift']>= 1]
#        rules_df = rules_df[['antecedent','consequent', 'support','confidence', 'lift']].sort_values(['lift'], ascending=False).groupby('consequent').head(10)
        rules_df = rules_df[['antecedent','consequent', 'support','confidence', 'lift']].sort_values(['lift'], ascending=False)
#        print(pd.merge(rules_df, file_df, how='inner', on=['antecedent', 'consequent']).to_csv(sep=' ', index=False))
        rules_df.to_csv(os.path.join('/repos/djangoapp/', "asso_without_tls"+time.ctime()+".csv") , sep='\t', index=False)
#        print(rules_df.to_csv(sep=' ', index=False, header=False))
    else:
        print("Unable to generate any rule")

def enc_web_trends(myList = []) -> OrderedDict:
	ssl_support = []
	security_checks = []
	hsts_checks = []
	web_vul_checks = []
	ssl_data = OrderedDict()
	security_data = OrderedDict()
	other_data = OrderedDict()
	https_data = OrderedDict()
	web_vul_data = OrderedDict()
	web_vul_data_1 = OrderedDict()

	ssl_support_keys = ['web_insecure_protocols_sslv2', 'web_insecure_protocols_sslv3', 
	'web_secure_protocols_tls1', 'web_secure_protocols_tls1_1', 'web_secure_protocols_tls1_2']
	for key in ssl_support_keys:
		ssl_support.append(CHECKS['ssl'][key]['short_title'])

	time_data = AnalysisTimeSeries.objects.all().order_by('id')
	for check in ssl_support:
		percentage = []
		total_sites = []
		analysis_dates = []

		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
			#total_sites.append(len(data.analysis.category.values('result')))
			date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
			analysis_dates.append(date)
		check = check.replace('Web server supports ', '')
		ssl_data[check] = percentage
	###############################################################################################
	security_checks_keys = ['header_csp', 'header_xfo', 'header_xssp', 'header_xcto', 'header_ref']
	for key in security_checks_keys:
		security_checks.append(CHECKS['security'][key]['short_title'])

	for check in security_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		security_data[check] = percentage
	###############################################################################################
	valid_hsts_keys = ['web_hsts_header', 'web_cert', 'web_pfs', 'web_vuln_rc4', 'web_vuln_fallback_scsv']
	for key in valid_hsts_keys:
		hsts_checks.append(CHECKS['ssl'][key]['short_title'])

	for check in hsts_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		other_data[check] = percentage
	##############################################################################################
	percentage = []
	for data in time_data:
		df = pd.read_json(data.result)
		query = df[df['check'] == 'Server offers HTTPS']
		percentage.append(query['percentage'].values[0])
	https_data['Server offers HTTPS'] = percentage
	##############################################################################################
	web_vul_keys = ['web_vuln_breach', 'web_vuln_poodle', 'web_vuln_sweet32',
	'web_vuln_freak', 'web_vuln_drown', 'web_vuln_logjam']
	for key in web_vul_keys:
		web_vul_checks.append(CHECKS['ssl'][key]['short_title'])

	for check in web_vul_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		check = check.replace('Web server ', '')
		web_vul_data[check] = percentage

	web_vul_checks = []
	web_vul_keys = ['web_vuln_heartbleed', 'web_vuln_ccs', 'web_vuln_ticketbleed', 'web_vuln_secure_renego',
	'web_vuln_secure_client_renego', 'web_vuln_crime']
	for key in web_vul_keys:
		web_vul_checks.append(CHECKS['ssl'][key]['short_title'])

	for check in web_vul_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		check = check.replace('Web server ', '')
		web_vul_data_1[check] = percentage

	return ssl_data, analysis_dates, security_data, other_data, https_data, web_vul_data, web_vul_data_1

def enc_mail_trends(myList = []) -> OrderedDict:
	ssl_support = []
	https_data = OrderedDict()
	ssl_data = OrderedDict()
	web_vul_data = OrderedDict()
	web_vul_data_1 = OrderedDict()
	time_data = AnalysisTimeSeries.objects.all().order_by('id')

	percentage = []
	for data in time_data:
		df = pd.read_json(data.result)
		query = df[df['check'] == 'Mail server supports encryption']
		query1 = df[df['check'] == 'Domain has Mail server']
		print(query)
		print(query1)
		final_val = round((query['count'].values[0] / query1['count'].values[0]) * 100, 1)
		percentage.append(final_val)
	https_data['Mail server supports encryption'] = percentage
	#################################################################################################
	ssl_support_keys = ['mx_insecure_protocols_sslv2', 'mx_insecure_protocols_sslv3', 'mx_secure_protocols_tls1',
	'mx_secure_protocols_tls1_1', 'mx_secure_protocols_tls1_2']
	for key in ssl_support_keys:
		ssl_support.append(CHECKS['mx'][key]['short_title'])

	for check in ssl_support:
		percentage = []
		total_sites = []
		analysis_dates = []

		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
			date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
			analysis_dates.append(date)
		check = check.replace('Mail server supports ', '')
		ssl_data[check] = percentage
	###############################################################################################
	web_vul_checks = []
	web_vul_keys = ['mx_vuln_heartbleed', 'mx_vuln_ccs', 'mx_vuln_ticketbleed', 'mx_vuln_secure_renego',
	'mx_vuln_secure_client_renego', 'mx_vuln_crime']
	for key in web_vul_keys:
		web_vul_checks.append(CHECKS['mx'][key]['short_title'])

	for check in web_vul_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		check = check.replace('Mail server ', '')
		web_vul_data[check] = percentage

	web_vul_checks = []
	web_vul_keys = ['mx_vuln_breach', 'mx_vuln_poodle', 'mx_vuln_sweet32',
	'mx_vuln_freak', 'mx_vuln_drown', 'mx_vuln_logjam']
	for key in web_vul_keys:
		web_vul_checks.append(CHECKS['mx'][key]['short_title'])

	for check in web_vul_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		check = check.replace('Mail server ', '')
		web_vul_data_1[check] = percentage

	return ssl_data, analysis_dates, https_data, web_vul_data, web_vul_data_1

def privacy_trends(myList = []) -> OrderedDict:
	privacy_checks = []
	privacy_data = OrderedDict()
	privacy_data_1 = OrderedDict()
	time_data = AnalysisTimeSeries.objects.all().order_by('id')

	embeds_keys = ['third_parties', 'third_party-trackers', 'cookies_3rd_party',
	'cookies_1st_party']
	for key in embeds_keys:
		privacy_checks.append(CHECKS['privacy'][key]['short_title'])

	for check in privacy_checks:
		percentage = []
		total_sites = []
		analysis_dates = []

		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
			date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
			analysis_dates.append(date)
		privacy_data[check] = percentage
	###############################################################################################
	other_keys = ['google_analytics_present', 'google_analytics_anonymizeIP_not_set', 'server_locations', 'leaks']
	privacy_checks = []
	for key in other_keys:
		privacy_checks.append(CHECKS['privacy'][key]['short_title'])

	for check in privacy_checks:
		percentage = []
		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
		privacy_data_1[check] = percentage

	return privacy_data, privacy_data_1, analysis_dates
