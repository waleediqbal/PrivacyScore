import csv
import json
import re
import collections
import pandas as pd
import numpy as np
import Orange
import os
import random
import math as ma
import seaborn as sns
import matplotlib.pyplot as plt
import time

from Orange.data import Domain, DiscreteVariable, ContinuousVariable
from orangecontrib.associate.fpgrowth import *
from tkinter import *
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse
from collections import Counter, defaultdict
from collections import OrderedDict
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS
from privacyscore.analysis.default_checks import CHECKS
from privacyscore.analysis.frontend_data import donut_chart, column_chart, donut_chart_single
from privacyscore.backend.models import Scan, ScanList, Site, ScanResult, Analysis, AnalysisCategory, AnalysisTimeSeries
from pandas.io.json import json_normalize

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

	ssl_support_keys = ['web_insecure_protocols_sslv2', 'web_insecure_protocols_sslv3', 'web_secure_protocols_tls1',
	'web_secure_protocols_tls1_1', 'web_secure_protocols_tls1_2']

	for key in ssl_support_keys:
		ssl_support.append(CHECKS['ssl'][key]['short_title'])

	#melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)
	melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good', '2': 'neutral'})
	query_1  = melted_data2.query('check == "Server offers HTTPS"')
	pass_count_1 = query_1[query_1['value'] == 'good']
	for ssl_ver in ssl_support:
		melted_data2.loc[melted_data2['check'] == ssl_ver, 'total_count'] = pass_count_1['count'].values[0]
		query  = melted_data2.query('check == @ssl_ver')
		pass_count = query[query['value'] == 'good']
		f_count = query['total_count'].values[0] - pass_count['count'].values[0]
		melted_data2.loc[(melted_data2["check"] == ssl_ver) & (melted_data2["value"] == "bad"), "count"] = f_count

	melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

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
	for check in tls_ssl:
		tls_data.loc[tls_data['check'] == check, 'total_count'] = pass_per['count'].values[0]
		query  = melted_data2.query('check == @check')
		pass_count = query[query['value'] == 'good']
		f_count =  pass_per['count'].values[0] - pass_count['count'].values[0]
		tls_data.loc[(tls_data["check"] == check) & (tls_data["value"] == "bad"), "count"] = f_count

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

def association(myList = [], min_supp = 0.1, confidence=0.1, min_lift=1, name=""):
    df = myList
    mydict = []
    for group in DEFAULT_GROUP_ORDER:
        for check, data in CHECKS[group].items():
            mydict.append(data.get('short_title'))

    melted_data = pd.melt(df, id_vars=['url'], value_vars=mydict, var_name='check', value_name='value')

    melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()

    #melted_data.groupby(by=['check', 'value']).size().unstack().plot(kind='bar', stacked=True, figsize=(8,5))
    #plt.show()

    url_all = []
    sites = Site.objects.all()
    print(sites.count())
    for site in sites:
        url_parsed = urlparse(site.url)
        url_all.append(url_parsed.netloc)
    print(len(url_all))
    print(len(list(set(url_all))))

    print("Total rows before : ", int(df.shape[0]))

    df['missing_val'] = df.isnull().sum(axis=1)

    print("Average missing values in each transaction = ", float(np.ceil(df['missing_val'].mean())))
    df = df.drop('missing_val', axis=1)

    #df =df[(df['Server offers HTTPS'] == '1') & (df['Mail server supports encryption'] == '1')]

    restricted_columns = ['Sites setting first party cookies', 'Sites using third party embeds',
    'Google Analytics privacy extension enabled', 'HTTP URL also reachable via HTTPS',
    'HSTS header duration sufficient', 'Server ready for HSTS preloading', 'Web server Protected against Secure Renegotiation',
    'Included in Chrome HSTS preload list', 'Web server supports SSL 2.0', 'Server offers HTTPS', 'Mail server supports encryption',
    'Mail server supports SSL 2.0', 'Mail server Protected against Secure Renegotiation',
    'Mail server Protected against Heartbleed', 'Web server Protected against Heartbleed', 'Web server Protected against BEAST', 'Mail server Protected against BEAST',
    'Mail server Protected against LOGJAM', 'Web server Protected against LOGJAM', 'Web server Protected against LUCKY13', 'Mail server Protected against LUCKY13',
    'Mail server Protected against CRIME', 'Web server Protected against CRIME', 'Mail server Protected against CCS attack',
    'Web server Protected against CCS attack', 'Mail server Protected against DROWN', 'Web server Protected against DROWN',
    'Mail server Protected against FREAK', 'Web server Protected against FREAK', 'Mail server Protected against BREACH', 'Domain has Mail server',
    'Mail server Protected against Ticketbleed', 'Web server Protected against Ticketbleed']

    for column in restricted_columns:
            if column in df.columns:
                    df.drop([column], axis=1, inplace=True)
    print(df.isnull().sum())

    input_assoc_rules = df
    print(df.columns)

    print("Total rows = ", int(df.shape[0]))
    print("Total columns = ", int(df.shape[1]))
    total_rows = int(df.shape[0])

    domain_checks = Domain([DiscreteVariable.make(name=check,values=['0', '1', '1000']) for check in input_assoc_rules.columns])
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
        if ante_rule and len(rule_lhs)>1 and len(rule_lhs)<5:
            rule_dict = {'support' : ex_rule_frm_rule_stat[2],
                         'confidence' : ex_rule_frm_rule_stat[3],
                     'lift' : ex_rule_frm_rule_stat[6],
                     'antecedent': ante_rule,
                     'consequent':named_cons }
            rule_list_df.append(rule_dict)
    rules_df = pd.DataFrame(rule_list_df)
    print("{} association rules generated".format(rules_df.shape[0]))

    if not rules_df.empty:
        rules_df['support'] = rules_df['support'].apply(lambda x: x/total_rows)
        rules_df = rules_df[rules_df['lift']>= float(min_lift)]
        rules_df = rules_df[['antecedent','consequent', 'support','confidence', 'lift']].sort_values(['lift'], ascending=False)
        rules_df.to_csv(os.path.join('/home/sysop/', "tls_"+name+".csv") , sep='\t', index=False)
#        print(rules_df.to_csv(sep=' ', index=False, header=False))
    else:
        print("Unable to generate any rule")

def association_without_TLS(myList = [], min_supp = 0.1, confidence=0.1, min_lift=1, name=""):
    df = myList
    print("Total rows before : ", int(df.shape[0]))

    allowed_columns = ['Sites using trackers', 'Sites setting third party cookies', 'Sites using Google Analytics',
    'Google Analytics privacy extension enabled', 'Web & mail servers in same country',
    'Content Security Policy header set', 'X-Frame-Options header set', 'Secure XSS Protection header set',
    'Secure X-Content-Type-Options header set', 'Referrer Policy header set', 'Server offers HTTPS',
    'Mail server supports encryption', 'Unintentional information leaks']

    for column in df.columns:
        if column not in allowed_columns:
                df.drop([column], axis=1, inplace=True)
    print("Sum of missing values:")
    print(df.isnull().sum())

    input_assoc_rules = df
    print(df.columns)

    print("Total rows = ", int(df.shape[0]))
    print("Total columns = ", int(df.shape[1]))
    total_rows = int(df.shape[0])

    domain_checks = Domain([DiscreteVariable.make(name=check,values=['0', '1', '1000']) for check in input_assoc_rules.columns])
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
        if ante_rule and len(rule_lhs)>1 and len(rule_lhs)<5:
            rule_dict = {'support' : ex_rule_frm_rule_stat[2],
                         'confidence' : ex_rule_frm_rule_stat[3],
                         'lift' : ex_rule_frm_rule_stat[6],
                     'antecedent': ante_rule,
                     'consequent':named_cons }
            rule_list_df.append(rule_dict)
    rules_df = pd.DataFrame(rule_list_df)

    print("{} association rules generated".format(rules_df.shape[0]))

    if not rules_df.empty:
        rules_df['support'] = rules_df['support'].apply(lambda x: x/total_rows)
        rules_df = rules_df[rules_df['lift']>= float(min_lift)]
        rules_df = rules_df[['antecedent','consequent', 'support','confidence', 'lift']].sort_values(['lift'], ascending=False)
        rules_df.to_csv(os.path.join('/home/sysop/', "ohne_tls_"+name+".csv") , sep='\t', index=False)
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

	time_data = AnalysisTimeSeries.objects.all().order_by('-id')[:2][::-1]
	for check in ssl_support:
		percentage = []
		total_sites = []
		analysis_dates = []

		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
			#total_sites.append(len(data.analysis.category.values('result')))
		#	date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
		#	analysis_dates.append(date)
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
		date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
		analysis_dates.append(date + ' (' + str(query['count'].values[0]) + ')')
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
	time_data = AnalysisTimeSeries.objects.all().order_by('-id')[:2][::-1]

	percentage = []
	analysis_dates = []
	for data in time_data:
		df = pd.read_json(data.result)
		query = df[df['check'] == 'Mail server supports encryption']
		query1 = df[df['check'] == 'Domain has Mail server']
		date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
		analysis_dates.append(date + ' (' + str(query['count'].values[0]) + ')')
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

		for data in time_data:
			df = pd.read_json(data.result)
			query = df[df['check'] == check]
			percentage.append(query['percentage'].values[0])
			#date = str(data.analysis.end.day) + '-' + str(data.analysis.end.month) + '-' + str(data.analysis.end.year)
			#analysis_dates.append(date)
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
	time_data = AnalysisTimeSeries.objects.all().order_by('-id')[:2][::-1]

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
