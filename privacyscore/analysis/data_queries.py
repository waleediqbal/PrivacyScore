import csv
import json
import re
import collections
import pandas as pd
import matplotlib.pyplot as plt
import mpld3
from tkinter import *
from collections import Counter, defaultdict
from collections import OrderedDict
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS
from privacyscore.analysis.default_checks import CHECKS

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

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')

		melted_data = melted_data.groupby(by=['country', 'value'])['value'].size()

		#dee = df_group.groupby(['country', 'category']).size()
		melted_data = melted_data.fillna(0).astype(int)
		
		d = json.loads(melted_data.unstack().to_json())
		print(d)
		d['0.0'] = {k: v for k, v in d['0.0'].items() if v!=None} #remove None values
		d['0.0'] = {k: int(v) for k, v in d['0.0'].items()} #convert values to int
	    
		data_count = (sorted(d['0.0'].values()))[-10:]
		country_count = (sorted(d['0.0'], key=d['0.0'].__getitem__))[-10:]

		my_array1 = {'items':[]}
		for cnt, ctry in zip(data_count, country_count):
			d1 = {}
			d1['name'] = ctry
			d1['y'] = cnt
			my_array1.get('items').append(d1)
		
		top_country_groups[group] = my_array1['items']

	return top_country_groups

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

		melted_data = pd.melt(df, id_vars=['country'], value_vars=mydict, var_name='check', value_name='value')

		melted_data = melted_data.groupby(by=['check', 'country', 'value'])['value'].count()
		my = round(melted_data / (melted_data.groupby(level = [0,2]).transform(sum)) * 100, 2).reset_index(name="percentage")
		#print(my.info(memory_usage='deep'))
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
	#df = df.dropna()
	#df.set_index('group', inplace=True)

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
		
		new1 = melted_data[melted_data['value'] == 'bad'].sort_values(by='count', ascending=False)

		new1['percentage'] = round(100 * new1['count']  / new1['count'].sum(), 2)
		new1 = new1.nlargest(10, columns=['percentage'])
		mx = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)

		title_array = list(mx['check'].values())
		per_array = list(mx['percentage'].values())

		described_groups[group] = (title_array, per_array)

	return described_groups
