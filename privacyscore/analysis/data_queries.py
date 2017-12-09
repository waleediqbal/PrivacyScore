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

#countries with most issues in each category
def country_category_list(myList = []) -> OrderedDict:
	df = pd.DataFrame(myList, columns = ['group', 'country', 'category'])
	df = df.dropna()

	top_country_groups = OrderedDict()
    #issues in countries w.r.t category
	for group in RESULT_GROUPS.values():
		df_group = df[df['group'] == group['short_name']]
		dee = df_group.groupby(['country', 'category']).size()
		dee = dee.fillna(0).astype(int)
		
		d = json.loads(dee.unstack().to_json())
		d['0.0'] = {k: v for k, v in d['0.0'].items() if v!=None} #remove None values
		d['0.0'] = {k: int(v) for k, v in d['0.0'].items()} #convert values to int 
		print(group['short_name'])
	    
		data_count = (sorted(d['0.0'].values()))[-10:]
		country_count = (sorted(d['0.0'], key=d['0.0'].__getitem__))[-10:]

		my_array1 = {'items':[]}
		for cnt, ctry in zip(data_count, country_count):
			d1 = {}
			d1['name'] = ctry
			d1['y'] = cnt
			my_array1.get('items').append(d1)
		
		top_country_groups[group['name']] = my_array1['items']

	return top_country_groups

# top 10 countries with most issues with respect to individual categories
def country_issues_category_list(myList = []) -> OrderedDict:

	df = pd.DataFrame(myList, columns = ['group', 'title', 'category', 'country'])
	df = df.dropna()

	described_country_groups = OrderedDict()
	#country checks
	for group in RESULT_GROUPS.values():
		df_group = df[df['group'] == group['short_name']]
		dee = df_group.groupby(['title', 'country', 'category'])['category'].count()

		my = round(dee / (dee.groupby(level = [0,2]).transform(sum)) * 100, 2).reset_index(name="percentage")

		my['category'] = my['category'].map({0.0: 'bad', 1.0: 'good'})

		de1 = ((my[my['category'] == 'bad']).sort_values(by=['title', 'percentage'], ascending=[False, False]))
#		de1 = de1.groupby('title')
#		print(de1.head(5))
        
		de1.drop_duplicates('title', inplace = True)
        
		new1 = de1.nlargest(10, columns=['percentage'])
        
		mx = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)

		title_array = list(mx['title'].values())
		per_array = list(mx['percentage'].values())
		country_array = list(mx['country'].values())

		zipped = [list(t) for t in zip(title_array, country_array)]

		described_country_groups[group['name']] = (zipped, per_array)

	return described_country_groups

# top 10 issues with respect to individual categories
def issues_category_list(myList = []) -> OrderedDict:
	df = pd.DataFrame(myList, columns = ['group', 'title', 'category'])
	df = df.dropna()

	title_array = []
	per_array = []
	described_groups = OrderedDict()
	for group in RESULT_GROUPS.values():
		df_group = df[df['group'] == group['short_name']]
		dee = df_group.groupby(['title', 'category'])['category'].count().reset_index(name="count")
		dee['category'] = dee['category'].map({0.0: 'bad', 1.0: 'good'})
		
		new1 = dee[dee['category'] == 'bad'].sort_values(by='count', ascending=False)

		new1['percentage'] = round(100 * new1['count']  / new1['count'].sum(), 2)
		new1 = new1.nlargest(10, columns=['percentage'])
		mx = json.loads(new1.to_json(), object_pairs_hook=OrderedDict)

		title_array = list(mx['title'].values())
		per_array = list(mx['percentage'].values())

		described_groups[group['name']] = (title_array, per_array)

	return described_groups
