import os
import json
import pandas as pd
import numpy as np

from django.core.management import BaseCommand
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER
from privacyscore.analysis.default_checks import CHECKS
from django.utils import timezone
from pandas.io.json import json_normalize
from collections import OrderedDict

from privacyscore.backend.models import Site, Analysis, ScanList, ScanResult, AnalysisTimeSeries

class Command(BaseCommand):
	help = 'Save data for time series in database.'

	def handle(self, *args, **options):
        default_checks = []
        common_urls = []
        urls = []
        for group in DEFAULT_GROUP_ORDER:
            for check, data in CHECKS[group].items():
                default_checks.append(data.get('short_title'))
        analysis_data = Analysis.objects.exclude(end__isnull=True).order_by('-end')[:2]
        for analysis in analysis_data:
            result = analysis.category.values('result')
            df = json_normalize(result, record_path='result')
            urls.append(df['url'].tolist())

        common_urls = set.intersection(*map(set,urls))
        common_urls = list(common_urls)
        scan_list = ScanList.objects.get(id=121)
        if analysis_data:
            result = analysis_data[0].category.values('result')
            df = json_normalize(result, record_path='result')
            df = df.query('url in @common_urls')

            result_1 = analysis_data[1].category.values('result')
            df_1 = json_normalize(result_1, record_path='result')
            df_1 = df_1.query('url in @common_urls')
            for col in df_1.columns:
                urls = list(df_1.loc[df_1[col] == 'None', 'url'])
                df.loc[df['url'].isin(urls), col] = 'None'
            print("df 1 updated")
            for col in df.columns:
                    urls = list(df.loc[df[col] == 'None', 'url'])
                    df_1.loc[df_1['url'].isin(urls), col] = 'None'
            print("df 2 updated")
            melted_data = pd.melt(df_1, id_vars=['url'], value_vars=default_checks, var_name='check', value_name='value')
            melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()
            melted_data1 = melted_data.groupby(by=['check', 'value'])['value'].count().reset_index(name='count')
            melted_data = melted_data.groupby(['check', 'value'])['value'].count()

            melted_data2 = melted_data.groupby(level = [0]).transform(sum).reset_index(name="total_count")
            melted_data2['count'] = melted_data1['count']
            melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good'})
            melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

            final_df = melted_data2[melted_data2['value']=='good']
            final_df.drop('value', axis=1, inplace=True)
            final_df = final_df.to_json()
            AnalysisTimeSeries.objects.create(
                      analysis_id=analysis_data[1].id,
                      scanlist_id=scan_list.id,
                      result=final_df)

            melted_data = pd.melt(df, id_vars=['url'], value_vars=default_checks, var_name='check', value_name='value')
            melted_data = melted_data.replace(to_replace='None', value=np.nan).dropna()
            melted_data1 = melted_data.groupby(by=['check', 'value'])['value'].count().reset_index(name='count')
            melted_data = melted_data.groupby(['check', 'value'])['value'].count()

            melted_data2 = melted_data.groupby(level = [0]).transform(sum).reset_index(name="total_count")
            melted_data2['count'] = melted_data1['count']
            melted_data2['value'] = melted_data2['value'].map({'0': 'bad', '1': 'good'})
            melted_data2['percentage'] = round((melted_data2['count'] / melted_data2['total_count']) * 100, 1)

            final_df = melted_data2[melted_data2['value']=='good']
            final_df.drop('value', axis=1, inplace=True)
            final_df = final_df.to_json()
            AnalysisTimeSeries.objects.create(
            analysis_id=analysis_data[0].id,
            scanlist_id=scan_list.id,
            result=final_df)
