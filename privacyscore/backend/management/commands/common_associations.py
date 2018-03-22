import os
import json
import pandas as pd
import numpy as np
import seaborn as sns

from django.core.management import BaseCommand
from django.utils import timezone
import matplotlib.pyplot as plt

from privacyscore.backend.models import Site, Analysis, ScanList, ScanResult

class Command(BaseCommand):
	help = 'Find associations from train and test association rules.'

	def handle(self, *args, **options):
		file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_without_tls_maj.csv") , sep='\t')
		file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_without_tls_ohne.csv") , sep='\t')
		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
		merged_df['rule_count'] = merged_df.groupby(["consequent"])['consequent'].transform("count")
		merged_df['consequent'] = merged_df["consequent"] + ' (' + merged_df["rule_count"].map(str) + ')'
		res = pd.DataFrame(merged_df.antecedent.str.split(',').tolist(), index=merged_df.consequent).stack()
		res = res.reset_index()[[0, 'consequent']]
		res.columns = ['antecedent', 'consequent']
		res = res.groupby(['consequent', 'antecedent']).size().reset_index(name='count')

		df3 = pd.pivot_table(res,  values='count',  columns=['antecedent'],  index = ["consequent"])
		# df4 = pd.pivot_table(res, values='antecedent', index='consequent', columns=['antecedent'], aggfunc=np.sum)

		#df3.plot(subplots=False, kind='barh')
		plt.figure(figsize=(10, 10))
		#sns.set(font_scale=0.7)
		sns.heatmap(df3,annot=True,cmap='Blues', fmt='g', cbar_kws={'label': 'No .of rules'})
		plt.tight_layout()
		plt.show()

#		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
#		merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
#		print(merged_df_sort.to_csv(sep=' '))
#		print(merged_df_sort.shape[0])

		# file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_maj.csv") , sep='\t')
		# file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_ohne.csv") , sep='\t')
		# merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
		# merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
		# print(merged_df_sort.to_csv(sep=' '))
		# print(merged_df_sort.shape[0])
