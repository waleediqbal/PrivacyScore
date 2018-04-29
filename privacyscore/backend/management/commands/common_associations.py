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
		file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "iteration_0.csv") , sep='\t')
		file_df.drop('support_x', axis=1, inplace=True)
		file_df.drop('confidence_x', axis=1, inplace=True)
		file_df.drop('lift_x', axis=1, inplace=True)
		file_df.rename(columns={'support_y': 'support', 'confidence_y': 'confidence', 'lift_y': 'lift'}, inplace=True)
		#file_df.plot.scatter('support', 'confidence')
		#plt.scatter(x=file_df.support, y=file_df.confidence, s=file_df.lift)
		print("first run rules {} " , file_df.shape[0])

		file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "iteration_1.csv") , sep='\t')
		print("second run rules {} " , file_df_1.shape[0])
		file_df_2 = pd.read_csv(os.path.join('/home/waleed/Desktop', "iteration_2.csv") , sep='\t')
		print("third run rules {} " , file_df_2.shape[0])
		col_allowed = ['antecedent', 'consequent', 'support_y', 'confidence_y', 'lift_y']
		file_df_1 = file_df_1[col_allowed]
		file_df_2 = file_df_2[col_allowed]
		# calculate intermediate metrics
		file_df_1.rename(columns={'support_y': 'support', 'confidence_y': 'confidence', 'lift_y': 'lift'}, inplace=True)
		file_df_2.rename(columns={'support_y': 'support', 'confidence_y': 'confidence', 'lift_y': 'lift'}, inplace=True)
		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
		merged_df['support'] = merged_df['support_x'] + merged_df['support_y']
		merged_df['confidence'] = merged_df['confidence_x'] + merged_df['confidence_y']
		merged_df['lift'] = merged_df['lift_x'] + merged_df['lift_y']
		col_final = ['antecedent', 'consequent', 'support', 'confidence', 'lift']
		merged_df = merged_df[col_final]
		merged_df = pd.merge(merged_df, file_df_2, how='inner', on=['antecedent', 'consequent'])
		# calculate final metrics
		merged_df['support'] = (merged_df['support_x'] + merged_df['support_y'])/3
		merged_df['confidence'] = (merged_df['confidence_x'] + merged_df['confidence_y'])/3
		merged_df['lift'] = (merged_df['lift_x'] + merged_df['lift_y'])/3
		col_final = ['antecedent', 'consequent', 'support', 'confidence', 'lift']
		merged_df = merged_df[col_final]
		print("final rules {}" , merged_df.shape[0])
		#print(merged_df.sort_values(['lift'], ascending=False).groupby('consequent').head(50))

		# groupby for visualization of rules
		merged_df['rule_count'] = merged_df.groupby(["consequent"])['consequent'].transform("count")
		merged_df['consequent'] = merged_df["consequent"] + ' (' + merged_df["rule_count"].map(str) + ')'
		res = pd.DataFrame(merged_df.antecedent.str.split(',').tolist(), index=merged_df.consequent).stack()
		res = res.reset_index()[[0, 'consequent']]
		res.columns = ['antecedent', 'consequent']
		res['antecedent'] = res['antecedent'].str.strip()
		res = res.groupby(['consequent', 'antecedent'])['antecedent'].size().reset_index(name='count')
		df3 = pd.pivot_table(res,  values='count',  columns=['antecedent'],  index = ["consequent"])
		plt.figure(figsize=(20, 10))
		#sns.set(font_scale=0.7)
		sns.heatmap(df3,annot=True,cmap='Blues', fmt='g', cbar_kws={'label': 'No .of rules'})
		plt.tight_layout()
		plt.show()

# 		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
# 		merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
#		print(merged_df_sort.to_csv(sep=' '))

#		file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_maj.csv") , sep='\t')
#		file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_ohne.csv") , sep='\t')
#		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
#		merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
#		print(merged_df_sort.to_csv(sep=' '))
