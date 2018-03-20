import os
import json
import pandas as pd

from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis, ScanList, ScanResult

class Command(BaseCommand):
	help = 'Find associations from train and test association rules.'

	def handle(self, *args, **options):
		file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_without_tls_maj.csv") , sep='\t')
		file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_without_tls_ohne.csv") , sep='\t')
		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
		merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
		print(merged_df_sort.to_csv(sep=' '))
		print(merged_df_sort.shape[0])

		file_df = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_maj.csv") , sep='\t')
		file_df_1 = pd.read_csv(os.path.join('/home/waleed/Desktop', "asso_with_tls_ohne.csv") , sep='\t')
		merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
		merged_df_sort = merged_df.sort_values(['lift_x'], ascending=False).groupby('consequent').head(5)
		print(merged_df_sort.to_csv(sep=' '))
		print(merged_df_sort.shape[0])
