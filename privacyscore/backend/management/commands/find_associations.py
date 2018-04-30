import os
import json
import pandas as pd

from django.core.management import BaseCommand
from django.utils import timezone
from sklearn.model_selection import train_test_split

from privacyscore.backend.models import Site, Analysis
from pandas.io.json import json_normalize
import privacyscore.analysis.data_queries as queries


class Command(BaseCommand):
	help = 'Find associations between checks.'

	def add_arguments(self, parser):
		parser.add_argument('min_support')
		parser.add_argument('min_confidence')
		parser.add_argument('min_lift')
		parser.add_argument('test_cycles')
		parser.add_argument('with_tls')

	def handle(self, *args, **options):
		supp = options['min_support']
		conf = options['min_confidence']
		lift = options['min_lift']
		cycles = options['test_cycles']
		analyse = Analysis.objects.exclude(end__isnull=True).order_by('-end')[0]
		if analyse:
			results = analyse.category.values('result')
			df = json_normalize(results, record_path='result')
			df = df.drop('url', axis=1)
			df = df.drop('country', axis=1)
			df = df.drop('mx_country', axis=1)
			df = df.replace('None', '1000')
			for x in range(0, int(cycles)):
				if options['with_tls'] == 'Y' or options['with_tls'] == 'yes':
					df_1 = df[(df['Server offers HTTPS'] == '1') & (df['Mail server supports encryption'] == '1')]
					train, test = train_test_split(df_1, test_size=0.4)
					queries.association(train, supp, conf, lift, "train_" + str(x))
					queries.association(test, supp, conf, lift, "test_"+ str(x))
					file_df = pd.read_csv(os.path.join('/home/sysop/', "tls_"+"train_" + str(x)+".csv") , sep='\t')
					file_df_1 = pd.read_csv(os.path.join('/home/sysop/', "tls_"+ "test_" + str(x) +".csv") , sep='\t')
					merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
					merged_df.to_csv(os.path.join('/home/sysop/', "iteration_"+str(x)+".csv") , sep='\t', index=False)
				else:
					train, test = train_test_split(df, test_size=0.4)
					queries.association_without_TLS(train, supp, conf, lift, "train_"+ str(x))
					queries.association_without_TLS(test, supp, conf, lift, "test_"+ str(x))
					file_df = pd.read_csv(os.path.join('/home/sysop/', "ohne_tls_"+"train_" + str(x)+".csv") , sep='\t')
					file_df_1 = pd.read_csv(os.path.join('/home/sysop/', "ohne_tls_"+ "test_" + str(x) +".csv") , sep='\t')
					merged_df = pd.merge(file_df, file_df_1, how='inner', on=['antecedent', 'consequent'])
					merged_df.to_csv(os.path.join('/home/sysop/', "ohne_iteration_"+str(x)+".csv") , sep='\t', index=False)
