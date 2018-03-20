import os
import json
import pandas as pd

from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis
from pandas.io.json import json_normalize
import privacyscore.analysis.data_queries as queries


class Command(BaseCommand):
	help = 'Find associations between checks.'

	def add_arguments(self, parser):
		parser.add_argument('min_support')
		parser.add_argument('min_confidence')
		parser.add_argument('with_tls')

	def handle(self, *args, **options):
		analyse = Analysis.objects.exclude(end__isnull=True).order_by('-end')[0]
		if analyse:
			analyse_cat = analyse.category.values('result')
			df = json_normalize(analyse_cat, record_path='result')
			if options['with_tls'] == 'Y' or options['with_tls'] == 'yes':
				queries.association(df, options['min_support'], options['min_confidence'])
			else:
				queries.association_without_TLS(df, options['min_support'], options['min_confidence'])
