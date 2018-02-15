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

	def handle(self, *args, **options):
		#queries.association_thread(options['min_support'], options['min_confidence'])
		analyse = Analysis.objects.exclude(end__isnull=True).order_by('-end')[0]
		if analyse:
			analyse_cat = analyse.category.values('result')
			df = json_normalize(analyse_cat, record_path='result')
			queries.association(df, options['min_support'], options['min_confidence'])
