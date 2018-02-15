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

	def handle(self, *args, **options):
		analyse = Analysis.objects.exclude(end__isnull=True).order_by('-end')[0]
		sss = analyse.category.values('result')
		
		df = json_normalize(sss, record_path='result')

		if analyse:
			result = df
			queries.association(result, options['min_support'])
