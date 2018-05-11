import os
from time import sleep
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis, ScanList, ScanResult
from privacyscore.utils import normalize_url
from privacyscore.scanner.tasks import process_site


class Command(BaseCommand):
	help = 'Quantify information leaks.'

	def handle(self, *args, **options):
		leaks = []
		scan_list = ScanList.objects.get(id=121) # get majestic-million list in database
		sites = scan_list.sites.all() # for majestic-million
		#sites = Site.objects.all().order_by('id')[:500] # for all websites
		site_count = 0
		for site in sites:
			scan_result = ScanResult.objects.get(scan_id=site.last_scan_id)
			site_res = scan_result.result
			self.stdout.write('Processing site no. {}, {}'.format(site_count, site))
			if site_res and 'leaks' in site_res:
				if len(site_res['leaks']) != 0:
					for key in site_res['leaks']:
						leaks.append(key)
			site_count +=1

		df = pd.DataFrame(leaks)
		df.columns = ['leaks']
		df = df.groupby(['leaks']).size()
