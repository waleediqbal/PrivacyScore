import os
from time import sleep

from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis
from privacyscore.utils import normalize_url
from privacyscore.scanner.tasks import process_site


class Command(BaseCommand):
	help = 'Schedule categorization of sites.'

	def add_arguments(self, parser):
		parser.add_argument('-s', '--sleep-between-scans', type=float, default=0)

	def handle(self, *args, **options):
		analyse = Analysis.objects.create()
		analyse.start = timezone.now()
		analyse.save()

		scan_list = ScanList.objects.filter(id=121).prefetch_columns()
		if scan_list:
			sites = scan_list.first().sites.annotate_most_recent_scan_result().select_related('last_scan')
			analysis = []

			site_count = 0
			for site in sites:
				self.stdout.write('Processing site no. {}, {}'.format(site_count, site))
				process_site.delay(site.last_scan__result, site.id, analyse.id)
				site_count +=1

		analyse.end = timezone.now()
		analyse.save()
