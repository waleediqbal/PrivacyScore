import os
from time import sleep

from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis, ScanList
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

		# scan_list = ScanList.objects.get(id=121)
		# sites = scan_list.sites.all()
		sites = Site.objects.order_by('-id')[:500]
		if sites:
			site_count = 0
			for site in sites:
				self.stdout.write('Processing site no. {}, {}'.format(site_count, site))
				if site.last_scan:
					process_site.delay(site.id, analyse.id)
				site_count +=1

		analyse.end = timezone.now()
		analyse.save()
