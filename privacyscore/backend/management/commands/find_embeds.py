import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from django.core.management import BaseCommand
from django.utils import timezone

from privacyscore.backend.models import Site, Analysis, ScanList, ScanResult

class Command(BaseCommand):
	help = 'Find third party embeds and trackers.'

	def handle(self, *args, **options):
		scan_list = ScanList.objects.get(id=121)
		sites = scan_list.sites.all()
		if sites:
			embeds = []
			trackers = []
			site_count = 0
			for site in sites:
				scan_result = ScanResult.objects.get(scan_id=site.last_scan_id)
				site_res = scan_result.result
				self.stdout.write('Processing site no. {}, {}'.format(site_count, site))
				if site_res and 'third_parties' in site_res:
					for key in site_res['third_parties']:
						embeds.append(key)
				if site_res and 'tracker_requests' in site_res:
					for key in site_res['tracker_requests']:
						trackers.append(key)
				site_count +=1

			df = pd.DataFrame(embeds)
			df.columns = ['embeds']
			df = df.groupby(['embeds']).size().nlargest(20)
			df.to_csv("third_parties.csv" , sep='\t', index=True)

			df1 = pd.DataFrame(trackers)
			df1.columns = ['trackers']
			df1 = df1.groupby(['trackers']).size().nlargest(20)
			df1.to_csv("trackers.csv" , sep='\t', index=True)

		df = pd.read_csv(os.path.join('/home/waleed/Desktop', "third_parties.csv") , sep='\t', names=['Embedded third parties', 'Percentage of websites'], header=None)
		df['Percentage of websites'] = round((df['Percentage of websites']/43695) * 100, 1)
		ax = sns.barplot(x='Embedded third parties', y='Percentage of websites', data=df, palette="Blues_d")
		for p in ax.patches:
		    ax.annotate(str(p.get_height()), (p.get_x() * 1.005, p.get_height() * 1.005)) #https://stackoverflow.com/questions/25447700/annotate-bars-with-values-on-pandas-bar-plots
		ax.set_xticklabels(ax.get_xticklabels(), rotation=40, ha="right")
		plt.tight_layout()
		plt.show()
