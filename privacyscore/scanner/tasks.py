import os
from getpass import getuser
import signal
import traceback
import pandas as pd
from typing import List, Tuple
from socket import getfqdn

from celery import chord, shared_task, group
from django.conf import settings
from django.utils import timezone

from privacyscore.backend.models import RawScanResult, Scan, ScanResult, \
    ScanError, Site, Analysis, AnalysisCategory, ScanList
from privacyscore.scanner.test_suites import AVAILABLE_TEST_SUITES, \
    TEST_PARAMETERS, SCAN_TEST_SUITE_STAGES
from privacyscore.utils import get_processes_of_user
from privacyscore.evaluation.result_groups import DEFAULT_GROUP_ORDER, RESULT_GROUPS


class Timeout:
    def __init__(self, seconds=1):
        self.seconds = seconds

    def __enter__(self):
        def handle_timeout(signum, frame):
            # kill all possible processes
            # TODO: this is a really bad idea
            # TODO: Especially with multiple worker threads, bad things are inevitable
            own_procs = get_processes_of_user(getuser())
            for pid, cmdline in own_procs:
                # TODO: Argh
                if '/tests/' not in cmdline:
                    continue
                os.kill(pid, 9)
            raise TimeoutError

        signal.signal(signal.SIGALRM, handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


@shared_task(queue='master')
def schedule_scan(scan_pk: int):
    """Prepare and schedule a scan."""
    scan = Scan.objects.get(pk=scan_pk)
    scan.start = timezone.now()
    scan.save()

    # Schedule next stage
    schedule_scan_stage(
        (getfqdn(), 'privacyscore.scanner.tasks.schedule_scan', [], {}),
        {},
        scan_pk)


@shared_task(queue='master')
def schedule_scan_stage(new_results: Tuple[list, dict, dict],
                        previous_results: Tuple[list, dict, dict],
                        scan_pk: int,
                        stage: int = 0,
                        previous_task_count: int = 0):
    """Schedule the next stage for a scan."""
    scan = Scan.objects.get(pk=scan_pk)

    if previous_task_count <= 1:
        new_results = [new_results]
    raw_data, new_results, errors = _parse_new_results(new_results)
    previous_results.update(new_results)

    # store raw data in database
    for params in raw_data:
        RawScanResult.store_raw_data(scan_pk=scan_pk, **params)

    # store errors in database
    for error in errors:
        test = None
        if ':' in error:
            scan_host, test, error = error.split(':', maxsplit=2)
        ScanError.objects.create(
            scan_host=scan_host, scan=scan, test=test, error=error)

    if stage >= len(SCAN_TEST_SUITE_STAGES):
        # all stages finished.
        handle_finished_scan(scan)

        # store final results
        ScanResult.objects.create(
            scan=scan, result=previous_results)

        return True

    tasks = []
    for test_suite in SCAN_TEST_SUITE_STAGES[stage]:
        tasks.append(run_test.s(test_suite, scan.site.url, previous_results))
    chord(tasks, schedule_scan_stage.s(previous_results, scan_pk, stage + 1, len(tasks))).apply_async()


def handle_finished_scan(scan: Scan):
    """
    Callback when all stages of tasks for a scan are completed.
    """
    scan.end = timezone.now()
    scan.save()


@shared_task(queue='slave')
def run_test(test_suite: str, url: str, previous_results: dict) -> bool:
    """Run a single test against a single url."""
    test_parameters = TEST_PARAMETERS[test_suite]
    test_suite = AVAILABLE_TEST_SUITES[test_suite]
    try:
        with Timeout(settings.SCAN_SUITE_TIMEOUT_SECONDS):
            raw_data = test_suite.test_site(
                url, previous_results, **test_parameters)
            processed = test_suite.process_test_data(
                raw_data, previous_results, **test_parameters)
            return getfqdn(), test_suite.test_name, raw_data, processed
    except Exception as e:
        return ':'.join([getfqdn(), test_suite.test_name, traceback.format_exc()])


@shared_task(queue='master')
def handle_aborted_scans():
    """
    Set status of scans to error when they are running longer than configured
    timeout.
    """
    now = timezone.now()
    Scan.objects.filter(
        start__lt=now - settings.SCAN_TOTAL_TIMEOUT,
        end__isnull=True).delete()


def _parse_new_results(previous_results: List[Tuple[list, dict]]) -> tuple:
    """
    Parse previous results, split into raw data, results and errors and merge
    data from multiple test suites.
    """
    raw = []
    result = {}
    errors = []
    for e in previous_results:
        if isinstance(e, (list, tuple)):
            scan_host = e[0]
            test = e[1]
            if isinstance(e[2], dict):
                # add test specifier to each raw data element
                for identifier, raw_elem in e[2].items():
                    raw.append(dict(
                        identifier=identifier,
                        scan_host=scan_host,
                        test=test,
                        **raw_elem))
            if isinstance(e[3], dict):
                result.update(e[3])
        else:
            errors.append(e)
    return raw, result, errors

@shared_task(queue='master', time_limit=1500)
def schedule_pre_processing(obj_id = int):

    analyse = Analysis.objects.get(id=obj_id)
    analyse.start = timezone.now()
    analyse.save()

    scan_list = ScanList.objects.filter(id=121).prefetch_columns()
    if scan_list:
        sites = scan_list.first().sites.annotate_most_recent_scan_result().select_related('last_scan')
        analysis = []
        if sites:
            tasks = group(process_site.s(site.last_scan__result, site.id, analyse.id) for site in sites)
            tasks.apply_async()

        analyse.end = timezone.now()
        analyse.save()

@shared_task(queue='slave')
def process_site(site_pk: int, analyse_id: int):
    site = Site.objects.get(pk=site_pk)
    scan_result = ScanResult.objects.get(scan_id=site.last_scan_id)
    site_res = scan_result.result
    if site_res:
        analysis = site.analyse(site_res, DEFAULT_GROUP_ORDER)[1].items()
        if analysis:
            data = []
            site_data = {}
            site_data['url'] = site.url
            if 'a_locations' in site_res:
                site_data['country'] = site_res['a_locations'][0] if len(site_res['a_locations'] != 0) else None
            else:
                site_data['country'] = None
            if 'mx_locations' in site_res:
                site_data['mx_country'] = site_res['mx_locations'][0] if len(site_res['mx_locations'] != 0) else None
            else:
                site_data['mx_country'] = None
            for group, result in zip(RESULT_GROUPS.values(), analysis):
                for description, title, rating in result[1]:
                    site_data[title] = str(rating)
            data.append(site_data)
            AnalysisCategory.objects.create(
                analysis_id=analyse_id,
                result=data)
