import importlib
import os
import signal
import traceback
from multiprocessing import Process
from typing import Iterable, List, Tuple, Union

from celery import chord, shared_task
from django.conf import settings
from django.utils import timezone

from privacyscore.backend.models import RawScanResult, Scan, ScanResult, ScanGroup, Site


class Timeout:
    def __init__(self, seconds=1):
        self.seconds = seconds

    def __enter__(self):
        def handle_timeout(self, signum, frame):
            raise TimeoutError

        signal.signal(signal.SIGALRM, handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


@shared_task(queue='master')
def schedule_scan(scan_group_pk: int):
    """Prepare and schedule all scans of a scan group."""
    # Schedule next stage
    scan_group = ScanGroup.objects.get(pk=scan_group_pk)
    sites = Site.objects.filter(list_id=scan_group.list_id)
    for site in sites:
        # create Scan object
        scan = Scan.objects.create(
            site=site,
            group=scan_group,
            success=False)
        schedule_scan_stage(([], {}), scan.pk)

    scan_group.status = ScanGroup.SCANNING
    scan_group.save()


@shared_task(queue='master')
def schedule_scan_stage(previous_results: Tuple[list, dict], scan_pk: int,
                        stage: int = 0, previous_task_count: int = 0):
    """Schedule the next stage for a scan."""
    scan = Scan.objects.get(pk=scan_pk)

    if previous_task_count <= 1:
        previous_results = [previous_results]
    raw_data, previous_results = _parse_previous_results(previous_results)
    for params, data in raw_data:
        RawScanResult.store_raw_data(data, **params)

    if stage >= len(settings.SCAN_TEST_SUITES):
        # all stages finished.
        handle_finished_scan(scan)

        # store final results
        ScanResult.objects.create(
            scan=scan, result=previous_results)

        return True

    tasks = []
    for test_suite, test_parameters in settings.SCAN_TEST_SUITES[stage]:
        tasks.append(run_test.s(test_suite, test_parameters, scan_pk, scan.site.url, previous_results))
    chord(tasks, schedule_scan_stage.s(scan_pk, stage + 1, len(tasks))).apply_async()


def handle_finished_scan(scan: Scan):
    """
    Callback when all stages of tasks for a scan group are completed.

    Mark single scan as finished and determine whether complete group is finished.
    """
    scan.success = True
    scan.save()

    # TODO: concurrency? What happens when two last tests finish at the same time?
    if scan.group.scans.filter(success=False).count() == 0:
        # was last scan to succeed.
        scan.group.status = ScanGroup.FINISH
        scan.group.save()


@shared_task(queue='slave')
def run_test(test_suite: str, test_parameters: dict, scan_pk: int, url: str, previous_results: dict) -> bool:
    """Run a single test against a single url."""
    test_suite = importlib.import_module(test_suite)
    try:
        with Timeout(settings.SCAN_SUITE_TIMEOUT_SECONDS):
            return test_suite.test(
                scan_pk, url, previous_results, **test_parameters)
    except:
        # TODO: Use chord error handling and do not catch here

        # TODO: some kind of logging (other than stdout)?
        print(traceback.format_exc())
        return [], {}


# TODO: configure beat or similar to run this task frequently.
@shared_task(queue='master')
def handle_aborted_scans():
    """
    Set status of scans to error when they are running longer than configured
    timeout.
    """
    now = timezone.now()
    ScanGroup.objects.filter(
        start__lt=now - settings.SCAN_TOTAL_TIMEOUT,
        end__isnull=True).update(end=now, status=ScanGroup.ERROR)


def _parse_previous_results(previous_results: List[Tuple[list, dict]]) -> tuple:
    """Parse previous results and split into raw data and results."""
    if isinstance(previous_results, list):
        # Multiple results.
        raw = []
        result = {}
        if isinstance(previous_results[0], Iterable):
            raw = previous_results[0][0]
            result = previous_results[0][1].copy()
        for r, d in (e for e in previous_results[1:] if isinstance(e, Iterable)):
            if isinstance(r, Iterable):
                raw.extend(r)
            if isinstance(d, dict):
                result.update(d)
        return raw, result

    # Only a single result which already has the desired format.
    return previous_results