import logging
import json
import reports.constants

from pathlib import Path
from typing import List
from models.requirements import Results
from models.vulnerability import AppFailureReport
from datetime import date


class FailureGenerator(object):
    def __init__(self, results: Results, out_dir: str, errors: List[str], descriptor_url: str, timeout: str):
        self.results = self._normalize_results(results)
        self.out_dir = out_dir
        self.errors = bool(errors)
        self.descriptor_url = descriptor_url
        self.timeout = timeout

    def _normalize_results(self, results: Results) -> Results:
        for req in results.requirements:
            results.requirements[req].title = reports.constants.REQ_TITLES[req]
        return results

    def _get_report_path(self, fname: str) -> str:
        return str(Path(self.out_dir + '/' + fname).resolve())

    def _create_json_report(self) -> AppFailureReport:
        app_failures_report = AppFailureReport(
            app_key=self.results.key,
            app_name=self.results.name,
            descriptor_url=self.descriptor_url,
            date=date.today()
        )
        return app_failures_report

    def _write_output(self, contents: str, json_name: str):
        with open(self._get_report_path(json_name), 'w') as file:
            file.write(contents)
        logging.info(f"Wrote report to: {self._get_report_path(json_name)}")

    def save_failures(self):
        json_report = self._create_json_report()

        timeout_fname = f"timeouts_{self.timeout}s"
        service_unavailable_fname = f"service_unavailable_{self.timeout}s"
        infinite_redirects_fname = f"infinite_redirects_{self.timeout}s"
        json_name = ""

        if "timeouts" in self.results.errors:
            Path(self.out_dir + '/' + timeout_fname).mkdir(exist_ok=True, parents=True)
            json_name = f"{timeout_fname}/{self.results.key}.json"
        if "service_unavailable" in self.results.errors:
            Path(self.out_dir + '/' + service_unavailable_fname).mkdir(exist_ok=True, parents=True)
            json_name = f"{service_unavailable_fname}/{self.results.key}.json"
        if "infinite_redirects" in self.results.errors:
            Path(self.out_dir + '/' + infinite_redirects_fname).mkdir(exist_ok=True, parents=True)
            json_name = f"{infinite_redirects_fname}/{self.results.key}.json"

        self._write_output(json.dumps(json_report.to_json()), json_name)
