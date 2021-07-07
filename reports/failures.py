import logging
from pathlib import Path
from typing import List
from models.requirements import Results

import reports.constants

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

    def save_failures(self):
        timeout_fname = f"timeouts_{self.timeout}s"
        service_unavailable_fname = f"service_unavailable_{self.timeout}s"
        infinite_redirects_fname = f"infinite_redirects_{self.timeout}s"
        fname = ""

        if "timeouts" in self.results.errors:
            Path(self.out_dir + '/' + timeout_fname).mkdir(exist_ok=True, parents=True)
            fname = f"{timeout_fname}/{self.results.key}.csv"
        if "service_unavailable" in self.results.errors:
            Path(self.out_dir + '/' + service_unavailable_fname).mkdir(exist_ok=True, parents=True)
            fname = f"{service_unavailable_fname}/{self.results.key}.csv"
        if "infinite_redirects" in self.results.errors:
            Path(self.out_dir + '/' + infinite_redirects_fname).mkdir(exist_ok=True, parents=True)
            fname = f"{infinite_redirects_fname}/{self.results.key}.csv"
        
        with open(self._get_report_path(fname), 'w') as file:
            file.write(self.descriptor_url)
            file.close()
        logging.info(f"Wrote failures to: {self._get_report_path(fname)}")
