import csv
import io
import json
import logging
import re
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional

import markdown2
from jinja2 import Template
from models.requirements import Results
from models.vulnerability import Vulnerability

import reports.constants

MARKDOWN_TEMPLATE = 'reports/standard_report.md'
HTML_TEMPLATE = 'reports/report_template.html'
LINK_REGEX = (
    r'((([A-Za-z]{3,9}:(?:\/\/)?)'  # scheme
    r'(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+(:\[0-9]+)?'  # user@hostname:port
    r'|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)'  # www.|user@hostname
    r'((?:\/[\+~%\/\.\w\-_]*)?'  # path
    r'\??(?:[\-\+=&;%@\.\w_]*)'  # query parameters
    r'#?(?:[\.\!\/\\\w\-]*))?)'  # fragment
    r'(?![^<]*?(?:<\/\w+>|\/?>))'  # ignore anchor HTML tags
    r'(?![^\(]*?\))'  # ignore links in brackets (Markdown links and images)
)
LINK_PATTERNS = [(re.compile(LINK_REGEX), r'\1')]


class ReportGenerator(object):
    def __init__(self, results: Results, out_dir: str, skip_branding: bool):
        self.results = self._normalize_results(results)
        self.skip_branding = skip_branding
        self.out_dir = out_dir
        self.file_name = f"{results.key}-{date.today()}"

    def _normalize_results(self, results: Results) -> Results:
        for req in results.requirements:
            results.requirements[req].title = reports.constants.REQ_TITLES[req]

        return results

    def _jinja_render(self, template: str, **kwargs) -> str:
        logging.debug(f"Rendering {template} with {kwargs.keys()}")
        jinja_template = Template(open(template, 'r').read())
        return jinja_template.render(kwargs)

    def _get_report_path(self, fname: str) -> str:
        return str(Path(self.out_dir + '/' + fname).resolve())

    def _write_output(self, contents: str, fname: str):
        Path(self.out_dir).mkdir(exist_ok=True, parents=True)
        with open(self._get_report_path(fname), 'w') as file:
            file.write(contents)

        logging.info(f"Wrote report to: {self._get_report_path(fname)}")

    def _create_json_report(self) -> List[dict]:
        vuln_report: List[dict] = []

        for req in self.results.requirements:
            req_res = self.results.requirements[req]
            if req_res.was_scanned() and not req_res.passed:
                vuln = Vulnerability(
                    vuln_id=f"{self.results.key}-requirement{req}",
                    title=reports.constants.REQ_TITLES[req],
                    description=','.join(req_res.description),
                    proof=','.join(req_res.proof),
                    recommendation=reports.constants.REQ_RECOMMENDATION[req],
                    severity='Medium',
                    app_key=self.results.key,
                    app_name=self.results.name,
                    date=date.today()
                )
                vuln_report.append(vuln.to_json())

        return vuln_report

    def _create_csv_report(self, vuln_report: List[dict]) -> Optional[str]:
        # Don't try to create a CSV for no vulns
        if not vuln_report:
            return ''

        # Create a fake IO stream to write the CSV content to, then return this
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=list(vuln_report[0]))
        writer.writeheader()
        writer.writerows(vuln_report)

        return out.getvalue()

    def _create_html_report(self) -> str:
        markdown_report = self._jinja_render(
            template=MARKDOWN_TEMPLATE,
            today=datetime.now(),
            constants=reports.constants,
            results=self.results,
            skip_branding=self.skip_branding
        )
        markdown_to_html = markdown2.markdown(
            markdown_report,
            extras=['fenced-code-blocks', 'target-blank-links', 'link-patterns', 'code-friendly'],
            link_patterns=LINK_PATTERNS
        )
        final_report = self._jinja_render(
            template=HTML_TEMPLATE,
            report_body=markdown_to_html
        )
        return final_report

    def save_report(self):
        json_report = self._create_json_report()
        csv_report = self._create_csv_report(json_report)
        html_report = self._create_html_report()

        html_name = f"{self.file_name}.html"
        json_name = f"{self.file_name}.json"
        csv_name = f"{self.file_name}.csv"

        self._write_output(html_report, html_name)
        self._write_output(json.dumps(json_report, indent=3), json_name)
        self._write_output(csv_report, csv_name)
