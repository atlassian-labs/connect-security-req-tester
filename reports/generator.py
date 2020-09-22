import json
import logging
import re
from datetime import date, datetime
from pathlib import Path

import markdown2
from jinja2 import Template

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
    def __init__(self, results, out_dir):
        self.results = results
        self.out_dir = out_dir
        self.file_name = f"{results.key}-{date.today()}"

    def _jinja_render(self, template, **kwargs):
        logging.debug(f"Rendering {template} with {kwargs.keys()}")
        jinja_template = Template(open(template, 'r').read())
        return jinja_template.render(kwargs)

    def _get_report_path(self, fname):
        return str(Path(self.out_dir + '/' + fname).resolve())

    def _write_output(self, contents, fname):
        Path(self.out_dir).mkdir(exist_ok=True, parents=True)
        with open(self._get_report_path(fname), 'w') as file:
            file.write(contents)

    def save_report(self):
        markdown_report = self._jinja_render(
            template=MARKDOWN_TEMPLATE,
            today=datetime.now(),
            titles=reports.constants.REQ_TITLES,
            constants=reports.constants,
            results=self.results
        )
        markdown_to_html = markdown2.markdown(
            markdown_report,
            extras=['fenced-code-blocks', 'target-blank-links', 'link-patterns'],
            link_patterns=LINK_PATTERNS
        )
        final_report = self._jinja_render(
            template=HTML_TEMPLATE,
            report_body=markdown_to_html
        )

        html_name = f"{self.file_name}.html"
        json_name = f"{self.file_name}.json"

        self._write_output(final_report, html_name)
        self._write_output(json.dumps(self.results.to_json(), indent=3), json_name)

        logging.info(f"Wrote reports to:\n\t{self._get_report_path(html_name)}\n\t{self._get_report_path(json_name)}")
