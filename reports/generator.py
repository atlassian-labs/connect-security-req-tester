from datetime import datetime
from jinja2 import Template
from pathlib import Path
from datetime import date
import reports.constants
import markdown2
import re
import logging

TEMPLATE_FILE = 'reports/standard_report.md'
pattern = (
    r'((([A-Za-z]{3,9}:(?:\/\/)?)'  # scheme
    r'(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+(:\[0-9]+)?'  # user@hostname:port
    r'|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)'  # www.|user@hostname
    r'((?:\/[\+~%\/\.\w\-_]*)?'  # path
    r'\??(?:[\-\+=&;%@\.\w_]*)'  # query parameters
    r'#?(?:[\.\!\/\\\w\-]*))?)'  # fragment
    r'(?![^<]*?(?:<\/\w+>|\/?>))'  # ignore anchor HTML tags
    r'(?![^\(]*?\))'  # ignore links in brackets (Markdown links and images)
)
link_patterns = [(re.compile(pattern), r'\1')]


class ReportGenerator(object):
    def __init__(self, results, out_dir):
        self.template = Template(open(TEMPLATE_FILE, 'r').read())
        self.results = results
        self.out_dir = out_dir

    def generate(self):
        logging.info('Generating markdown results from template...')
        return self.template.render(
            today=datetime.now(),
            titles=reports.constants.REQ_TITLES,
            constants=reports.constants,
            results=self.results
        )

    def save_report(self):
        report = self.generate()

        Path(self.out_dir).mkdir(exist_ok=True, parents=True)
        fname = f"{self.results.key}-{date.today()}.html"

        logging.info(f"Writing HTML Report to: {Path('./' + self.out_dir + '/' + fname).resolve()}")

        with open(f"{self.out_dir}/{fname}", 'w') as file:
            base = '''
                <html>
                <head>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/4.0.0/github-markdown.min.css" integrity="sha512-Oy18vBnbSJkXTndr2n6lDMO5NN31UljR8e/ICzVPrGpSud4Gkckb8yUpqhKuUNoE+o9gAb4O/rAxxw1ojyUVzg==" crossorigin="anonymous" />
                    <style>
                        .markdown-body {{
                            box-sizing: border-box;
                            min-width: 200px;
                            max-width: 980px;
                            margin: 0 auto;
                            padding: 45px;
                        }}

                        @media (max-width: 767px) {{
                            .markdown-body {{
                                padding: 15px;
                            }}
                        }}
                    </style>
                </head>
                <body class="markdown-body">
                {}
                </body>
                </html>
            '''
            base = base.format(markdown2.markdown(report, extras=['fenced-code-blocks', 'target-blank-links', 'link-patterns'], link_patterns=link_patterns))
            file.write(base)
