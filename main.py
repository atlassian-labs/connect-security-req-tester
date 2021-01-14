import json
import logging
import sys

import fire

from analyzers.branding_analyzer import BrandingAnalyzer
from analyzers.descriptor_analyzer import DescriptorAnalyzer
from analyzers.tls_analyzer import TlsAnalyzer
from models.requirements import Requirements, Results
from reports.generator import ReportGenerator
from scans.descriptor_scan import DescriptorScan
from scans.tls_scan import TlsScan
from utils.app_validator import AppValidator


def main(descriptor_url, skip_branding=False, debug=False, out_dir='out'):
    # Setup our logging
    setup_logging(debug)
    # Validate that the descriptor URL points to a seemingly valid connect app descriptor
    validator = AppValidator(descriptor_url)
    validator.validate()
    descriptor = validator.get_descriptor()

    # Run our scans -- SSL/TLS and Descriptor Checks
    tls_scan = TlsScan(descriptor['baseUrl'])
    descriptor_scan = DescriptorScan(descriptor_url, descriptor)

    tls_res = tls_scan.scan()
    descriptor_res = descriptor_scan.scan()

    # Analyze the results from the scans
    results = Results(
        name=descriptor_res.name,
        key=descriptor_res.key,
        base_url=descriptor_res.base_url,
        app_descriptor_url=descriptor_res.app_descriptor_url,
        requirements=Requirements(),
        tls_scan_raw=json.dumps(tls_res.to_json(), indent=3),
        descriptor_scan_raw=json.dumps(descriptor_res.to_json(), indent=3),
        errors=descriptor_res.link_errors
    )

    logging.info('Starting analysis of results...')

    tls_analyzer = TlsAnalyzer(tls_res, results.requirements)
    results.requirements = tls_analyzer.analyze()

    descriptor_analyzer = DescriptorAnalyzer(descriptor_res, results.requirements)
    results.requirements = descriptor_analyzer.analyze()

    if not skip_branding:
        branding_analyzer = BrandingAnalyzer(descriptor_res.links, descriptor_res.name, results.requirements)
        results.requirements = branding_analyzer.analyze()

    logging.info('Finished analysis')

    # Generate a report based on the analyzed results against Security Requirements
    generator = ReportGenerator(results, out_dir)
    generator.save_report()

    if results.errors:
        errors: str = '\n'.join(descriptor_res.link_errors)
        logging.error(f"The following links caused errors:\n{errors}")
        sys.exit(1)


def setup_logging(debug):
    logging_format = '%(asctime)s %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    logging.basicConfig(
        format=logging_format,
        level=logging.DEBUG if debug else logging.INFO
    )
    # Turn off extra logging from filelock and HTTPS warnings when not in debug mode
    logging.captureWarnings(True)
    logging.getLogger('filelock').propagate = True if debug else False
    logging.getLogger('py.warnings').propagate = True if debug else False


if __name__ == '__main__':
    fire.Fire(main)
