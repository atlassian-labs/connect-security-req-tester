import json
import logging
import sys
from datetime import datetime

import fire
from pythonjsonlogger import jsonlogger

from analyzers.branding_analyzer import BrandingAnalyzer
from analyzers.descriptor_analyzer import DescriptorAnalyzer
from analyzers.tls_analyzer import TlsAnalyzer
from models.requirements import Requirements, Results
from reports.generator import ReportGenerator
from scans.descriptor_scan import DescriptorScan
from scans.tls_scan import TlsScan
from utils.app_validator import AppValidator


def main(descriptor_url, skip_branding=False, debug=False, timeout=30, out_dir='out', json_logging=False):
    # Setup our logging
    setup_logging('connect-security-requirements-tester', debug, json_logging)
    logging.info(f"CSRT Scan started at: {(start := datetime.utcnow())}")
    # Validate that the descriptor URL points to a seemingly valid connect app descriptor
    validator = AppValidator(descriptor_url, timeout)
    validator.validate()
    descriptor = validator.get_descriptor()

    # Run our scans -- SSL/TLS and Descriptor Checks
    tls_scan = TlsScan(descriptor['baseUrl'])
    descriptor_scan = DescriptorScan(descriptor_url, descriptor, timeout)

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
    generator = ReportGenerator(results, out_dir, skip_branding, start, results.errors)
    generator.save_report()

    logging.info(f"CSRT Scan completed in: {datetime.utcnow() - start}")

    if results.errors:
        errors: str = '\n'.join(descriptor_res.link_errors)
        logging.error(f"The following links caused errors:\n{errors}")
        sys.exit(1)


def setup_logging(scanner_name, debug, json_logging):
    if json_logging:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter("%(tool)s %(asctime)s %(levelname)s %(filename)s %(lineno)d %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        orig_factory = logging.getLogRecordFactory()

        def scanner_inline(*args, **kwargs):
            record = orig_factory(*args, **kwargs)
            record.tool = scanner_name
            return record

        logging.setLogRecordFactory(scanner_inline)
    else:
        logging_format = '%(asctime)s %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        logging.basicConfig(
            format=logging_format,
            level=logging.DEBUG if debug else logging.INFO
        )

    # Turn off extra logging from other packages that end up getting merged into the root logger unless in Debug
    logging.captureWarnings(True)
    logging.getLogger('sslyze').propagate = True if debug else False
    logging.getLogger('filelock').propagate = True if debug else False
    logging.getLogger('py.warnings').propagate = True if debug else False


if __name__ == '__main__':
    fire.Fire(main)
