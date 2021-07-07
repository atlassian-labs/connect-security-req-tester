import json
import logging
import sys
from datetime import datetime

import fire
from pythonjsonlogger import jsonlogger

from analyzers.branding_analyzer import BrandingAnalyzer
from analyzers.descriptor_analyzer import DescriptorAnalyzer
from analyzers.tls_analyzer import TlsAnalyzer
from analyzers.hsts_analyzer import HstsAnalyzer
from models.requirements import Requirements, Results
from reports.generator import ReportGenerator
from reports.failures import FailureGenerator
from scans.descriptor_scan import DescriptorScan
from scans.tls_scan import TlsScan
from scans.hsts_scan import HstsScan
from utils.app_validator import AppValidator


def main(descriptor_url, skip_branding=False, debug=False, timeout=30, out_dir='out', json_logging=False):
    # Setup our logging
    setup_logging('connect-security-requirements-tester', debug, json_logging)
    logging.info(f"CSRT Scan started at: {(start := datetime.utcnow())}")
    # Validate that the descriptor URL points to a seemingly valid connect app descriptor
    validator = AppValidator(descriptor_url, timeout)
    validator.validate()
    descriptor = validator.get_descriptor()

    # Run our scans -- TLS/HSTS/Descriptor
    tls_scan = TlsScan(descriptor['baseUrl'])
    hsts_scan = HstsScan(descriptor['baseUrl'], timeout)
    descriptor_scan = DescriptorScan(descriptor_url, descriptor, timeout)

    tls_res = tls_scan.scan()
    hsts_res = hsts_scan.scan()
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

    hsts_analyzer = HstsAnalyzer(hsts_res, results.requirements)
    results.requirements = hsts_analyzer.analyze()

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
        # We would want to track apps/links that fail with a timeout of 30 seconds (so that we can retry only these later)
        # and have failed either due to a timeout or 503 service unavailable or infinite redirects
        # For 503 or timeout failures or infinite redirects (on timeout>30s), we can't do much about it except track them

        if ("timeouts" or "service_unavailable" or "infinite_redirects") in results.errors:
            failures = FailureGenerator(results, out_dir, results.errors, descriptor_url, timeout)
            failures.save_failures()
            logging.warning(f"The following links didn't scan successfully:\n{json.dumps(results.errors, indent=2)}")
            sys.exit(0)  # For both the above cases, we don't want to fail the scan as such so need to exit graciously
        else:  # For every other failures, we would want to fail the scan and alert in Slack
            logging.error(f"The following links caused errors:\n{json.dumps(results.errors, indent=2)}")
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
