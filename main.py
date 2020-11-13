import json
import logging

import fire

import utils
from analyzers.branding_analyzer import BrandingAnalyzer
from analyzers.descriptor_analyzer import DescriptorAnalyzer
from analyzers.tls_analyzer import TlsAnalyzer
from models.requirements import Requirements, Results
from reports.constants import NO_SCAN_INFO
from reports.generator import ReportGenerator
from scans.descriptor_scan import DescriptorScan
from scans.tls_scan import TlsScan


def main(descriptor_url, skip_branding=False, debug=False, out_dir='out'):
    # Setup our logging
    setup_logging(debug)
    # Validate and fetch the provided connect descriptor to confirm it works
    base_url, descriptor = utils.validate_and_resolve_descriptor(descriptor_url)

    # Run all of the gather scans (TLS & Descriptor Scan)
    tls_scan = TlsScan(base_url)
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
        descriptor_scan_raw=json.dumps(descriptor_res.to_json(), indent=3)
    )

    logging.info('Starting analysis of results...')

    tls_analyzer = TlsAnalyzer(tls_res, results.requirements)
    results.requirements = tls_analyzer.analyze()

    descriptor_analyzer = DescriptorAnalyzer(descriptor_res, results.requirements)
    results.requirements = descriptor_analyzer.analyze()

    if not skip_branding:
        branding_analyzer = BrandingAnalyzer(descriptor_res.links, descriptor_res.name, results.requirements)
        results.requirements = branding_analyzer.analyze()
        # Slightly gross hack that tells the tool we are actually running branding scans
        del NO_SCAN_INFO['16']

    logging.info('Finished analysis')

    # Generate a report based on the analyzed results against Security Requirements
    generator = ReportGenerator(results, out_dir)
    generator.save_report()


def setup_logging(debug):
    logging_format = '%(asctime)s %(levelname)s - %(filename)s:%(funcName)s - %(message)s'
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
