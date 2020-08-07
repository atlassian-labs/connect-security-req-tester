import fire
import logging
import json
import validators
import sys
from scans.descriptor_scan import DescriptorScan
from scans.tls_scan import TlsScan
from reports.generator import ReportGenerator
from analyzers.tls_analyzer import TlsAnalyzer
from analyzers.descriptor_analyzer import DescriptorAnalyzer
from models.requirements import Results, Requirements


def main(descriptor_url, force_scan=False, debug=False, out_dir='out'):
    setup_logging(debug)
    validate_descriptor_url(descriptor_url)

    # Run all of the gather scans (TLS & Descriptor Scan)
    tls_scan = TlsScan(descriptor_url)
    descriptor_scan = DescriptorScan(descriptor_url)

    tls_res = tls_scan.scan(force_scan)
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

    logging.info('Finished analysis')

    # Generate a report based on the analyzed results against Security Requirements
    generator = ReportGenerator(results, out_dir)
    generator.save_report()


def validate_descriptor_url(descriptor_url):
    if not descriptor_url.endswith('.json'):
        logging.error(
            'Descriptor URL does not end with ".json", confirm the link to your Connect Descriptor.'
        )
        sys.exit(1)
    if not validators.url(descriptor_url):
        logging.error(
            'Descriptor URL appears invalid, confirm the link to your Connect Descriptor.'
        )
        sys.exit(1)


def setup_logging(debug):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO
    )


if __name__ == '__main__':
    fire.Fire(main)
