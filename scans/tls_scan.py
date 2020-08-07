import requests
import logging
import time
import json
from collections import defaultdict
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from models.tls_result import TlsResult, IpResult

BASE_API = 'https://api.ssllabs.com/api/v3'


class TlsScanError(Exception):
    def __init__(self, error_list):
        self.message = f"The TLS Scan API threw an error: {json.dumps(error_list, indent=3)}"


class TlsScan(object):
    def __init__(self, base_url):
        self.session = self._setup_session()
        self.base_url = base_url

    def _setup_session(self):
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 503, 529],
            method_whitelist=['GET']
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        return session

    def _call_api(self, path, params):
        url = f'{BASE_API}/{path}'

        res = self.session.get(url, params=params).json()
        if res.get('errors', None):
            raise TlsScanError(res['errors'])

        return res

    def _run_ssl_scan(self, ignore_cache=False):
        path = 'analyze'
        params = {
            'host': self.base_url,
            'all': 'done',
            'fromCache': 'on',
            'maxAge': '1'
        }

        if ignore_cache:
            params['startNew'] = 'on'
            del params['fromCache']
            del params['maxAge']
            # Initial request may start a new scan, all subsequent polling requests should omit it
            res = self._call_api(path, params)
            del params['startNew']
            logging.debug(f"Forcing scan of {self.base_url} - Waiting initial 1 minute for results.")
            time.sleep(60)

        # Poll the endpoint because that's what Qualys says to do
        while True:
            res = self._call_api(path, params)
            if res.get('status', None) == 'READY':
                break
            logging.debug(f"Scan for {self.base_url} is not ready. Waiting 10 more seconds.")
            time.sleep(10)

        return res

    def scan(self, ignore_cache=False):
        logging.info('Starting SSL/TLS Scan. Hang in there, this will take some time...')
        scan_data = self._run_ssl_scan(ignore_cache)
        res = TlsResult(
            ips_scanned=len(scan_data.get('endpoints', [])),
            protocols=[],
            hsts_present=True,
            trusted=True,
            scan_results={}
        )

        scan_res = defaultdict()
        scan_protos = set()

        for endpoint in scan_data.get('endpoints', []):
            if endpoint.get('statusMessage', None) == 'Ready':
                protocols = [
                    f"{x['name']} {x['version']}"
                    for x in endpoint['details']['protocols']
                ]
                scan_protos.update(protocols)
                hsts_present = endpoint['details']['hstsPolicy']['status'] == 'present'
                res.hsts_present = res.hsts_present and hsts_present
                res.trusted = res.trusted and endpoint['grade'] not in ['T', 'M']

                scan_res[endpoint['ipAddress']] = IpResult(
                    protocols=protocols,
                    hsts=endpoint['details']['hstsPolicy'],
                    cert_grade=endpoint['grade']
                )

        res.protocols = list(scan_protos)
        res.scan_results = scan_res

        logging.info(f"SSL/TLS scan complete, found and tested {len(scan_res)} IPs")

        return res
