import json
import logging
import time
from collections import defaultdict
import random

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from models.tls_result import IpResult, TlsResult

BASE_API = 'https://api.ssllabs.com/api/v3'
POLL_TIME = 15
WAIT_TIME_PER_ENDPOINT = 60
# Changes the amount of time waiting before scan start
RANDOM_JITTER = 5


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
            status_forcelist=[403, 429, 500, 503, 529],
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
            'fromCache': 'off' if ignore_cache else 'on',
            'maxAge': '1',
            'startNew': 'on' if ignore_cache else 'off'
        }

        # Kick off a scan - Include some random jitter wait to ensure the Qualys API does not rate limit us
        time.sleep(random.randint(1, RANDOM_JITTER))
        res = self._call_api(path, params)
        del params['startNew']
        time.sleep(random.randint(RANDOM_JITTER, POLL_TIME))

        # Attempt to intelligently guess the length of the scan based on the number of IPs Qualys needs to scan
        # If we underguess, fall-back to a POLL_TIME many seconds poll
        long_initial_poll = True
        while (res.get('status', None)) not in ['READY', 'ERROR']:
            res = self._call_api(path, params)
            num_ips = len(res.get('endpoints', []))
            poll_amount = POLL_TIME if not long_initial_poll else num_ips * WAIT_TIME_PER_ENDPOINT

            if long_initial_poll:
                logging.info(f"Qualys found {num_ips} endpoint(s). Waiting {poll_amount} seconds for scan completion.")
                long_initial_poll = False
            else:
                logging.debug(f"Scan for {self.base_url} still not ready. Waiting {poll_amount} more seconds.")

            time.sleep(poll_amount)

        return res

    def scan(self, ignore_cache=False):
        logging.info(f"Starting SSL/TLS scan for: {self.base_url}. This may take some time, please be patient.")
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
