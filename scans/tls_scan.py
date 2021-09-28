import json
import logging
from dataclasses import asdict
from typing import List, Optional

import tldextract
from models.tls_result import TlsResult
from sslyze import (JsonEncoder, ScanCommand, Scanner, ServerConnectivityInfo,
                    ServerConnectivityTester,
                    ServerNetworkLocationViaDirectConnection,
                    ServerScanRequest, ServerScanResult)
from sslyze.errors import ConnectionToServerFailed


class TlsScan(object):

    CIPHER_SUITES = {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES
    }

    def __init__(self, base_url: str):
        self.domain = self._get_domain_from_base(base_url)

    def _get_domain_from_base(self, base_url: str) -> str:
        ext = tldextract.extract(base_url)

        # Convenient way to turn a URL into a domain via re-joining it after extracting it
        # https://github.com/john-kurkowski/tldextract#user-content-python-module--
        return '.'.join(part for part in ext if part)

    def _check_connectivity(self) -> Optional[ServerConnectivityInfo]:
        location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(self.domain, 443)

        try:
            server_info = ServerConnectivityTester().perform(location)
        except ConnectionToServerFailed as e:
            logging.error(f"SSL/TLS Scan could not connect to: {self.domain}\n{e.error_message}")
            return None

        return server_info

    def _run_scan(self, server_info: ServerConnectivityInfo) -> List[ServerScanResult]:
        scanner = Scanner()
        scan_request = ServerScanRequest(
            server_info=server_info,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                *self.CIPHER_SUITES
            }
        )
        scanner.queue_scan(scan_request)
        res = scanner.get_results()
        # Unpack the generator that is returned as we need to navigate this
        # data structure multiple times
        list_res: List[ServerScanResult] = []
        for server_res in res:
            list_res.append(server_res)

        return list_res

    def _check_cert_valid(self, scan_res: List[ServerScanResult]) -> bool:
        for res in scan_res:
            cert_info = res.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
            for dep in cert_info.certificate_deployments:
                if not dep.leaf_certificate_subject_matches_hostname:
                    return False
                for validation in dep.path_validation_results:
                    if not validation.verified_certificate_chain:
                        return False

        return True

    def _get_supported_protocols(self, scan_res: List[ServerScanResult]) -> List[str]:
        protocols = set()
        for res in scan_res:

            # find accepted cipher suites
            for cipher in self.CIPHER_SUITES:
                try:
                    result = res.scan_commands_results[cipher]
                    if result.accepted_cipher_suites:
                        protocols.add(result.tls_version_used.name)
                except KeyError:
                    # there was an error trying to get that cipher suite or we did not send the corresponding command
                    # TODO log the scan command errors
                    pass

        return list(protocols)

    def scan(self) -> TlsResult:
        logging.info(f"Starting SSL/TLS Scan for {self.domain}...")
        server_info = self._check_connectivity()
        scan_res = self._run_scan(server_info)

        # Data shuffling to get this into a pretty state for reporting purposes
        raw_output = [json.loads(json.dumps(asdict(x), cls=JsonEncoder)) for x in scan_res]

        tls_res = TlsResult(
            domain=self.domain,
            ips_scanned=len(scan_res),
            protocols=self._get_supported_protocols(scan_res),
            trusted=self._check_cert_valid(scan_res),
            scan_results=raw_output
        )

        logging.info('SSL/TLS Scan completed.')
        return tls_res
