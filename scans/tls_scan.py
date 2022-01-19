import logging
from typing import List

import tldextract
from models.tls_result import TlsResult
from sslyze.scanner.models import ServerScanRequest, ServerScanResult, ServerScanStatusEnum
from sslyze.server_setting import ServerNetworkLocation
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scanner import Scanner
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.json.json_output import SslyzeOutputAsJson, ServerScanResultAsJson
from datetime import datetime


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
        self.request = self._resolve_dns(self.domain)

    def _get_domain_from_base(self, base_url: str) -> str:
        ext = tldextract.extract(base_url)

        # Convenient way to turn a URL into a domain via re-joining it after extracting it
        # https://github.com/john-kurkowski/tldextract#user-content-python-module--
        return '.'.join(part for part in ext if part)

    def _resolve_dns(self, host: str) -> List[ServerScanRequest]:
        try:
            scan_req = [
                ServerScanRequest(
                    server_location=ServerNetworkLocation(hostname=host),
                    scan_commands={
                        ScanCommand.CERTIFICATE_INFO,
                        *self.CIPHER_SUITES
                    }
                )
            ]
        except ServerHostnameCouldNotBeResolved:
            logging.error(f"SSL/TLS scan failed to resolve DNS for: {self.domain}")
            raise

        return scan_req

    def _run_scan(self, req: List[ServerScanRequest]) -> List[ServerScanResult]:
        scanner = Scanner()
        scanner.queue_scans(req)
        scanner_res = scanner.get_results()  # Unpack ReportGenerator

        # Return scan results for all scans that completed
        return [res for res in scanner_res if res.scan_status == ServerScanStatusEnum.COMPLETED]

    def _check_cert_valid(self, scan_res: List[ServerScanResult]) -> bool:
        for res in scan_res:
            cert_info = res.scan_result.certificate_info

            if cert_info.status == ServerScanStatusEnum.COMPLETED:
                for dep in cert_info.result.certificate_deployments:
                    if dep.verified_certificate_chain is None:
                        return False
                    if not dep.leaf_certificate_subject_matches_hostname:
                        return False
            else:
                # If the cert info scan failed, return false
                logging.error(f"SSL/TLS scan failed to retrieve HTTPS certificate information for: {self.domain}")
                raise

        return True

    def _get_supported_protocols(self, scan_res: List[ServerScanResult]) -> List[str]:
        protocols = set()
        for res in scan_res:
            # find accepted cipher suites
            for cipher in self.CIPHER_SUITES:
                try:
                    cipher_res = getattr(res.scan_result, cipher)
                    if cipher_res.status != ServerScanStatusEnum.COMPLETED:
                        raise
                    if cipher_res.result.accepted_cipher_suites:
                        protocols.add(cipher_res.result.tls_version_used.name)
                except Exception:
                    logging.error(f"SSL/TLS scan failed for {cipher} on {self.domain}")
                    raise

        return list(protocols)

    def scan(self) -> TlsResult:
        logging.info(f"Starting SSL/TLS Scan for {self.domain}...")
        scan_res = self._run_scan(self.request)

        if not scan_res:
            logging.error(f"SSL/TLS scan failed to complete for: {self.domain}")
            raise

        # Undocumented, but useful helper function to convert the sslyze output to JSON
        raw_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(result) for result in scan_res],
            date_scans_started=datetime.utcnow(),  # Required but not used
            date_scans_completed=datetime.utcnow()  # Required but not used
        ).json()

        tls_res = TlsResult(
            domain=self.domain,
            ips_scanned=len(scan_res),
            protocols=self._get_supported_protocols(scan_res),
            trusted=self._check_cert_valid(scan_res),
            scan_results=raw_output
        )

        logging.info('SSL/TLS Scan completed.')
        return tls_res
