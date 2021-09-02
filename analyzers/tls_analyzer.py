from typing import List, Tuple

from models.requirements import Requirements, RequirementsResult
from models.tls_result import TlsResult
from reports.constants import (CERT_NOT_VALID, NO_ISSUES, REQ_TITLES,
                               TLS_PROTOCOLS)

PROTO_DENYLIST = ['TLS_1_0', 'TLS_1_1', 'SSL_3_0', 'SSL_2_0']


class TlsAnalyzer(object):
    def __init__(self, tls_scan: TlsResult, requirements: Requirements):
        self.scan: TlsResult = tls_scan
        self.reqs: Requirements = requirements

    def _check_tls_versions(self) -> Tuple[bool, List[str]]:
        passed = True
        proof: List[str] = []

        uses_bad_protos = any(item in self.scan.protocols for item in PROTO_DENYLIST)
        if uses_bad_protos:
            proof += [f"Your domain: {self.scan.domain} - presented the following protocols: {self.scan.protocols}"]
            passed = False

        return passed, proof

    def _check_cert_valid(self) -> Tuple[bool, List[str]]:
        passed = self.scan.trusted
        proof: List[str] = []

        if not passed:
            proof += [f"Your domain: {self.scan.domain} - presented an HTTPS certificate that was not valid."]

        return passed, proof

    def analyze(self) -> Requirements:
        tls_passed, tls_proof = self._check_tls_versions()
        cert_passed, cert_proof = self._check_cert_valid()

        req1_1 = RequirementsResult(
            passed=tls_passed,
            description=[NO_ISSUES] if tls_passed else [TLS_PROTOCOLS],
            proof=tls_proof,
            title=REQ_TITLES['1.1']
        )
        req3 = RequirementsResult(
            passed=cert_passed,
            description=[NO_ISSUES] if cert_passed else [CERT_NOT_VALID],
            proof=cert_proof,
            title=REQ_TITLES['3']
        )

        self.reqs.req1_1 = req1_1
        self.reqs.req3 = req3

        return self.reqs
