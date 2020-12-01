from typing import List, Tuple

from models.requirements import Requirements, RequirementsResult
from models.tls_result import TlsResult
from reports.constants import (CERT_NOT_VALID, HSTS_MISSING, NO_ISSUES,
                               REQ_TITLES, TLS_PROTOCOLS)

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
            proof += [f"Protocols Found: {self.scan.protocols}"]
            passed = False

        return passed, proof

    def _check_hsts(self) -> Tuple[bool, List[str]]:
        passed = self.scan.hsts_present
        proof: List[str] = []

        if not passed:
            proof += ['We did not detect an HSTS header when scanning your app.']

        return passed, proof

    def _check_cert_valid(self) -> Tuple[bool, List[str]]:
        passed = self.scan.trusted
        proof: List[str] = []

        if not passed:
            proof += ['Your app presented an HTTPS certificate that was not valid.']

        return passed, proof

    def _determine_description(self, passed, tls, hsts) -> List[str]:
        res: List[str] = []
        if passed:
            return [NO_ISSUES]
        if not tls:
            res.append(TLS_PROTOCOLS)
        if not hsts:
            res.append(HSTS_MISSING)

        return res

    def analyze(self) -> Requirements:
        tls_passed, tls_proof = self._check_tls_versions()
        hsts_passed, hsts_proof = self._check_hsts()
        passed = tls_passed and hsts_passed
        proof = tls_proof + hsts_proof

        req1 = RequirementsResult(
            passed=passed,
            description=self._determine_description(passed, tls_passed, hsts_passed),
            proof=proof,
            title=REQ_TITLES['1']
        )
        self.reqs.req1 = req1

        cert_passed, cert_proof = self._check_cert_valid()

        req3 = RequirementsResult(
            passed=cert_passed,
            description=[NO_ISSUES] if cert_passed else [CERT_NOT_VALID],
            proof=cert_proof,
            title=REQ_TITLES['3']
        )
        self.reqs.req3 = req3

        return self.reqs
