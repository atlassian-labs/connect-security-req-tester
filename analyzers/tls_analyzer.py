import json

from models.requirements import RequirementsResult
from reports.constants import (CERT_NOT_VALID, HSTS_MISSING, NO_ISSUES,
                               TLS_PROTOCOLS)

PROTO_DENYLIST = ['TLS 1.0', 'TLS 1.1', 'SSL 3.0']


class TlsAnalyzer(object):
    def __init__(self, tls_scan, requirements):
        self.scan = tls_scan
        self.reqs = requirements
        self.proof = json.dumps(self.scan.to_json(), indent=3)

    def _check_tls_versions(self):
        passed = True
        proof = []
        for ip in self.scan.scan_results:
            bad_protos = any(item in self.scan.scan_results[ip]['protocols'] for item in PROTO_DENYLIST)
            if bad_protos:
                proof.append(f"{ip} - {self.scan.scan_results[ip]['protocols']}")
            passed = passed and not bad_protos

        return passed, proof

    def _check_hsts(self):
        passed = True
        proof = []
        for ip in self.scan.scan_results:
            if self.scan.scan_results[ip].hsts['status'] != 'present':
                passed = False
                proof.append(f"{ip} - {self.scan.scan_results[ip].hsts}")

        return passed, proof

    def _check_cert_valid(self):
        passed = True
        proof = []
        for ip in self.scan.scan_results:
            if self.scan.scan_results[ip].cert_grade in ['T', 'M']:
                passed = False
                proof.append(f"{ip} - Failing Grade of {self.scan.scan_results[ip].cert_grade}")

        return passed, proof

    def _determine_description(self, passed, tls, hsts):
        res = []
        if passed:
            return [NO_ISSUES]
        if not tls:
            res.append(TLS_PROTOCOLS)
        if not hsts:
            res.append(HSTS_MISSING)

        return res

    def analyze(self):
        tls_passed, tls_proof = self._check_tls_versions()
        hsts_passed, hsts_proof = self._check_hsts()
        passed = tls_passed and hsts_passed
        proof = tls_proof + hsts_proof

        req1 = RequirementsResult(
            passed=passed,
            description=self._determine_description(passed, tls_passed, hsts_passed),
            proof=proof
        )
        self.reqs.req1 = req1

        cert_passed, cert_proof = self._check_cert_valid()

        req3 = RequirementsResult(
            passed=cert_passed,
            description=[NO_ISSUES] if cert_passed else [CERT_NOT_VALID],
            proof=cert_proof
        )
        self.reqs.req3 = req3

        return self.reqs
