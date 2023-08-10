from models.hsts_result import HstsResult
from models.requirements import Requirements, RequirementsResult
from reports.constants import HSTS_MISSING, NO_ISSUES, REQ_TITLES


class HstsAnalyzer(object):
    def __init__(self, hsts_scan: HstsResult, requirements: Requirements):
        self.scan = hsts_scan
        self.reqs = requirements

    def _check_header_present(self) -> tuple[bool, list[str]]:
        passed = True
        proof = []

        if not self.scan.header:
            passed = False
            proof += [f"We did not detect a Strict-Transport-Security (HSTS) header when scanning: {self.scan.scanned}"]

        return passed, proof

    def analyze(self) -> Requirements:
        header_passed, header_proof = self._check_header_present()

        req3_0 = RequirementsResult(
            passed=header_passed,
            description=[NO_ISSUES] if header_passed else [HSTS_MISSING],
            proof=header_proof,
            title=REQ_TITLES['3.0']
        )

        self.reqs.req3_0 = req3_0

        return self.reqs
