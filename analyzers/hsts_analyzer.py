from models.hsts_result import HstsResult
from models.requirements import Requirements, RequirementsResult
from reports.constants import (HSTS_MAX_AGE_INVALID, HSTS_MISSING, NO_ISSUES,
                               REQ_TITLES)

# NOTE: This is slightly less than 365 days to be a little lenient
MINIMUM_AGE = 31500000


class HstsAnalyzer(object):
    def __init__(self, hsts_scan: HstsResult, requirements: Requirements):
        self.scan = hsts_scan
        self.reqs = requirements

    def _check_header_present(self) -> tuple[bool, list[str]]:
        passed = True
        proof = []

        if not self.scan.header:
            passed = False
            proof += ['We did not detect an HSTS header when scanning your app.']

        return passed, proof

    def _check_max_age(self) -> tuple[bool, list[str]]:
        passed = True
        proof = []

        if self.scan.max_age < MINIMUM_AGE:
            passed = False
            proof += [f"Your max-age directive was less than a year, detected: {self.scan.max_age} seconds"]

        return passed, proof

    def analyze(self) -> Requirements:
        header_passed, header_proof = self._check_header_present()
        max_age_passed, max_age_proof = self._check_max_age()

        hsts_passed = header_passed and max_age_passed
        hsts_proof = header_proof + max_age_proof

        req1_2 = RequirementsResult(
            passed=hsts_passed,
            description=[NO_ISSUES] if hsts_passed else [HSTS_MISSING] if not header_passed else [HSTS_MAX_AGE_INVALID],
            proof=hsts_proof,
            title=REQ_TITLES['1.2']
        )

        self.reqs.req1_2 = req1_2

        return self.reqs
