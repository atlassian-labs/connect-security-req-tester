import tldextract
from models.requirements import RequirementsResult
from reports.constants import BRANDING_ISSUE, NO_ISSUES, REQ_TITLES

PRODUCT_NAMES = [
    'atlassian', 'jira', 'confluence', 'jira service desk', 'bitbucket',
    'atlassian access', 'trello', 'statuspage', 'opsgenie', 'jira align'
]
APP_NAME_START_DENYLIST = PRODUCT_NAMES
APP_NAME_DENYLIST = ['premium']
# Creates a dynamic list containing all product names with spaces replaced with underscores and dashes
DOMAIN_DENYLIST = list(
    set([x.replace(' ', '-') for x in PRODUCT_NAMES] +
        [x.replace(' ', '_') for x in PRODUCT_NAMES]))


class BrandingAnalyzer(object):
    def __init__(self, links, name, requirements):
        self.links = links
        self.app_name = name
        self.reqs = requirements

    def _check_against_denylist(self, search, denylist):
        search = search.lower()
        for item in denylist:
            if item in search:
                return True

        return False

    def _check_starts_with_denylist(self, search, denylist):
        search = search.lower()
        for item in denylist:
            if search.startswith(item):
                return True

        return False

    def _check_links(self):
        passed = True
        proof = []
        for link in self.links:
            sub, domain, suffix = tldextract.extract(link)
            sub_test = self._check_against_denylist(sub, DOMAIN_DENYLIST)
            domain_test = self._check_against_denylist(domain, DOMAIN_DENYLIST)

            if sub_test or domain_test:
                proof.append(
                    f"{link} - Contains a denied word in the subdomain or primary domain"
                )
                passed = False

        return passed, proof

    def _check_app_name(self):
        passed = True
        proof = []
        starts_with = self._check_starts_with_denylist(
            self.app_name, APP_NAME_START_DENYLIST)
        contains = self._check_against_denylist(self.app_name,
                                                APP_NAME_DENYLIST)

        if starts_with or contains:
            proof.append(
                f"App Name ({self.app_name}) starts with or contains a denied word"
            )
            passed = False

        return passed, proof

    def analyze(self):
        domain_passed, domain_proof = self._check_links()
        name_passed, name_proof = self._check_app_name()

        branding_passed = domain_passed and name_passed
        branding_proof = domain_proof + name_proof

        req16 = RequirementsResult(
            passed=branding_passed,
            description=[NO_ISSUES] if branding_passed else [BRANDING_ISSUE],
            proof=branding_proof,
            title=REQ_TITLES['16']
        )
        self.reqs.req16 = req16

        return self.reqs
