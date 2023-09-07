import re
from distutils import util
from typing import List, Tuple

from models.descriptor_result import DescriptorResult
from models.requirements import Requirements, RequirementsResult
from reports.constants import (MISSING_ATTRS_SESSION_COOKIE,
                               MISSING_AUTHN, MISSING_CACHE_HEADERS,
                               MISSING_REF_HEADERS, NO_ISSUES, NO_AUTH_PROOF, VALID_AUTH_PROOF, VALID_AUTHZ_PROOF, REQ_TITLES,
                               MISSING_SIGNED_INSTALL_AUTHN, MISSING_AUTHZ)

REQ_CACHE_HEADERS = ['no-cache', 'no-store']
REF_DENYLIST = ['no-referrer-when-downgrade', 'unsafe-url']
COOKIE_PARSE = r'(.*); Domain=(.*); Secure=(.*); HttpOnly=(.*)'


class DescriptorAnalyzer(object):
    def __init__(self, desc_scan: DescriptorResult, requirements: Requirements):
        self.scan = desc_scan
        self.reqs = requirements

    def _check_cache_headers(self) -> Tuple[bool, List[str]]:
        passed = True
        proof: List[str] = []
        scan_res = self.scan.scan_results
        for link in scan_res:
            cache_headers = scan_res[link].cache_header.split(',')
            cache_headers = [x.strip().lower() for x in cache_headers]
            directives = all(item in cache_headers for item in REQ_CACHE_HEADERS)
            if not directives:
                proof.append(f"{link} | Cache header: {scan_res[link].cache_header}")
            passed = passed and directives

        return passed, proof

    def _check_referrer_headers(self) -> Tuple[bool, List[str]]:
        passed = True
        proof: List[str] = []
        scan_res = self.scan.scan_results
        for link in scan_res:
            ref_headers = scan_res[link].referrer_header.split(',')
            ref_headers = [x.strip().lower() for x in ref_headers]
            policy = ref_headers[0] not in REF_DENYLIST if ref_headers[0] != 'header missing' else False
            if not policy:
                proof.append(f"{link} | Referrer header: {scan_res[link].referrer_header}")
            passed = passed and policy

        return passed, proof

    def _check_cookie_headers(self) -> Tuple[bool, List[str]]:
        passed = True
        proof: List[str] = []
        scan_res = self.scan.scan_results
        scan_res = self.scan.scan_results
        for link in scan_res:
            cookies = scan_res[link].session_cookies
            for cookie in cookies:
                # Parsing the cookie string became messy, so we use a regex to match and tear
                # the string apart into its relevant pieces
                parsed = re.match(COOKIE_PARSE, cookie)
                secure = bool(util.strtobool(parsed.group(3)))
                httponly = bool(util.strtobool(parsed.group(4)))

                if not secure or not httponly:
                    proof.append(f"{link} | Cookie: {cookie}")
                passed = passed and secure and httponly

        return passed, proof

    def _check_authn_authz(self) -> Tuple[bool, List[str], bool, List[str], bool, List[str]]:
        passed = True
        proof: List[str] = []
        signed_install_passed = True
        signed_install_proof: List[str] = []
        authz_passed = True
        authz_proof: List[str] = []
        scan_res = self.scan.scan_results

        # Don't check authentication if the app doesn't have an authentication method.
        # Default to no authentication check if no authentication field is provided
        authentication_method = self.scan.app_descriptor.get('authentication')
        use_authentication = (False if authentication_method is None else authentication_method.get("type") == "jwt")
        if not use_authentication:
            proof.append(NO_AUTH_PROOF)
            return passed, proof, signed_install_passed, signed_install_proof, authz_passed, authz_proof

        for link in scan_res:
            res_code = int(scan_res[link].res_code) if scan_res[link].res_code else 0
            auth_header = scan_res[link].auth_header
            req_method = scan_res[link].req_method
            response = scan_res[link].response
            authz_req_method = scan_res[link].authz_req_method
            authz_code = int(scan_res[link].authz_code) if scan_res[link].authz_code else 0
            authz_header = scan_res[link].authz_header

            # Check for invalid responses in the body before failing the authn check
            invalid_responses = ['Invalid JWT', 'unauthorized', 'forbidden', 'error', 'unlicensed', 'not licensed',
                                 'no license', 'invalid', '401', '403', '404', '500']
            invalid_response = False
            if any(str(x).lower() in str(response).lower() for x in invalid_responses):
                invalid_response = True

            # We shouldn't be able to visit this link if the app uses authentication.
            if res_code >= 200 and res_code < 400 and not invalid_response:
                if any(x in link for x in ('installed', 'install', 'uninstalled', 'uninstall')):
                    signed_install_passed = False
                    signed_install_proof_text = f"Lifecycle endpoint: {link} | Res Code: {res_code}" \
                                                f" Auth Header: {auth_header}"
                    signed_install_proof.append(signed_install_proof_text)

                else:
                    passed = False
                    proof_text = f"{link} | Res Code: {res_code} Req Method: {req_method} Auth Header: {auth_header}"
                    proof.append(proof_text)

            # similarly check for authorization status codes for authorization bypass
            if authz_code >= 200 and authz_code < 400:
                authz_passed = False
                authz_proof_text = (f"{link} | Authz Res Code: {authz_code} Req Method: {authz_req_method}"
                                    f" Authz Header: {authz_header}")
                authz_proof.append(authz_proof_text)

        if passed:
            proof.append(VALID_AUTH_PROOF)
        if authz_passed:
            authz_proof.append(VALID_AUTHZ_PROOF)

        return passed, proof, signed_install_passed, signed_install_proof, authz_passed, authz_proof

    def analyze(self, authz_only=False) -> Requirements:
        cache_passed, cache_proof = self._check_cache_headers()
        ref_passed, ref_proof = self._check_referrer_headers()
        cookies_passed, cookies_proof = self._check_cookie_headers()
        (auth_passed, auth_proof, signed_install_passed, signed_install_proof,
         authz_passed, authz_proof) = self._check_authn_authz()

        req1_1 = RequirementsResult(
            passed=auth_passed,
            description=[NO_ISSUES] if auth_passed else [MISSING_AUTHN],
            proof=auth_proof,
            title=REQ_TITLES['1.1']
        )

        req1_2 = RequirementsResult(
            passed=authz_passed,
            description=[NO_ISSUES] if authz_passed else [MISSING_AUTHZ],
            proof=authz_proof,
            title=REQ_TITLES['1.2']
        )

        req1_4 = RequirementsResult(
            passed=signed_install_passed,
            description=[NO_ISSUES] if signed_install_passed else [MISSING_SIGNED_INSTALL_AUTHN],
            proof=signed_install_proof,
            title=REQ_TITLES['1.4']
        )

        req7_2 = RequirementsResult(
            passed=ref_passed,
            description=[NO_ISSUES] if ref_passed else [MISSING_REF_HEADERS],
            proof=ref_proof,
            title=REQ_TITLES['7.2']
        )

        req7_3 = RequirementsResult(
            passed=cache_passed,
            description=[NO_ISSUES] if cache_passed else [MISSING_CACHE_HEADERS],
            proof=cache_proof,
            title=REQ_TITLES['7.3']
        )

        req7_4 = RequirementsResult(
            passed=cookies_passed,
            description=[NO_ISSUES] if cookies_passed else [MISSING_ATTRS_SESSION_COOKIE],
            proof=cookies_proof,
            title=REQ_TITLES['7.4']
        )

        # Skip reporting other checks if we only run authz check
        if not authz_only:
            self.reqs.req1_1 = req1_1
            self.reqs.req1_4 = req1_4
            self.reqs.req7_2 = req7_2
            self.reqs.req7_3 = req7_3
            self.reqs.req7_4 = req7_4
        self.reqs.req1_2 = req1_2

        return self.reqs
