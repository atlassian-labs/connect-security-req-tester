import hashlib
import itertools
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse

import jwt
import requests
from models.descriptor_result import DescriptorLink, DescriptorResult
from utils.csrt_session import create_csrt_session

COMMON_SESSION_COOKIES = ['PHPSESSID', 'JSESSIONID', 'CFID', 'CFTOKEN', 'ASP.NET_SESSIONID']
KEY_IGNORELIST = ['icon', 'icons', 'documentation', 'imagePlaceholder', 'template', 'post-install-page']
MODULE_IGNORELIST = ['jiraBackgroundScripts', 'postInstallPage']
ADMIN_MODULES = ['configurePage', 'adminPages', 'jiraProjectAdminTabPanels', 'jiraProjectPermissions']
CONDITION_MATCHER = r'{condition\..*}'
BRACES_MATCHER = r'\$?{.*}'


class DescriptorScan(object):
    def __init__(self, descriptor_url: str, descriptor: dict, timeout: int):
        self.descriptor_url: str = descriptor_url
        self.descriptor: dict = descriptor
        self.base_url: str = descriptor['baseUrl'] if not descriptor['baseUrl'].endswith('/') else descriptor['baseUrl'][:-1]
        self.lifecycle_events = self._get_lifecycle_events()
        self.links = self._get_module_links() + self.lifecycle_events
        self.admin_links = self._get_admin_module_links()
        self.session = create_csrt_session(timeout)
        self.link_errors = defaultdict(list)

    def _get_lifecycle_events(self) -> List[str]:
        events = self.descriptor.get('lifecycle', [])
        # Pull all lifecycle events from the descriptor
        links = [self._convert_to_full_link(event) for event in [events[event] for event in events]]
        # Deduplicate life cycle events
        res = list(set(links))

        return res

    def _get_module_links(self) -> List[str]:
        res: List[str] = []
        modules = self.descriptor.get('modules', [])
        # Acquire all URLs from a descriptor ignoring modules in MODULE_IGNORELIST or keys in KEY_IGNORELIST
        # Calling itertools here to flatten a list of lists
        # TODO: Ensure we mark items in the MODULE_IGNORELIST to just ignore Requirement 5, scan for all other issues
        urls = list(itertools.chain.from_iterable(
            [self._find_urls_in_module(modules[x]) for x in modules if x not in MODULE_IGNORELIST]
        ))

        # Remove duplicates
        urls = list(set(urls))

        for url in urls:
            # Replace context vars eg. {project.issue} and {condition.is_admin}
            url = self._fill_context_vars(url)
            # Build each module url to be a full link eg. https://example.com/test
            res.append(self._convert_to_full_link(url))

        return res

    def _convert_to_full_link(self, link: str) -> str:
        if not link.startswith('http://') and not link.startswith('https://'):
            link = link if not link.startswith('/') else link[1:]
            link = f"{self.base_url}/{link}"

        return link

    def _fill_context_vars(self, url: str) -> str:
        url = re.sub(CONDITION_MATCHER, 'true', url, flags=re.IGNORECASE)
        url = re.sub(BRACES_MATCHER, 'test', url)

        return url

    def _find_urls_in_module(self, module: Union[dict, list]) -> List[str]:
        # Takes a connect module and traverses the JSON to find URLs - Handles both lists and dicts
        # Returns a list of lists
        urls: List[str] = []
        if type(module) is list:
            for item in module:
                urls.extend(self._find_urls_in_module(item))
        elif type(module) is dict:
            # Connect modules can be marked as "cacheable" meaning authN/authZ checks happen within the JS context.
            # We will ignore modules that are marked as cacheable for now
            # Ref: https://developer.atlassian.com/cloud/confluence/cacheable-app-iframes-for-connect-apps/
            # TODO: Mark these endpoints as not subjected to Requirement 5 checks, but subject to all other checks
            cacheable = module.get('cacheable', False)
            if not cacheable:
                for key, value in module.items():
                    if key in KEY_IGNORELIST:
                        continue
                    if type(value) is dict:
                        urls.extend(self._find_urls_in_module(value))
                    if key == 'url':
                        urls.extend([value])
        else:
            return urls
        return urls

    def conditions_helper(self, condition, value, admin_urls):
        # Helper function to find admin urls for conditions
        if (condition.get('condition', None) == 'user_is_admin' or
                condition.get('condition', None) == 'user_is_sysadmin'):
            condition_url = self._find_urls_in_module(value)
            admin_urls.extend(condition_url)
        if condition.get('or', None):
            for or_condition in condition['or']:
                if (or_condition.get('condition', None) == 'user_is_admin' or
                        condition.get('condition', None) == 'user_is_sysadmin'):
                    condition_url = self._find_urls_in_module(value)
                    admin_urls.extend(condition_url)

    def _find_urls_in_admin_module(self, module: Union[dict, list]) -> List[str]:
        # Takes an admin module and traverses the JSON to find URLs - Handles both lists and dicts
        # Returns a list of lists
        admin_urls: List[str] = []
        if type(module) is list:
            for item in module:
                admin_urls.extend(self._find_urls_in_admin_module(item))
        elif type(module) is dict:
            # Connect modules can be marked as "cacheable" meaning authN/authZ checks happen within the JS context.
            # We will ignore modules that are marked as cacheable for now
            # Ref: https://developer.atlassian.com/cloud/confluence/cacheable-app-iframes-for-connect-apps/
            cacheable = module.get('cacheable', False)
            if not cacheable:
                for key, value in module.items():
                    # Handle conditions if module is in list format
                    if type(value) is list:
                        for conditions_module in value:
                            if conditions_module.get('conditions', []):
                                for condition in conditions_module.get('conditions', []):
                                    self.conditions_helper(condition, value, admin_urls)

                    # Handle conditions if module is in dict format
                    if type(value) is dict:
                        for condition_key, condition_value in value.items():
                            if condition_key == 'conditions':
                                for conditions in condition_value:
                                    self.conditions_helper(conditions, value, admin_urls)

        else:
            return admin_urls
        return admin_urls

    def _get_admin_module_links(self) -> List[str]:
        res: List[str] = []
        modules = self.descriptor.get('modules', [])
        # Acquire all URLs from admin modules only
        # Calling itertools here to flatten a list of lists

        # Find URLs in modules listed in ADMIN_MODULES list only
        urls = list(itertools.chain.from_iterable(
            [self._find_urls_in_module(modules[x]) for x in modules if x in ADMIN_MODULES]
        ))

        # Find URLs in modules that have conditions that require admin access
        urls.extend(list(self._find_urls_in_admin_module(modules)))

        # Remove duplicates
        urls = list(set(urls))

        for url in urls:
            # Replace context vars eg. {project.issue} and {condition.is_admin}
            url = self._fill_context_vars(url)
            # Build each module url to be a full link eg. https://example.com/test
            res.append(self._convert_to_full_link(url))

        return res

    def _is_lifecycle_link(self, link: str):
        return link in self.lifecycle_events

    def _generate_fake_jwts(self, link: str, method: str = 'GET') -> Tuple[str, str]:
        # Create a "realistic" Connect JWT using a bogus key and a JWT using the none algorithm
        # Refer to: https://developer.atlassian.com/cloud/confluence/understanding-jwt/ for more info
        # on why we build the JWT token this way
        parsed = urlparse(link)
        method = method.upper()
        qsh = hashlib.sha256(f"{method}&{parsed.path}&{parsed.query}".encode('ascii')).hexdigest()
        token_body = {
            'qsh': qsh,
            'iss': 'csrt-fake-token-ignore',
            'exp': round((datetime.utcnow() + timedelta(hours=3)).timestamp()),
            'iat': round(datetime.utcnow().timestamp())
        }

        hs256_jwt = jwt.encode(token_body, 'fake-jwt-secret', algorithm='HS256')
        none_jwt = jwt.encode(token_body, '', algorithm='none')

        return hs256_jwt, none_jwt

    def _generate_fake_signed_install_jwt(self, link: str, method: str = 'POST') -> str:
        # Create a fake signed-install JWT using a private key
        # Refer to: https://developer.atlassian.com/cloud/confluence/understanding-jwt/ for more info
        parsed = urlparse(link)
        qsh = hashlib.sha256(f"{method}&{parsed.path}&{parsed.query}".encode('ascii')).hexdigest()
        token_body = {
            "aud": self.descriptor_url,
            "sub": "csrt-fake-user-ignore",
            'qsh': qsh,
            'iss': 'csrt-fake-token-ignore',
            "context": {},
            'exp': round((datetime.utcnow() + timedelta(hours=3)).timestamp()),
            'iat': round(datetime.utcnow().timestamp())
        }

        # Generate a dummy private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        rs256_jwt = jwt.encode(token_body, private_key, algorithm='RS256',
                               headers={'typ': 'JWT', 'kid': 'fake-kid', 'alg': 'RS256'})

        return rs256_jwt

    def _get_app_info(self, app_key) -> str:
        url = f"https://marketplace.atlassian.com/rest/2/addons/{app_key}/versions/latest?hosting=cloud"
        try:
            app_info = requests.get(url).json()
            prod = app_info['compatibilities'][0]['application']
            return prod
        except Exception as e:
            logging.error(f"Error while retrieving product type for {app_key}, Error - {e} ")
            return "unknown"

    def _generate_fake_signed_install_payload(self, event_type) -> dict:
        domain = f"csrt-scanner-{random.randint(0, 99999)}.atlassian.net"
        # Fetch the product type this app supports from MPAC endpoint
        product_type = self._get_app_info(self.descriptor.get('key', None))
        client_key = str(''.join(random.choices(string.ascii_lowercase + string.digits, k=8))) + '-' + str(
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))) + '-' + str(
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))) + '-' + str(
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))) + '-' + str(
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)))
        install_payload = {'key': self.descriptor.get('key', None), 'clientKey': client_key, 'cloudId': client_key,
                           'sharedSecret': 'csrt-fake-secret-ignore', 'baseUrl': f'https://{domain}',
                           'eventType': event_type, 'productType': f'{product_type}', 'oauthClientId': client_key,
                           'description': 'CSRT Signed-Install scanner, contact Atlassian EcoAppSec team for more info',
                           'serverVersion': '6452', 'pluginsVersion': '1.801.0'}
        logging.debug(f'Generated fake signed-install payload - {install_payload}')

        return install_payload

    def _authz_check(self, link: str, user_jwt: str = None):
        # Check for authorization bypass on admin endpoints using user JWT token
        params = {
            "jwt": f"{user_jwt}"
        }
        tasks = [
            {'method': 'GET', 'headers': {'Authorization': f"JWT {user_jwt}", 'Connection': 'close'}},
            {'method': 'POST', 'headers': {'Authorization': f"JWT {user_jwt}", 'Connection': 'close'}}
        ]

        res: Optional[requests.Response] = None
        for task in tasks:
            try:
                if user_jwt:
                    no_jwt_res = self.session.request(task['method'], link)
                    logging.debug(f"Requesting admin endpoint {link} via {task['method']} with auth: {task['headers']=}")
                    res = self.session.request(task['method'], link, headers=task['headers'], params=params)
                else:
                    no_jwt_res = None
                    res = None
                if res and res.status_code < 400:
                    # Validate the result without a JWT before flagging it as vulnerable
                    if no_jwt_res and no_jwt_res.status_code == res.status_code:
                        logging.warning(f"{link} does not authenticate requests, skipping endpoint...")
                        return None
                    else:
                        break
                elif res and res.status_code == 503:
                    logging.warning(
                        f"{link} caused a 503 status. Run with --debug for more information. Skipping endpoint...",
                        exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)
                    return None
            except requests.exceptions.ReadTimeout:
                logging.warning(f"{link} timed out, skipping endpoint...")
                self.link_errors['timeouts'] += [f"{link}"]
                return None
            except requests.exceptions.TooManyRedirects:
                logging.warning(f"{link} is causing infinite redirects, skipping endpoint...")
                self.link_errors['infinite_redirects'] += [f"{link}"]
                return None
            except requests.exceptions.RequestException:
                # Only print stacktrace if we are log level DEBUG
                logging.warning(
                    f"{link} caused an exception. Run with --debug for more information. Skipping endpoint...",
                    exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG
                )
                self.link_errors['exceptions'] += [f"{link}"]
                return None
        return res

    def _visit_link(self, link: str) -> Optional[requests.Response]:
        get_hs256, get_none = self._generate_fake_jwts(link, 'GET')
        post_hs256, post_none = self._generate_fake_jwts(link, 'POST')
        # Test for both incorrectly signed JWT and JWT using the None/Null algorithm
        tasks = [
            {'method': 'GET', 'headers': {'Connection': 'close'}},
            {'method': 'GET', 'headers': {'Authorization': f"JWT {get_hs256}", 'Connection': 'close'}},
            {'method': 'GET', 'headers': {'Authorization': f"JWT {get_none}", 'Connection': 'close'}},
            {'method': 'POST', 'headers': {'Connection': 'close'}},
            {'method': 'POST', 'headers': {'Authorization': f"JWT {post_hs256}", 'Connection': 'close'}},
            {'method': 'POST', 'headers': {'Authorization': f"JWT {post_none}", 'Connection': 'close'}}
        ]

        res: Optional[requests.Response] = None
        for task in tasks:

            # Gracefully handle links that result in an exception, report them via warning, and skip any further tests
            try:
                # If we are requesting a lifecycle event, ensure we perform signed-install authentication check
                if self._is_lifecycle_link(link) and any(x in link for x in ('installed', 'uninstalled')):
                    event_type = 'uninstalled' if 'uninstalled' in link else 'installed'
                    rs256_jwt = self._generate_fake_signed_install_jwt(link, 'POST')
                    task['headers']['Content-Type'] = 'application/json'
                    task['headers']['Authorization'] = f"JWT {rs256_jwt}"
                    logging.debug(f"Requesting lifecycle hook {link} via {task['headers']=}")
                    signed_install_payload = self._generate_fake_signed_install_payload(event_type)
                    res = self.session.request('POST', link, headers=task['headers'], json=signed_install_payload)
                    logging.debug(f"Signed install response - Status:{res.status_code} | Res:{res.text}")

                else:
                    logging.debug(f"Requesting {link} via {task['method']} with auth: {task['headers']=}")
                    res = self.session.request(task['method'], link, headers=task['headers'])
                if res.status_code < 400:
                    break
                if res.status_code == 503:
                    logging.warning(
                        f"{link} caused a 503 status. Run with --debug for more information. Skipping endpoint...",
                        exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)
                    self.link_errors['service_unavailable'] += [f"{link}"]
                    return None
            except requests.exceptions.ReadTimeout:
                logging.warning(f"{link} timed out, skipping endpoint...")
                self.link_errors['timeouts'] += [f"{link}"]
                return None
            except requests.exceptions.TooManyRedirects:
                logging.warning(f"{link} is causing infinite redirects, skipping endpoint...")
                self.link_errors['infinite_redirects'] += [f"{link}"]
                return None
            except requests.exceptions.RequestException:
                # Only print stacktrace if we are log level DEBUG
                logging.warning(
                    f"{link} caused an exception. Run with --debug for more information. Skipping endpoint...",
                    exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG
                )
                self.link_errors['exceptions'] += [f"{link}"]
                return None

        return res

    def _get_session_cookies(self, cookiejar: requests.cookies.RequestsCookieJar) -> List[str]:
        res: List[str] = []
        for cookie in cookiejar:
            if cookie.name.upper() in COMMON_SESSION_COOKIES:
                res.append(
                    f"{cookie.name}; Domain={cookie.domain}; Secure={cookie.secure}; HttpOnly={'HttpOnly' in cookie._rest}"
                )

        return res

    def scan(self, user_jwt: str = None) -> DescriptorResult:
        logging.info(f"Scanning app descriptor at: {self.descriptor_url}")
        res = DescriptorResult(
            key=self.descriptor['key'],
            name=self.descriptor['name'],
            base_url=self.base_url,
            app_descriptor_url=self.descriptor_url,
            app_descriptor=self.descriptor,
            scopes=self.descriptor.get('scopes', []),
            links=self.links,
            scan_results={}
        )
        scan_res = defaultdict()
        for link in self.links:
            r = self._visit_link(link)

            # If we are testing an admin restricted link, perform Authorization check
            authz_res = None
            if self.admin_links and link in self.admin_links:
                authz_res = self._authz_check(link, user_jwt)
                logging.debug(f"Found and tested admin link for Authorization issue: {link} |"
                              f" Result: {authz_res.status_code if authz_res else None}")

            if r or authz_res:
                scan_res[link] = DescriptorLink(
                    cache_header=r.headers.get('Cache-Control', 'Header missing'),
                    referrer_header=r.headers.get('Referrer-Policy', 'Header missing'),
                    session_cookies=self._get_session_cookies(r.cookies),
                    auth_header=r.request.headers.get('Authorization', None),
                    req_method=r.request.method,
                    res_code=str(r.status_code),
                    response=str(r.text),
                    authz_req_method=authz_res.request.method if authz_res else None,
                    authz_code=str(authz_res.status_code) if authz_res else None,
                    authz_header=str(authz_res.request.headers.get('Authorization', None)) if authz_res else None,
                )

        res.scan_results = scan_res
        res.link_errors = self.link_errors

        logging.info(f"Descriptor scan complete, found and visited {len(self.links)} links")
        return res
