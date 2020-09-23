import hashlib
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

import jwt
import requests

from models.descriptor_result import DescriptorLink, DescriptorResult

COMMON_SESSION_COOKIES = ['PHPSESSID', 'JSESSIONID', 'CFID', 'CFTOKEN', 'ASP.NET_SESSIONID']
KEY_IGNORELIST = ['icon', 'icons', 'documentation']
CONDITION_MATCHER = r'{condition\..*}'
BRACES_MATCHER = r'\$?{.*}'


class DescriptorScan(object):
    def __init__(self, descriptor_url, descriptor):
        self.descriptor_url = descriptor_url
        self.descriptor = descriptor
        self.base_url = descriptor['baseUrl'] if not descriptor['baseUrl'].endswith('/') else descriptor['baseUrl'][:-1]
        self.links = self._get_links()

    def _get_links(self):
        res = []
        lifecycle_events = self.descriptor.get('lifecycle', [])
        modules = self.descriptor.get('modules', [])
        # Grab all lifecycle events
        urls = [evt for evt in lifecycle_events]
        # Grab all URLs from modules, this magic flattens a list of lists to a single list structure
        urls += [item for sublist in [self._find_urls_in_module(modules[x]) for x in modules] for item in sublist]

        # Remove duplicates
        urls = list(set(urls))

        for url in urls:
            # Replace context vars eg. {project.issue} and {condition.is_admin}
            url = self._fill_context_vars(url)
            # Build each module url to be a full link eg. https://example.com/test
            res.append(self._convert_to_full_link(url))

        return res

    def _convert_to_full_link(self, link):
        if not link.startswith('http://') and not link.startswith('https://'):
            link = link if not link.startswith('/') else link[1:]
            link = f"{self.base_url}/{link}"

        return link

    def _fill_context_vars(self, url):
        url = re.sub(CONDITION_MATCHER, 'true', url, flags=re.IGNORECASE)
        url = re.sub(BRACES_MATCHER, 'test', url)

        return url

    def _find_urls_in_module(self, module):
        # Takes a connect module and traverses the JSON to find URLs - Handles both lists and dicts
        # Returns a list of lists
        urls = []
        if type(module) is list:
            for item in module:
                urls.extend(self._find_urls_in_module(item))
        elif type(module) is dict:
            for key, value in module.items():
                if key in KEY_IGNORELIST:
                    continue
                if type(value) is dict:
                    urls.extend(self._find_urls_in_module(value))
                if key == 'url':
                    return [value]
        else:
            return urls
        return urls

    def _generate_fake_jwts(self, link, method='GET'):
        # Create a "realistic" Connect JWT using a bogus key and a JWT using the none algorithm
        # Refer to: https://developer.atlassian.com/cloud/confluence/understanding-jwt/ for more info
        # on why we build the JWT token this way
        parsed = urlparse(link)
        method = method.upper()
        qsh = hashlib.sha256(f"{method}&{parsed.path}&{parsed.query}".encode('ascii')).hexdigest()
        token_body = {
            'qsh': qsh,
            'iss': 'csrt-fake-token-ignore',
            'exp': round((datetime.now() + timedelta(hours=3)).timestamp()),
            'iat': round(datetime.now().timestamp())
        }

        hs256_jwt = jwt.encode(token_body, 'fake-jwt-secret', algorithm='HS256')
        none_jwt = jwt.encode(token_body, None, algorithm='none')

        return hs256_jwt, none_jwt

    def _visit_link(self, link):
        get_hs256, get_none = self._generate_fake_jwts(link, 'GET')
        post_hs256, post_none = self._generate_fake_jwts(link, 'POST')
        tasks = [
            {'method': 'GET', 'headers': None},
            {'method': 'GET', 'headers': {'Authorization': f"JWT {get_hs256}"}},
            {'method': 'GET', 'headers': {'Authorization': f"JWT {get_none}"}},
            {'method': 'POST', 'headers': None},
            {'method': 'POST', 'headers': {'Authorization': f"JWT {post_hs256}"}},
            {'method': 'POST', 'headers': {'Authorization': f"JWT {post_none}"}}
        ]

        res = None
        for task in tasks:
            res = requests.request(task['method'], link, headers=task['headers'])
            if res.status_code < 400:
                return res, True

        return res, False

    def _get_session_cookies(self, cookiejar):
        res = []
        for cookie in cookiejar:
            if cookie.name.upper() in COMMON_SESSION_COOKIES:
                res.append(f"{cookie.name}; Domain={cookie.domain}; Secure={cookie.secure}; HttpOnly={cookie._rest.get('HttpOnly', False)}")

        return res

    def scan(self):
        logging.info(f"Scanning app descriptor at: {self.descriptor_url}")
        res = DescriptorResult(
            key=self.descriptor['key'],
            name=self.descriptor['name'],
            base_url=self.base_url,
            app_descriptor_url=self.descriptor_url,
            app_descriptor=self.descriptor,
            scopes=self.descriptor['scopes'],
            links=self.links,
            scan_results={}
        )
        scan_res = defaultdict()
        for link in self.links:
            r, jwt_used = self._visit_link(link)
            scan_res[link] = DescriptorLink(
                cache_header=r.headers.get('Cache-Control', 'Header missing'),
                referrer_header=r.headers.get('Referrer-Policy', 'Header missing'),
                session_cookies=self._get_session_cookies(r.cookies),
                jwt_used=jwt_used,
                res_code=str(r.status_code)
            )

        res.scan_results = scan_res

        logging.info(f"Descriptor scan complete, found and visited {len(self.links)} links")
        return res
