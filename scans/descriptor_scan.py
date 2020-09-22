import logging
import re
from collections import defaultdict

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

    def _visit_link(self, link):
        res = requests.get(link)

        if res.status_code >= 400:
            res = requests.post(link)

        return res

    def _get_session_cookies(self, cookiejar):
        res = []
        for cookie in cookiejar:
            if cookie.name.upper() in COMMON_SESSION_COOKIES:
                res.append(f"{cookie.name}; Domain={cookie.domain}; Secure={cookie.secure}; HttpOnly={cookie._rest.get('HttpOnly', False)}")

        return res

    def scan(self):
        logging.info(f"Scanning descriptor for {self.descriptor['name']}...")
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
            r = self._visit_link(link)
            scan_res[link] = DescriptorLink(
                cache_header=r.headers.get('Cache-Control', 'Header missing'),
                referrer_header=r.headers.get('Referrer-Policy', 'Header missing'),
                session_cookies=self._get_session_cookies(r.cookies),
                res_code=str(r.status_code)
            )

        res.scan_results = scan_res

        logging.info(f"Descriptor scan complete, found and visited {len(self.links)} links")
        return res
