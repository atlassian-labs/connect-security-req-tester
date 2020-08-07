import requests
import json
import utils
import logging
from collections import defaultdict
from models.descriptor_result import DescriptorResult, DescriptorLink

COMMON_SESSION_COOKIES = ['PHPSESSID', 'JSESSIONID', 'CFID', 'CFTOKEN', 'ASP.NET_SESSIONID']


class DescriptorScan(object):
    def __init__(self, descriptor_url):
        self.descriptor_url = descriptor_url
        self.descriptor, self.base_url = self._get_descriptor_and_base_url(self.descriptor_url)
        self.links = self._get_links()

    def _get_descriptor_and_base_url(self, descriptor_url):
        headers = {'Accept': 'application/json'}
        res = requests.get(descriptor_url, headers=headers).json()
        base_url = res['baseUrl'] if not res['baseUrl'].endswith('/') else res['baseUrl'][:-1]

        return res, base_url

    def _get_links(self):
        res = []
        lifecycle_events = self.descriptor.get('lifecycle', [])
        for evt in lifecycle_events:
            res.append(self._convert_to_full_link(evt))
        modules = self.descriptor.get('modules', [])
        modules_urls = []
        for module in modules:
            modules_urls.extend(utils.find_url_in_module(modules[module]))

        for url in modules_urls:
            res.append(self._convert_to_full_link(url))

        return list(set(res))

    def _convert_to_full_link(self, link):
        if not link.startswith('http://') and not link.startswith('https://'):
            link = link if not link.startswith('/') else link[1:]
            link = f"{self.base_url}/{link}"

        return link

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
