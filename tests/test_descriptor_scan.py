import json
import logging
from collections import defaultdict

import requests
from scans.descriptor_scan import DescriptorScan

ADDON_KEY = ''


# Create a dynamic connect app to scan to ensure the whole end-to-end
# process is working as expected.
def setup_module(module):
    res = requests.post('https://connect-inspector.services.atlassian.com/addon').json()
    global ADDON_KEY
    ADDON_KEY = res['addonKey']
    logging.info(f"Created test app with value: {ADDON_KEY=}")


def get_links_from_descriptor(descriptor):
    # Automagically create the list of links because we know how Connect Inspector apps are defined
    links = []
    links += [descriptor['baseUrl'] + descriptor['lifecycle'][x] for x in descriptor['lifecycle'].keys()]
    links += [descriptor['baseUrl'] + x['url'] for x in descriptor['modules']['webhooks']]
    links += [x['url'] for x in descriptor['modules']['webItems']]
    return list(set(links))


def get_lifecycle_events_from_descriptor(descriptor):
    return [descriptor['baseUrl'] + event for event in [descriptor['lifecycle'][event] for event in descriptor['lifecycle']]]


def create_scan_results(links):
    res = defaultdict()
    for link in links:
        response = requests.get(link)
        res[link] = {
            'cache_header': 'Header missing',
            'referrer_header': 'Header missing',
            'session_cookies': [],
            'auth_header': None,
            'req_method': 'POST' if any(x in link for x in ['installed', 'uninstalled']) else 'GET',
            'res_code': '200' if '?' in link else '204',
            'response': str(response.text)
        }
    return res


def test_init_valid_url():
    valid_url = f"https://connect-inspector.services.atlassian.com/resources/{ADDON_KEY}/atlassian-connect.json"
    descriptor = requests.get(valid_url).json()
    scanner = DescriptorScan(valid_url, descriptor, 30)
    links = get_links_from_descriptor(descriptor)
    lifecycle_events = get_lifecycle_events_from_descriptor(descriptor)

    assert scanner.descriptor_url == valid_url
    assert scanner.descriptor == descriptor
    assert scanner.base_url == descriptor['baseUrl']
    assert set(scanner.links) == set(links)
    assert set(scanner.lifecycle_events) == set(lifecycle_events)


def test_scan_valid_app():
    valid_url = f"https://connect-inspector.services.atlassian.com/resources/{ADDON_KEY}/atlassian-connect.json"
    descriptor = requests.get(valid_url).json()
    scanner = DescriptorScan(valid_url, descriptor, 30)
    res = scanner.scan().to_json()
    res['links'].sort()
    # Replace auth header to None for signed install/uninstall events
    for link in res['scan_results']:
        if any(x in link for x in ['installed', 'uninstalled']):
            res['scan_results'][link]['auth_header'] = None
    res = json.dumps(res, sort_keys=True)

    links = get_links_from_descriptor(descriptor)
    links.sort()

    scan_res = create_scan_results(links)

    expected_res = json.dumps({
        'key': descriptor['key'],
        'name': descriptor['name'],
        'base_url': descriptor['baseUrl'],
        'app_descriptor_url': valid_url,
        'app_descriptor': descriptor,
        'scopes': descriptor['scopes'],
        'links': links,
        'scan_results': scan_res,
        'response': scan_res.get('response', None),
        'link_errors': {}
    }, sort_keys=True)

    assert res == expected_res
