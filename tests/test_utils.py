import logging

import pytest
import requests
from utils import validate_and_resolve_descriptor

ADDON_KEY = ''


# Create a dynamic connect app to scan to ensure the whole end-to-end
# process is working as expected.
def setup_module(module):
    res = requests.post('https://connect-inspector.services.atlassian.com/addon').json()
    global ADDON_KEY
    ADDON_KEY = res['addonKey']
    logging.info(f"Created test app with value: {ADDON_KEY=}")


def test_descriptor_url_valid():
    url = f"https://connect-inspector.services.atlassian.com/resources/{ADDON_KEY}/atlassian-connect.json"
    actual_descriptor = requests.get(url).json()
    base_url, descriptor = validate_and_resolve_descriptor(url)

    assert actual_descriptor == descriptor
    assert base_url == actual_descriptor['baseUrl']


def test_invalid_descriptor_or_url():
    urls = [
        'https://atlassian.com/doesnotexist/connect.json',  # Returns 404
        'atlassian.com',  # Not a URL
        'https://marketplace.atlassian.com/rest/2/addons/com.atlassian.confluence.emcee/versions/latest',  # Random JSON response
        'https://expired.badssl.com'  # Expired HTTPS cert
    ]

    for url in urls:
        with pytest.raises(SystemExit) as wrapped_e:
            validate_and_resolve_descriptor(url)

        assert wrapped_e.type == SystemExit
        assert wrapped_e.value.code == 1


def test_marketplace_url_valid():
    url = 'https://marketplace.atlassian.com/download/apps/1218875/version/1000134/descriptor'
    actual_descriptor = requests.get(url).json()
    base_url, descriptor = validate_and_resolve_descriptor(url)

    assert actual_descriptor == descriptor
    assert base_url == actual_descriptor['baseUrl']


def test_marketplace_url_missing_scopes():
    url = 'https://marketplace.atlassian.com/download/apps/1211655/version/1000017/descriptor'
    actual_descriptor = requests.get(url).json()
    base_url, descriptor = validate_and_resolve_descriptor(url)

    assert actual_descriptor == descriptor
    assert base_url == actual_descriptor['baseUrl']
