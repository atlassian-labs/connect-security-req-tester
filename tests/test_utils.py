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
    descriptor = validate_and_resolve_descriptor(url)

    assert actual_descriptor == descriptor


def test_descriptor_invalid():
    url = 'https://atlassian.com/doesnotexist/connect.json'
    with pytest.raises(SystemExit) as wrapped_e:
        validate_and_resolve_descriptor(url)

    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == 1


def test_url_invalid():
    url = 'atlassian.com'
    with pytest.raises(SystemExit) as wrapped_e:
        validate_and_resolve_descriptor(url)

    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == 1


def test_url_json_invalid():
    url = 'https://marketplace.atlassian.com/rest/2/addons/com.atlassian.confluence.emcee/versions/latest'
    with pytest.raises(SystemExit) as wrapped_e:
        validate_and_resolve_descriptor(url)

    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == 1
