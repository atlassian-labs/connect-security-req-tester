import json
import logging

import pytest
import requests
from utils.app_validator import AppValidator

ADDON_KEY = ''


# Create a dynamic connect app to scan to ensure the whole end-to-end
# process is working as expected.
def setup_module(module):
    res = requests.post('https://connect-inspector.services.atlassian.com/addon').json()
    global ADDON_KEY
    ADDON_KEY = res['addonKey']
    logging.info(f"Created test app with value: {ADDON_KEY=}")


def test_descriptor_fetch():
    url = f"https://connect-inspector.services.atlassian.com/resources/{ADDON_KEY}/atlassian-connect.json"
    actual_descriptor = requests.get(url).json()
    validator = AppValidator(url, 30)

    assert validator.descriptor == actual_descriptor
    assert validator.descriptor_url == url
    assert validator.session is not None


def test_valid_descriptor():
    url = f"https://connect-inspector.services.atlassian.com/resources/{ADDON_KEY}/atlassian-connect.json"
    validator = AppValidator(url, 30)

    assert validator.validate() is True


def test_missing_keys():
    descriptor_file = 'tests/examples/descriptor_missing_keys.json'
    validator = object.__new__(AppValidator)
    validator.session = None
    validator.descriptor_url = 'https://example.com'
    validator.descriptor = json.loads(open(descriptor_file, 'r').read())
    validator.timeout = 30

    assert validator._validate_required_keys() is False
    with pytest.raises(SystemExit) as wrapped_e:
        validator.validate()

    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == 1


def test_invalid_base_url():
    descriptor_file = 'tests/examples/descriptor_invalid_base_url.json'
    validator = object.__new__(AppValidator)
    validator.session = None
    validator.descriptor_url = 'https://example.com'
    validator.descriptor = json.loads(open(descriptor_file, 'r').read())
    validator.timeout = 30

    assert validator._validate_base_url() is False
    with pytest.raises(SystemExit) as wrapped_e:
        validator.validate()

    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == 1


def test_invalid_remote_descriptor():
    # Test for exceptions on non-JSON responses and when a descriptor returns an error HTTP status code
    remote_url_non_json = 'https://example.com'
    remote_url_404 = 'https://example.com/doesnotexist'

    with pytest.raises(requests.exceptions.JSONDecodeError) as wrapped_e:
        AppValidator(remote_url_non_json, 30)

    assert wrapped_e.type == requests.exceptions.JSONDecodeError

    with pytest.raises(requests.exceptions.HTTPError) as wrapped_e:
        AppValidator(remote_url_404, 30)

    assert wrapped_e.type == requests.exceptions.HTTPError
