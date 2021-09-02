import logging
import sys
from typing import Optional

import validators

from utils.csrt_session import create_csrt_session

REQUIRED_KEYS = ['baseUrl', 'key', 'name']


class AppValidator(object):
    def __init__(self, descriptor_url: str, timeout: int):
        self.session = create_csrt_session(timeout)
        self.descriptor_url = descriptor_url
        self.descriptor = self._get_and_request_descriptor()

    def _get_and_request_descriptor(self) -> Optional[dict]:
        descriptor = None
        try:
            descriptor = self.session.get(self.descriptor_url)
            descriptor.raise_for_status()
            descriptor = descriptor.json()
        except Exception as e:
            logging.error(f"Could not retrieve connect descriptor at: {self.descriptor_url}\nException: {e}")
            raise(e)

        return descriptor

    def _validate_base_url(self) -> bool:
        res = validators.url(self.descriptor['baseUrl'], public=True)
        if not res:
            logging.error(f"{self.descriptor['baseUrl']} was not a valid URL.")
        return bool(res)

    def _validate_dns_and_network_connectivity(self) -> bool:
        if self._is_cached_descriptor():
            try:
                # We attempt to request the app's baseUrl to determine if the app is up or not
                # There is no need to follow redirects, a 302 response still indicates in-some-way that the app is responding.
                self.session.get(self.descriptor['baseUrl'], allow_redirects=False)
            except Exception as e:
                logging.error(f"Failed to request {self.descriptor['baseUrl']} - DNS or Networking error occurred.")
                logging.debug(f"Exception: {e}")
                return False

        return True

    def _validate_required_keys(self) -> bool:
        res = all(keys in self.descriptor for keys in REQUIRED_KEYS)
        if not res:
            logging.error(f"App Descriptor does not contain all required keys: {REQUIRED_KEYS}")
        return res

    def validate(self) -> bool:
        res = self._validate_required_keys() and self._validate_base_url() and self._validate_dns_and_network_connectivity()
        if not res:
            sys.exit(1)
        return res

    def _is_cached_descriptor(self) -> bool:
        return self.descriptor_url.startswith('https://marketplace.atlassian.com/download/apps/')

    def get_descriptor(self) -> dict:
        return self.descriptor

    def get_test_url(self) -> str:
        # If scanning a marketplace cached descriptor, test using the app's baseUrl
        # Otherwise, use the descriptor URL provided as it should be able to return a 200/OK response
        # which is a good way for us to test for TLS/HSTS
        if self._is_cached_descriptor():
            return self.descriptor['baseUrl']
        else:
            return self.descriptor_url
