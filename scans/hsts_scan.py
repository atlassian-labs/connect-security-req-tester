import logging
import sys
from typing import Optional

import validators
from models.hsts_result import HstsResult
from utils.csrt_session import create_csrt_session


class HstsScan(object):
    def __init__(self, base_url: str, timeout: int):
        self.base_url = base_url
        self.session = create_csrt_session(timeout)

    def _check_for_hsts(self) -> Optional[str]:
        if validators.url(self.base_url):
            res = self.session.get(self.base_url, allow_redirects=False)
            # Docs: https://docs.python-requests.org/en/master/user/quickstart/#response-headers
            # Requests "headers" dictionary are special and case-insensitive
            hsts_header = res.headers.get('strict-transport-security', None)
            return hsts_header
        else:
            # NOTE: This should not be possible to reach. We validate the baseUrl earlier on.
            # This is merely an extra added fail safe.
            logging.error(f"{self.base_url} is not a valid URL, exiting...")
            sys.exit(1)

    def scan(self) -> HstsResult:
        logging.info(f"Checking {self.base_url} for an HSTS header...")
        header = self._check_for_hsts()

        hsts_res = HstsResult(
            header=header
        )

        logging.info('HSTS check completed.')
        return hsts_res
