import logging
import sys

import validators
from models.hsts_result import HstsResult
from utils.csrt_session import create_csrt_session


class HstsScan(object):
    def __init__(self, base_url: str, timeout: int):
        self.base_url = base_url
        self.session = create_csrt_session(timeout)

    def _process_hsts_header(self, hsts_directive: str) -> tuple[str, int]:
        header = hsts_directive.split(',')[0] if hsts_directive else None
        max_age = 0

        for part in header.lower().split(';'):
            part = part.strip()

            if 'max-age' in part:
                max_age = int(part.split('max-age=')[1].strip())

        return header, max_age

    def _check_for_hsts(self) -> tuple[str, int]:
        if validators.url(self.base_url):
            res = self.session.get(self.base_url, allow_redirects=False)
            # Docs: https://docs.python-requests.org/en/master/user/quickstart/#response-headers
            # Requests "headers" dictionary are special and case-insensitive
            hsts_header = res.headers.get('strict-transport-security', None)
            return self._process_hsts_header(hsts_header)
        else:
            # NOTE: This should not be possible to reach. We validate the baseUrl earlier on.
            # This is merely an extra added fail safe.
            logging.error(f"{self.base_url} is not a valid URL, exiting...")
            sys.exit(1)

    def scan(self) -> HstsResult:
        logging.info(f"Checking {self.base_url} for an HSTS header...")
        header, max_age = self._check_for_hsts()

        hsts_res = HstsResult(
            header=header,
            max_age=max_age
        )

        logging.info('HSTS check completed.')
        return hsts_res
