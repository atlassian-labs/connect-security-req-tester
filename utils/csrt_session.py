import logging
import os

import requests
from requests.adapters import HTTPAdapter

session = None


# Ref: https://stackoverflow.com/a/62044100
# Create an HTTP Adapter that we can mount to a Requests.Session object to globally apply
# a timeout on all requests
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        timeout = kwargs.get("timeout", 30)
        super().__init__(*args, **kwargs)
        self.timeout = timeout

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None and hasattr(self, 'timeout'):
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


def create_csrt_session(timeout: int = 30) -> requests.Session:
    """Return a requests.Session object setup in a standard way to make HTTP requests from

    Returns:
        requests.Session: A session object pre-configured for timeouts, a standardized user-agent, and does not verify SSL/TLS
    """
    global session

    # See if an outbound proxy was defined, if so capture the connection string
    proxy_config = os.getenv('OUTBOUND_PROXY')

    if not session:
        session = requests.Session()
        session.mount('http://', TimeoutHTTPAdapter(timeout=timeout))
        session.mount('https://', TimeoutHTTPAdapter(timeout=timeout))
        proxies = {
            'http': proxy_config if proxy_config else None,
            'https': proxy_config if proxy_config else None
        }
        session.headers.update(
            {'User-Agent': 'CSRT (github.com/atlassian-labs/connect-security-req-tester)'}
        )
        session.verify = False
        session.proxies.update(proxies)

        # Log relevant information about proxy usage
        check_for_proxy(session)

    return session


def check_for_proxy(session: requests.Session) -> None:
    if (proxy_config := os.getenv('OUTBOUND_PROXY')):
        try:
            res = session.get('https://httpbin.org/ip').json().get('origin', None)
            logging.info(f"Using proxy: {proxy_config} | Detected IP: {res}")
        except Exception:
            logging.warning(f"Using proxy: {proxy_config} | Could not identify external IP.")
