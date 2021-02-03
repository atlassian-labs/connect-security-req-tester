import requests
from requests.adapters import HTTPAdapter

session = None


# Ref: https://stackoverflow.com/a/62044100
# Create an HTTP Adapter that we can mount to a Requests.Session object to globally apply
# a timeout on all requests
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

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
    if not session:
        session = requests.Session()
        session.mount('http://', TimeoutHTTPAdapter(timeout=timeout))
        session.mount('https://', TimeoutHTTPAdapter(timeout=timeout))
        session.headers.update(
            {'User-Agent': 'CSRT (github.com/atlassian-labs/connect-security-req-tester)'}
        )
        session.verify = False

    return session
