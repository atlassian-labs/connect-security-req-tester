import pytest
import requests
from utils.csrt_session import create_csrt_session
import utils.csrt_session as csrt_session


def setup_module(module):
    # Zero out the session object just in-case it has already been setup, yay global variables
    csrt_session.session = None


def teardown_module(module):
    # Reset our session back to None to ensure other tests aren't affected by our shenanigans
    csrt_session.session = None


def test_session_timeout():
    session = create_csrt_session(timeout=5)

    with pytest.raises((requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError)) as wrapped_e:
        session.get('https://httpstat.us/200?sleep=50000')

    assert wrapped_e.type in (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError)
