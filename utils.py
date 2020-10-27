import logging
import sys

import requests
import validators


def validate_and_resolve_descriptor(url):
    """Validate and resolve the provided URL to a connect app descriptor. Ensure the URL is well-formed,
    is externally reachable via a web request, and that it contains the required fields.

    Args:
        url (str): The URL to the connect app descriptor

    Returns:
        tuple(str, dict): The app's base URL and the connect app descriptor
    """
    if not validators.url(url):
        logging.error(
            'Descriptor URL appears invalid, confirm the link to your Connect Descriptor.'
        )
        sys.exit(1)
    # Fetch the descriptor, ensure file is JSON, reachable, and contains required fields
    res = None
    required_fields = ['baseUrl', 'key', 'name', 'scopes']
    try:
        res = requests.get(url)
        res.raise_for_status()
        res = res.json()
        # Ensure we have the required fields we use later on
        if not all(fields in res for fields in required_fields):
            raise Exception('Connect Descriptor is not valid.')
        # Ensure the base URL is reachable and exists - This ensures a simple DNS lookup succeeds
        requests.get(res['baseUrl'])
    except Exception as e:
        logging.error(f"We were unable to retrieve the connect descriptor at: {url}\nException: {str(e)}")
        sys.exit(1)

    return res['baseUrl'], res
