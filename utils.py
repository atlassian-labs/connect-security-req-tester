import logging
import sys

import requests
import validators


def validate_and_resolve_descriptor(url):
    """Validate that the connect descriptor URL provided is valid, and then request
    the descriptor from the remote URL. Return the descriptor URL from the descriptor
    file instead of trusting user-input.

    Args:
        url (str): The user-supplied descriptor URL

    Returns:
        dict: The app descriptor at the url converted to a dict
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
    except Exception:
        logging.error(f"We were unable to retrieve the connect descriptor at: {url}")
        sys.exit(1)

    return res
