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
        tuple(str,str): The determined descriptor url and full descriptor file json parsed
    """
    if not validators.url(url):
        logging.error(
            'Descriptor URL appears invalid, confirm the link to your Connect Descriptor.'
        )
        sys.exit(1)
    # Attempt to resolve descriptor...
    res = requests.get(url)
    res.raise_for_status()

    descriptor = res.json()
    remote_url = descriptor.get('links', {}).get('self', None)

    if not remote_url:
        base_url = descriptor['baseUrl'] if descriptor['baseUrl'].endswith('/') else descriptor['baseUrl'] + '/'
        remote_url = base_url + 'atlassian-connect.json'

    logging.debug(f"Resolved descriptor location: {remote_url}")
    return remote_url, descriptor
