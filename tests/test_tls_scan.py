from collections import defaultdict

from scans.tls_scan import TlsScan


def test_init_valid():
    # We expect to call this with the URL of the connect descriptor,
    # so we will call it as such with the tests
    url = 'https://atlassian.com/random/atlassian-connect.json'
    scanner = TlsScan(url)

    assert scanner.base_url == url
    assert scanner.session is not None


def test_tls_valid():
    url = 'https://atlassian.com'
    scanner = TlsScan(url)
    res = scanner.scan().to_json()

    ips_scanned = defaultdict()
    for ip in res['scan_results']:
        ips_scanned[ip] = {
            'protocols': res['scan_results'][ip]['protocols'],
            'hsts': {
                'LONG_MAX_AGE': 15552000,
                'header': 'max-age=63072000; preload',
                'status': 'present',
                'maxAge': 63072000,
                'preload': True,
                'directives': {
                    'max-age': '63072000',
                    'preload': ''
                }
            },
            'cert_grade': 'A+'
        }

    expected_res = {
        'ips_scanned': 3,
        'protocols': res['protocols'],
        'hsts_present': True,
        'trusted': True,
        'scan_results': ips_scanned
    }
    expected_protos = ['TLS 1.2', 'TLS 1.3']

    # Protocols may end up any order, this ensures we have the protocols we expect
    assert all(proto in expected_protos for proto in res['protocols'])
    assert res == expected_res


def test_hsts_valid():
    url = 'https://hsts.badssl.com'
    scanner = TlsScan(url)
    res = scanner.scan().to_json()

    assert res['hsts_present'] is True
    assert res['trusted'] is True
    assert res['ips_scanned'] == 1


def test_untrusted_cert():
    url = 'https://expired.badssl.com/'
    scanner = TlsScan(url)
    res = scanner.scan().to_json()

    assert res['trusted'] is False
