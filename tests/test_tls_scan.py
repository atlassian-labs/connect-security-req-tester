from scans.tls_scan import TlsScan
import time


def test_init_domain_valid():
    url = 'https://atlassian.com/random/atlassian-connect.json'
    scanner = TlsScan(url)

    assert scanner.domain == 'atlassian.com'


def test_tls_valid():
    url = 'https://atlassian.com'
    scanner = TlsScan(url)
    res = scanner.scan()

    expected_protos = ['TLS_1_2', 'TLS_1_3']

    assert res.ips_scanned == 1
    assert all(proto in expected_protos for proto in res.protocols)
    assert res.trusted is True
    assert res.scan_results is not None


def test_untrusted_certs():
    # A handful of different ways an HTTPS cert can be invalid
    urls = [
        'https://expired.badssl.com/',
        'https://wrong.host.badssl.com/',
        'https://self-signed.badssl.com/',
        'https://untrusted-root.badssl.com/'
    ]

    for url in urls:
        scanner = TlsScan(url)
        res = scanner.scan()

        assert res.trusted is False
        assert res.ips_scanned == 1
        assert res.scan_results is not None
        # Github actions seem to fail with this test, adding a sleep between scans to
        # hopefully make whatever is upset less mad.
        time.sleep(1)
