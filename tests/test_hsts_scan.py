from scans.hsts_scan import HstsScan


def test_init_domain_valid():
    base_url = 'https://atlassian.com/connect-app'
    scanner = HstsScan(base_url, 5)

    assert scanner.base_url == base_url


def test_hsts_header_valid():
    base_url = 'https://hsts.badssl.com'
    scanner = HstsScan(base_url, 5)
    res = scanner.scan()

    assert res.header == 'max-age=15768000; includeSubDomains'


def test_hsts_header_preload_valid():
    base_url = 'https://preloaded-hsts.badssl.com/'
    scanner = HstsScan(base_url, 5)
    res = scanner.scan()

    assert res.header == 'max-age=15768000; includeSubDomains; preload'


def test_hsts_header_and_max_age_valid():
    base_url = 'https://www.atlassian.com/'
    scanner = HstsScan(base_url, 5)
    res = scanner.scan()

    assert res.header == 'max-age=63072000; preload'


def test_hsts_invalid():
    base_url = 'https://example.com'
    scanner = HstsScan(base_url, 5)
    res = scanner.scan()

    assert res.header is None
