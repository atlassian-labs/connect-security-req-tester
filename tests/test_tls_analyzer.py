import json

from analyzers.tls_analyzer import TlsAnalyzer
from models.requirements import Requirements
from models.tls_result import TlsResult
from reports.constants import (CERT_NOT_VALID, HSTS_MISSING, NO_ISSUES,
                               TLS_PROTOCOLS)


def test_good_scan():
    file = 'tests/examples/tls_scan_valid.json'
    scan = TlsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = TlsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req1.passed is True
    assert res.req1.description == [NO_ISSUES]
    assert res.req1.proof == []
    assert res.req3.passed is True
    assert res.req3.description == [NO_ISSUES]
    assert res.req3.proof == []


def test_hsts_valid():
    file = 'tests/examples/tls_scan_hsts.json'
    scan = TlsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = TlsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req1.passed is False
    assert res.req1.description == [TLS_PROTOCOLS]
    assert res.req1.proof == ['104.154.89.105 - [\'TLS 1.0\', \'TLS 1.1\', \'TLS 1.2\']']
    assert res.req3.passed is True
    assert res.req3.description == [NO_ISSUES]
    assert res.req3.proof == []


def test_expired_cert():
    file = 'tests/examples/tls_scan_expired.json'
    scan = TlsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = TlsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req1.passed is False
    assert res.req1.description == [TLS_PROTOCOLS, HSTS_MISSING]
    assert res.req1.proof == [
        '104.154.89.105 - [\'TLS 1.0\', \'TLS 1.1\', \'TLS 1.2\']',
        '104.154.89.105 - {\'LONG_MAX_AGE\': 15552000, \'status\': \'absent\', \'directives\': {}}'
    ]
    assert res.req3.passed is False
    assert res.req3.description == [CERT_NOT_VALID]
    assert res.req3.proof == ['104.154.89.105 - Failing Grade of T']
