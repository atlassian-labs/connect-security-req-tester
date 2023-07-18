import json

from analyzers.tls_analyzer import TlsAnalyzer
from models.requirements import Requirements
from models.tls_result import TlsResult
from reports.constants import CERT_NOT_VALID, NO_ISSUES, TLS_PROTOCOLS


def test_good_scan():
    file = 'tests/examples/tls_scan_valid.json'
    scan = TlsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = TlsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req3.passed is True
    assert res.req3.description == [NO_ISSUES]
    assert res.req3.proof == []
    assert res.req6_2.passed is True
    assert res.req6_2.description == [NO_ISSUES]
    assert res.req6_2.proof == []


def test_expired_cert():
    file = 'tests/examples/tls_scan_expired.json'
    scan = TlsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = TlsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req3.passed is False
    assert res.req3.description == [TLS_PROTOCOLS]
    assert res.req3.proof == ['Your domain: example.com - presented the following protocols: [\'TLS_1_2\', \'TLS_1_1\', \'TLS_1_0\']']
    assert res.req6_2.passed is False
    assert res.req6_2.description == [CERT_NOT_VALID]
    assert res.req6_2.proof == ['Your domain: example.com - presented an HTTPS certificate that was not valid.']
