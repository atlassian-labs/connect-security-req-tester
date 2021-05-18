import json

from analyzers.hsts_analyzer import HstsAnalyzer
from models.hsts_result import HstsResult
from models.requirements import Requirements
from reports.constants import HSTS_MISSING, NO_ISSUES, REQ_TITLES


def test_valid_scan():
    file = 'tests/examples/hsts_valid.json'
    scan = HstsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = HstsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req1_2.passed is True
    assert res.req1_2.description == [NO_ISSUES]
    assert res.req1_2.proof == []
    assert res.req1_2.title == REQ_TITLES['1.2']


def test_invalid_scan_header():
    file = 'tests/examples/hsts_invalid_header.json'
    scan = HstsResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = HstsAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req1_2.passed is False
    assert res.req1_2.description == [HSTS_MISSING]
    assert res.req1_2.proof == [
        'We did not detect an HSTS header when scanning your app\'s baseUrl.'
    ]
    assert res.req1_2.title == REQ_TITLES['1.2']
