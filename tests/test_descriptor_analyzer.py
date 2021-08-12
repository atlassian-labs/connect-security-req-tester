import json

from analyzers.descriptor_analyzer import DescriptorAnalyzer
from models.descriptor_result import DescriptorResult
from models.requirements import Requirements
from reports.constants import (MISSING_ATTRS_SESSION_COOKIE,
                               MISSING_AUTHN_AUTHZ, MISSING_CACHE_HEADERS,
                               MISSING_REF_HEADERS, NO_ISSUES, VALID_AUTH_PROOF)


def test_good_scan():
    file = 'tests/examples/desc_scan_valid.json'
    scan = DescriptorResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = DescriptorAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req2.passed is True
    assert res.req2.description == [NO_ISSUES]
    assert res.req2.proof == []
    assert res.req5.passed is True
    assert res.req5.description == [NO_ISSUES]
    assert res.req5.proof == [VALID_AUTH_PROOF]
    assert res.req11.passed is True
    assert res.req11.description == [NO_ISSUES]
    assert res.req11.proof == []
    assert res.req12.passed is True
    assert res.req12.description == [NO_ISSUES]
    assert res.req12.proof == []


def test_bad_cache_header():
    file = 'tests/examples/desc_scan_cache_headers.json'
    scan = DescriptorResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = DescriptorAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req2.passed is False
    assert res.req2.description == [MISSING_CACHE_HEADERS]
    assert res.req2.proof == ['https://bbc7069740af.ngrok.io/installed | Cache header: Header missing']
    assert res.req5.passed is True
    assert res.req5.description == [NO_ISSUES]
    assert res.req5.proof == [VALID_AUTH_PROOF]
    assert res.req11.passed is True
    assert res.req11.description == [NO_ISSUES]
    assert res.req11.proof == []
    assert res.req12.passed is True
    assert res.req12.description == [NO_ISSUES]
    assert res.req12.proof == []


def test_bad_referrer_header():
    file = 'tests/examples/desc_scan_referrer_headers.json'
    scan = DescriptorResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = DescriptorAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req2.passed is True
    assert res.req2.description == [NO_ISSUES]
    assert res.req2.proof == []
    assert res.req5.passed is True
    assert res.req5.description == [NO_ISSUES]
    assert res.req5.proof == [VALID_AUTH_PROOF]
    assert res.req11.passed is True
    assert res.req11.description == [NO_ISSUES]
    assert res.req11.proof == []
    assert res.req12.passed is False
    assert res.req12.description == [MISSING_REF_HEADERS]
    assert res.req12.proof == [
        'https://bbc7069740af.ngrok.io/installed | Referrer header: Header missing',
        'https://bbc7069740af.ngrok.io/my-admin-page | Referrer header: unsafe-url'
    ]


def test_bad_cookies():
    file = 'tests/examples/desc_scan_cookies.json'
    scan = DescriptorResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = DescriptorAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req2.passed is True
    assert res.req2.description == [NO_ISSUES]
    assert res.req2.proof == []
    assert res.req5.passed is True
    assert res.req5.description == [NO_ISSUES]
    assert res.req5.proof == [VALID_AUTH_PROOF]
    assert res.req11.passed is False
    assert res.req11.description == [MISSING_ATTRS_SESSION_COOKIE]
    assert res.req11.proof == ['https://bbc7069740af.ngrok.io/installed | Cookie: JSESSIONID; Domain=9ee0fd043609.ngrok.io; Secure=False; HttpOnly=True']
    assert res.req12.passed is True
    assert res.req12.description == [NO_ISSUES]
    assert res.req12.proof == []


def test_bad_authn():
    file = 'tests/examples/desc_scan_authn.json'
    scan = DescriptorResult(json.load(open(file, 'r')))
    reqs = Requirements()
    analyzer = DescriptorAnalyzer(scan, reqs)

    res = analyzer.analyze()

    assert res.req2.passed is True
    assert res.req2.description == [NO_ISSUES]
    assert res.req2.proof == []
    assert res.req5.passed is False
    assert res.req5.description == [MISSING_AUTHN_AUTHZ]
    assert res.req5.proof == [
        'https://bbc7069740af.ngrok.io/installed | Res Code: 200 Req Method: GET Auth Header: ',
        'https://bbc7069740af.ngrok.io/my-admin-page | Res Code: 200 Req Method: GET Auth Header: JWT sometexthere'
    ]
    assert res.req11.passed is True
    assert res.req11.description == [NO_ISSUES]
    assert res.req11.proof == []
    assert res.req12.passed is True
    assert res.req12.description == [NO_ISSUES]
    assert res.req12.proof == []
