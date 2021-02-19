from analyzers.branding_analyzer import BrandingAnalyzer
from models.requirements import Requirements
from reports.constants import BRANDING_ISSUE, NO_ISSUES, REQ_TITLES


def test_init_valid():
    links = ['https://google.com', 'https://google.com/link']
    name = 'Example App'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    assert analyzer.links == links
    assert analyzer.app_name == name
    assert analyzer.reqs == reqs


def test_bad_domain():
    links = ['https://confluence.com/confluence']
    name = 'Example App'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    res = analyzer.analyze()

    assert res.req16.passed is False
    assert res.req16.description == [BRANDING_ISSUE]
    assert res.req16.title == REQ_TITLES['16']
    assert res.req16.proof == [f"{links[0]} | Contains a denied word in the subdomain or primary domain"]


def test_bad_name():
    links = ['https://google.com']
    name = 'Confluence Connect App'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    res = analyzer.analyze()

    assert res.req16.passed is False
    assert res.req16.description == [BRANDING_ISSUE]
    assert res.req16.title == REQ_TITLES['16']
    assert res.req16.proof == [f"App Name ({name}) starts with or contains a denied word"]


def test_bad_name_and_links():
    links = ['https://atlassian.com/connect-app']
    name = 'Atlassian Confluence Connect'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    res = analyzer.analyze()

    assert res.req16.passed is False
    assert res.req16.description == [BRANDING_ISSUE]
    assert res.req16.title == REQ_TITLES['16']
    assert res.req16.proof == [
        f"{links[0]} | Contains a denied word in the subdomain or primary domain",
        f"App Name ({name}) starts with or contains a denied word"
    ]


def test_good_app():
    links = ['https://google.com']
    name = 'Data Organizer for Confluence Connect'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    res = analyzer.analyze()

    assert res.req16.passed is True
    assert res.req16.description == [NO_ISSUES]
    assert res.req16.title == REQ_TITLES['16']
    assert res.req16.proof == []


def test_subdomain_exclusion():
    links = ['https://atlassian.myapp.com/confluence']
    name = 'Example App'
    reqs = Requirements()
    analyzer = BrandingAnalyzer(links, name, reqs)

    res = analyzer.analyze()

    assert res.req16.passed is True
    assert res.req16.description == [NO_ISSUES]
    assert res.req16.title == REQ_TITLES['16']
    assert res.req16.proof == []
