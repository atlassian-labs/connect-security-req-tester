from scans.descriptor_scan import DescriptorScan


def _scan_for(descriptor):
    scan = DescriptorScan.__new__(DescriptorScan)
    scan.descriptor = descriptor
    scan.base_url = descriptor['baseUrl']
    return scan


def test_fill_context_vars_replaces_each_placeholder_individually():
    scan = _scan_for({'baseUrl': 'https://example.com'})
    url = ('/atlassian/project/{project.key}/{project.id}/?canViewProject=true'
           '&project_key={project.key}&project_id={project.id}'
           '&canEditProject={condition.has_project_permission(permission=EDIT_ISSUES)}')

    assert scan._fill_context_vars(url) == (
        '/atlassian/project/test/test/?canViewProject=true'
        '&project_key=test&project_id=test&canEditProject=true'
    )


def test_fill_context_vars_replaces_multiple_condition_placeholders():
    scan = _scan_for({'baseUrl': 'https://example.com'})

    assert scan._fill_context_vars('/x?a={condition.one}&b={condition.two}') == '/x?a=true&b=true'


def test_fill_context_vars_leaves_static_urls_untouched():
    scan = _scan_for({'baseUrl': 'https://example.com'})

    assert scan._fill_context_vars('/static/path?foo=bar') == '/static/path?foo=bar'
    assert scan._fill_context_vars('/page/${issue.key}') == '/page/test'


def test_module_links_preserve_query_string():
    # Regression test for https://github.com/atlassian-labs/connect-security-req-tester/issues/71
    descriptor = {
        'baseUrl': 'https://example.com',
        'modules': {
            'jiraProjectPages': [
                {'url': '/atlassian/project/{project.key}/{project.id}/?canViewProject=true'
                        '&project_key={project.key}&project_id={project.id}'
                        '&canEditProject={condition.has_project_permission(permission=EDIT_ISSUES)}'}
            ]
        },
    }
    scan = _scan_for(descriptor)

    assert scan._get_module_links() == [
        'https://example.com/atlassian/project/test/test/?canViewProject=true'
        '&project_key=test&project_id=test&canEditProject=true'
    ]
