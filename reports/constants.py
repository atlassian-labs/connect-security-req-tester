REQ_TITLES = {
    '1': 'Authentication of Application Resources',
    '1.2': 'Authorization of Application Resources',
    '1.4': 'Signed Install Authentication',
    '2': 'Authentication and Authorization of Stored Data',
    '3': 'Transport Layer Security Validation',
    '3.0': 'HSTS Validation',
    '5': 'Secret Handling',
    '6.2': 'Validity of Domain Registration and TLS Certificates',
    '6.3': 'Domain and Subdomain Takeover',
    '7.3': 'Cache Control',
    '7.4': 'Session Cookie Configuration',
    '7.2': 'Referrer Policy',
    '8.1': 'URL Tampering',
    '9': 'Use of External Components',
    '10': 'Collection of Atlassian Credentials',
    '11': 'Security SLAs',
    '16': 'App Name and Domain Branding Violations'
}

NO_ISSUES = 'We did not detect any issues for this check.'
NO_PROOF = 'Check passed, no proof available. Please refer to Appendix for raw scan output.'
NO_SCAN_PROOF = 'We do not have a scan for this issue. Please refer to the description for more information.'
NO_AUTH_PROOF = 'Check passed, since there is no authentication method.'
VALID_AUTH_PROOF = 'Check passed, since we cannot access any of the links.'
VALID_AUTHZ_PROOF = 'Check passed, since we cannot access any of the links using user JWT token.'
TLS_PROTOCOLS = 'Your app supports a SSL/TLS protocol(s) that are below TLS 1.2'
HSTS_MISSING = 'We did not detect an HSTS Header on one or all hosts.'
CERT_NOT_VALID = 'Your app has an invalid SSL/TLS certificate.'
MISSING_CACHE_HEADERS = 'We did not detect the correct Cache-Control header on one or more endpoints.'
MISSING_REF_HEADERS = 'We did not detect the correct Referrer-Policy header on one or more endpoints.'
MISSING_ATTRS_SESSION_COOKIE = 'We did not detect the "Secure" or "HttpOnly" attribute on one or more session cookies set by your app.'
MISSING_AUTHN = 'One or more endpoints returned a <400 status code without authentication information. This may indicate that your app is not performing authentication and authorization checks.'
BRANDING_ISSUE = 'Your app name or domain contained words that are not allowed. Please refer to our branding guidelines at: https://developer.atlassian.com/platform/marketplace/atlassian-brand-guidelines-for-marketplace-vendors/#app-names for more information.'
MISSING_SIGNED_INSTALL_AUTHN = 'One or more lifecycle endpoints returned a <400 status code with an invalid JWT token. This may indicate that your app is not performing authentication checks on lifecycle endpoints.'
MISSING_AUTHZ = 'One or more endpoints returned a <400 status code with a user JWT token while accessing admin restricted resources. This may indicate that your app is not performing authorization check on admin endpoints.'

REQ_RECOMMENDATION = {
    '1': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#authentication-and-authorization-of-application-resources for more information.',
    '1.2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#authentication-and-authorization-of-application-resources for more information.',
    '1.4': 'Refer to https://community.developer.atlassian.com/t/action-required-atlassian-connect-installation-lifecycle-security-improvements/49046',
    '2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#authentication-and-authorization-of-stored-data for more information.',
    '3': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#transport-layer-security:~:text=requirement.-,Transport%20layer%20security for more information.',
    '3.0': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#transport-layer-security:~:text=requirement.-,Transport%20layer%20security for more information.',
    '5': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#secret-handling for more information.',
    '6.2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#validity-of-domain-registration---tls-certificates for more information.',
    '6.3': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#domain-and-subdomain-takeover for more information.',
    '7.2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#referrer-policy for more information.',
    '7.3': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#cache-control for more information.',
    '7.4': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#session-cookie-configuration for more information.',
    '8.1': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#url-tampering for more information.',
    '9': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#use-of-external-components for more information.',
    '10': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#collection-of-atlassian-credentials for more information.',
    '11': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#security-slas for more information.',
    '16': 'Refer to https://developer.atlassian.com/platform/marketplace/atlassian-brand-guidelines-for-marketplace-vendors/#app-names for more information.'
}
