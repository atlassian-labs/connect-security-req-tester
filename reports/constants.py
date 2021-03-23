REQ_TITLES = {
    '1.1': 'Transport Layer Security Validation',
    '1.2': 'HSTS Validation',
    '2': 'Cache Control',
    '3': 'Validity of Domain Registration and TLS Certificates',
    '4': 'Domain and Subdomain Takeover',
    '5': 'Authentication and Authorization of Application Resources',
    '6': 'Authentication and Authorization of Stored Data',
    '7': 'Secure Handling of the "sharedSecret"',
    '8': 'Secret Handling',
    '9': 'JWT Validation',
    '10': 'Collection of Atlassian Credentials',
    '11': 'Session Cookie Configuration',
    '12': 'Referrer Policy',
    '13': 'URL Tampering',
    '14': 'Use of External Components',
    '15': 'Security SLAs',
    '16': 'App Name and Domain Branding Violations'
}

NO_ISSUES = 'We did not detect any issues for this check.'
NO_PROOF = 'Check passed, no proof available. Please refer to Appendix for raw scan output.'
NO_SCAN_PROOF = 'We do not have a scan for this issue. Please refer to the description for more information.'
TLS_PROTOCOLS = 'Your app supports a SSL/TLS protocol(s) that are below TLS 1.2'
HSTS_MISSING = 'We did not detect an HSTS Header on one or all hosts.'
CERT_NOT_VALID = 'Your app has an invalid SSL/TLS certificate.'
MISSING_CACHE_HEADERS = 'We did not detect the correct Cache-Control header on one or more endpoints.'
MISSING_REF_HEADERS = 'We did not detect the correct Referrer-Policy header on one or more endpoints.'
MISSING_ATTRS_SESSION_COOKIE = 'We did not detect the "Secure" or "HttpOnly" attribute on one or more session cookies set by your app.'
MISSING_AUTHN_AUTHZ = 'One or more endpoints returned a <400 status code without authentication information. This may indicate that your app is not performing authentication and authorization checks.'
BRANDING_ISSUE = 'Your app name or domain contained words that are not allowed. Please refer to our branding guidelines at: https://developer.atlassian.com/platform/marketplace/atlassian-brand-guidelines-for-marketplace-vendors/#app-names for more information.'

REQ_RECOMMENDATION = {
    '1.1': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#transport-layer-security:~:text=requirement.-,Transport%20layer%20security for more information.',
    '1.2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#transport-layer-security:~:text=requirement.-,Transport%20layer%20security for more information.',
    '2': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#cache-control for more information.',
    '3': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#validity-of-domain-registration---tls-certificates for more information.',
    '4': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#domain-and-subdomain-takeover for more information.',
    '5': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#authentication-and-authorization-of-application-resources for more information.',
    '6': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#authentication-and-authorization-of-stored-data for more information.',
    '7': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#secure-handling-of-the-sharedsecret for more information.',
    '8': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#secret-handling for more information.',
    '9': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#jwt-validation for more information.',
    '10': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#collection-of-atlassian-credentials for more information.',
    '11': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#session-cookie-configuration for more information.',
    '12': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#referrer-policy for more information.',
    '13': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#url-tampering for more information.',
    '14': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#use-of-external-components for more information.',
    '15': 'Refer to https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/#security-slas for more information.',
    '16': 'Refer to https://developer.atlassian.com/platform/marketplace/atlassian-brand-guidelines-for-marketplace-vendors/#app-names for more information.'
}
