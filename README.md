# Atlassian Connect - Security Requirements Test Suite

The purpose of this tool is help you scan your Atlassian Connect app for compliance against the [Atlassian Connect Security Requirements](https://developer.atlassian.com/platform/marketplace/security-requirements/) and potential security misconfigurations.

## Usage
This utility can be run as a python script or can be pulled/built from Docker and run as a containerized application. Choose the path that makes the most sense for your setup.

### Python Usage
`pipenv run python main.py url-to-atlassian-connect-json --force_scan=True/False --debug=True/False`

Example: `pipenv run python3 main.py https://example.com/atlassian-connect.json`

### Docker Usage
`docker build -t atlas-connect-sec-test .`
`docker run -v $(pwd)/out:/app/out atlas-connect-sec-test`

| Argument | Argument Description |
|----------|----------------------|
|--force_scan | Ignores cache for SSL/TLS validation scans and will make the scan run longer, **default: False** |
|--out_dir  | The directory to store the HTML Report from the scan, **default: ./out** |
|--debug | Turns on debug level logging exposing the network calls being performed, **default: False** |

## Useful Information
This tool assumes your connect app is reachable by the machine running this tool. If your connect app is not reachable, the tool will fail to produce any meaningful results. The following internet addresses are required to be accessible for this tool to work:
* Your connect app's `base_url`
* Qualys SSL Labs (https://ssllabs.com)

This tool will make network requests on from your computer. Please ensure this is allowed from your organization if running this from a work network.

Additional information about the Atlassian Connect Security Requirements can be found at: [https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/](https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/)

## Issues/Feedback?
TBD
