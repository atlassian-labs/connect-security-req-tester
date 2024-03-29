# Connect Security Requirements Tester (CSRT)

![CSRT Tests](https://github.com/atlassian-labs/connect-security-req-tester/workflows/CSRT%20Linting%20and%20Testing/badge.svg)

The purpose of this tool is help you scan your Atlassian Connect app for compliance against the [Atlassian Connect Security Requirements](https://developer.atlassian.com/platform/marketplace/security-requirements/) and potential security misconfigurations.

## Usage
This utility can be run as a python script or can be built as a Docker container.

_If you are unsure what option makes the most sense for you, follow the Docker setup instructions._

### Python Usage

CSRT uses [Python 3.9](https://www.python.org/downloads/release/python-390/) and [Pipenv](https://github.com/pypa/pipenv). Both are required to successfully run the tool.

Common usage:

`pipenv run python3 main.py https://example.com/atlassian-connect.json`

CSRT with all arguments:

`pipenv run python main.py url-to-atlassian-connect-json --debug=True/False --out_dir=./out --skip_branding=True/False --timeout=30 --json_logging=True/False --user_jwt=<jwt_token> --authz_only=True/False`

### Docker Usage

Ensure you have [Docker setup for your respective operating system](https://docs.docker.com/get-docker/).

Run the following from the project root:

1. `docker build -t connect-security-req-tester .`
2. `docker run -v $(pwd)/out:/app/out connect-security-req-tester <url of descriptor>`

### Arguments
| Argument | Argument Description                                                                       |
|----------|--------------------------------------------------------------------------------------------|
|--timeout          | Defines how long CSRT will wait on web requests before timing out, **default: 30 seconds** |
|--skip_branding    | Whether or not to skip branding checks, **default: True**                                  |
|--out_dir          | The output directory where results are stored, **default: ./out**                          |
|--json_logging     | Whether or not to log output in a JSON format, **default: False**                          |
|--debug            | Sets logging to DEBUG for more verbose logging, **default: False**                         |
|--user_jwt         | A **user** JWT token to use for authorization check on admin endpoints, **default: None**  |
|--authz_only       | Only run and report authorization check, **default: False**                                |
### Environment Variables
| Variable | Description |
|----------|-------------|
| OUTBOUND_PROXY | If defined, route all requests through this proxy server (eg. `OUTBOUND_PROXY=http://proxy.example.com:8080`)

## Useful Information
This tool assumes your connect app is reachable by the machine running this tool. If your connect app is not reachable, the tool will fail to produce any meaningful results. The following internet addresses are required to be accessible for this tool to work:
* Your connect app's descriptor URL
* All URLs referenced inside your connect app descriptor

This tool will make network requests on from your computer. Please ensure this is allowed from your organization if running this from a monitored network.

**Authorization Check**:
* This tool also runs authorization check on admin endpoints to report any authorization bypass issues. If your app uses admin modules, and they need to be authenticated to access admin endpoints, you can pass a user JWT token via the `--user_jwt` argument. This will allow the tool to make requests to admin endpoints using user authentication information and test for authorization bypass issues. If you do not pass a user JWT token, the tool will skip authorization checks on admin endpoints.
* You can generate a user JWT token for testing by following the instructions at: [https://developer.atlassian.com/cloud/jira/platform/understanding-jwt/](https://developer.atlassian.com/cloud/jira/platform/understanding-jwt/) and use a shared secret received on your test instance for signing or capture a context token by entering `AP.context.getToken(console.log)` in the browser’s dev console when you load the app in Jira/Confluence.
* Additionally, if you only want to run Authorization check and not the entire suite of checks in this tool, you can pass the `--authz_only` argument.

**Tips**: 
* Use a proxy by setting `OUTBOUND_PROXY` to your organization's proxy server if your app needs to be accessed via a proxy server.

Additional information about the Atlassian Connect Security Requirements can be found at: [https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/](https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/)

## Testing
To run the entire test suite:

* `pipenv run lint` -- Runs flake8 with the project settings
* `pipenv run test` -- Runs pytest with the project settings

## Issues / Feedback?
Found a bug or have an idea for an improvement? Create an issue via the [issue tracker](https://github.com/atlassian-labs/connect-security-req-tester/issues).
