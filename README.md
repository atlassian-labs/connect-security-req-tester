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

`pipenv run python main.py url-to-atlassian-connect-json --debug=True/False --out_dir=./out --skip_branding=True/False --timeout=30 --json_logging=True/False`

### Docker Usage

Ensure you have [Docker setup for your respective operating system](https://docs.docker.com/get-docker/).

Run the following from the project root:

1. `docker build -t connect-security-req-tester .`
2. `docker run -v $(pwd)/out:/app/out connect-security-req-tester <url of descriptor>`

### Arguments
| Argument | Argument Description |
|----------|----------------------|
|--timeout          | Defines how long CSRT will wait on web requests before timing out, **default: 30 seconds**        |
|--skip_branding    | Whether or not to skip branding checks, **default: False**                                        |
|--out_dir          | The output directory where results are stored, **default: ./out**                                 |
|--json_logging     | Whether or not to log output in a JSON format, **default: False**                                 |
|--debug            | Sets logging to DEBUG for more verbose logging, **default: False**                                |

## Useful Information
This tool assumes your connect app is reachable by the machine running this tool. If your connect app is not reachable, the tool will fail to produce any meaningful results. The following internet addresses are required to be accessible for this tool to work:
* Your connect app's descriptor URL
* All URLs referenced inside your connect app descriptor

This tool will make network requests on from your computer. Please ensure this is allowed from your organization if running this from a monitored network.

Additional information about the Atlassian Connect Security Requirements can be found at: [https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/](https://developer.atlassian.com/platform/marketplace/security-requirements-more-info/)

## Testing
To run the entire test suite:

* `pipenv run lint` -- Runs flake8 with the project settings
* `pipenv run test` -- Runs pytest with the project settings

## Issues / Feedback?
Found a bug or have an idea for an improvement? Create an issue via the [issue tracker](https://github.com/atlassian-labs/connect-security-req-tester/issues).
