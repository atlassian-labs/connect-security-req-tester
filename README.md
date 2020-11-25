# Connect Security Requirements Tester (CSRT)

![CSRT Tests](https://github.com/atlassian-labs/connect-security-req-tester/workflows/CSRT%20Linting%20and%20Testing/badge.svg)

The purpose of this tool is help you scan your Atlassian Connect app for compliance against the [Atlassian Connect Security Requirements](https://developer.atlassian.com/platform/marketplace/security-requirements/) and potential security misconfigurations.

## Usage
This utility can be run as a python script or can be built as a Docker container. Choose the path that makes the most sense for your setup.

### Python Usage

Using CSRT with Python requires [pipenv](https://pipenv.pypa.io) to be installed.

`pipenv run python main.py url-to-atlassian-connect-json --debug=True/False --out_dir=./out --skip_branding=True/False`

Example: `pipenv run python3 main.py https://example.com/atlassian-connect.json`

### Docker Usage
`docker build -t atlas-connect-sec-test .`

`docker run -v $(pwd)/out:/app/out atlas-connect-sec-test <url of descriptor>`

### Arguments
| Argument | Argument Description |
|----------|----------------------|
|--skip_branding    | Whether or not to skip branding checks, **default: False**                                        |
|--out_dir          | The output directory where results are stored, **default: ./out**                                 |
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

Tests may take a few minutes to run as we rely on the Qualys API to return results back to us to confirm functionality.

## Issues / Feedback?
Found a bug or have an idea for an improvement? Create an issue via the [issue tracker](https://github.com/atlassian-labs/connect-security-req-tester/issues).
