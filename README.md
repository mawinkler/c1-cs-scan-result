# Smart Check Scan-Report

- [Smart Check Scan-Report](#smart-check-scan-report)
  - [Container Variant](#container-variant)
  - [Support](#support)
  - [Contribute](#contribute)

Reports discovered vulnerabilities by Smart Check. If multiple scans have been requested for the given image, the latest scan is evaluated.

First, create your config.yml by

```sh
cp config.yml.sample config.yml
```

and define the values.

Sample:

```yaml
# Your Smart Check installation
# Can be overwritten by command line arguments
dssc:
  service: "<smart check url:port>"
  username: "<smart check username>"
  password: "<smart check password>"

# The default scan result to generate
# Can be overwritten by command line arguments
repository:
  name: "<repository name>"
  image_tag: "<image tag, e.g. latest>"

# If you want to limit discovered vulnerabilities to specific criticalities
criticalities:
  - defcon1
  - critical
  - high
  - medium
```

Ensure to have the dependencies satisfied

```sh
pip install -r requirements.txt
```

Run the reporter by

```sh
python3 scan-result.py -n nginx -t latest | jq .
```

Optional command line arguments:

```sh
"-n", "--name", type=str, help="image name"
"-t", "--image_tag", type=str, help="image tag"
"-s", "--service", type=str, help="image security url"
"-u", "--username", type=str, help="username"
"-p", "--password", type=str, help="password"
```

## Container Variant

Build

```sh
docker build -t scan-result .
```

Run

```sh
docker run scan-result \
  --name "${TARGET_IMAGE}" \
  --image_tag "${TARGET_IMAGE_TAG}" \
  --service "${DSSC_SERVICE}" \
  --username "${DSSC_USERNAME}" \
  --password "${DSSC_PASSWORD}"
```

Example:

```sh
# With Smart Check parametes set in the config.yaml
docker run scan-result:latest --name nginx --image_tag latest | \
  jq .

# Define a different Smart Check
docker run scan-result:latest --name nginx --image_tag latest \
  --service 192.168.1.121:8443 --username admin --password trendmicro | \
  jq .
```

```json
{
  "id": "4462a186-e5e6-4a5a-b05b-a4a20de94566",
  "href": "/api/scans/4462a186-e5e6-4a5a-b05b-a4a20de94566",
  "requested": "2022-06-29T05:05:57Z",
  "status": "completed-with-findings",
  "database_time": "2022-05-11T04:26:36Z",
  "findings": {
    "vulnerabilitites": {
      "defcon1": 0,
      "critical": 8,
      "high": 30,
      "medium": 34
    }
  },
  "report": {
    "vulnerabilities": [
      ...
      {
        "id": "CVE-2022-2068",
        "name": "openssl",
        "version": "1.1.1n-0+deb11u2",
        "fixed_by": "1.1.1n-0+deb11u3",
        "advisory": "https://security-tracker.debian.org/tracker/CVE-2022-2068",
        "rating": "unknown",
        "description": "In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).",
        "attackvector": "local",
        "source": {
          "name": "debian:11"
        }
      },
      ...
```

## Support

This is an Open Source community project. Project contributors may be able to help, depending on their time and availability. Please be specific about what you're trying to do, your system, and steps to reproduce the problem.

For bug reports or feature requests, please [open an issue](../../issues). You are welcome to [contribute](#contribute).

Official support from Trend Micro is not available. Individual contributors may be Trend Micro employees, but are not official support.

## Contribute

I do accept contributions from the community. To submit changes:

1. Fork this repository.
1. Create a new feature branch.
1. Make your changes.
1. Submit a pull request with an explanation of your changes or additions.

I will review and work with you to release the code.
