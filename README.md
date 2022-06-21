# Smart Check Scan-Report

- [Smart Check Scan-Report](#smart-check-scan-report)
  - [Container Variant - TODO](#container-variant---todo)
  - [Support](#support)
  - [Contribute](#contribute)

Reports discovered vulnerabilities by Cloud One Image Security. If multiple scans have been requested for the given image, the latest scan is evaluated.

First, create your config.yml by

```sh
cp config.yml.sample config.yml
```

and define the values.
Sample:

```yaml
dssc:
  service: "<smart check url:port>"
  username: "<smart check username>"
  password: "<smart check password>"

repository:
  name: "<repository name>"
  image_tag: "<image tag, e.g. latest>"

criticalities:
  - defcon1
  - critical
  - high
  - medium
```

Run the reporter by

```sh
python3 scan-result.py -n nginx -t latest | jq .
```

Optional command line arguments:

```sh
"-c", "--config_path", type=str, help="path to config.yml"
"-n", "--name", type=str, help="image name"
"-t", "--image_tag", type=str, help="image tag"
"-o", "--out_path", type=str, help="output directory"
"-s", "--service", type=str, help="image security url"
"-u", "--username", type=str, help="username"
"-p", "--password", type=str, help="password"
"-O", "--stdout", action='store_true', help="output to stdout"
```

## Container Variant - TODO

Build

```sh
docker build -t scan-result .
```

Run

```sh
docker run scan-result -O \
  --config_path "/usr/src/app" \
  --name "${TARGET_IMAGE}" \
  --image_tag "${TARGET_IMAGE_TAG}" \
  --out_path "." \
  --service "${DSSC_SERVICE}" \
  --username "${DSSC_USERNAME}" \
  --password "${DSSC_PASSWORD}"
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
