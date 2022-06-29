#!/usr/bin/env python3

import ssl

ssl._create_default_https_context = ssl._create_unverified_context
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import json
import os
import pprint
import re
import time

import requests
import yaml


def dssc_auth(cfg):
    """Authenticates to Smart Check"""

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/sessions"
    data = {
        "user": {"userid": cfg["dssc"]["username"], "password": cfg["dssc"]["password"]}
    }

    post_header = {
        "Content-type": "application/json",
        "x-argus-api-version": "2017-10-16",
    }
    response = requests.post(
        url, data=json.dumps(data), headers=post_header, verify=False
    )
    response = response.json()

    if "message" in response:
        print("Authentication response: " + response["message"])
        if response["message"] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or", "SmartCheck not available")

    return response["token"]


def dssc_latest_scan(cfg, token):
    """Queries the latest scan of the given image"""

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/scans?limit=500"
    data = {}
    post_header = {"Content-type": content_type, "authorization": "Bearer " + token}
    response = requests.get(
        url, data=json.dumps(data), headers=post_header, verify=False
    ).json()

    scan_id = ""
    scan_time = "2000-01-1T00:00:00Z"
    for scan in response.get("scans", {}):
        if (
            scan.get("source", {}).get("repository", "") == cfg["repository"]["name"]
        ) and (
            scan.get("source", {}).get("tag", "") == str(cfg["repository"]["image_tag"])
        ):
            if scan["details"]["updated"] > scan_time:
                scan_time = scan["details"]["updated"]
                scan_id = scan["id"]

    if scan_id == "":
        raise ValueError("Scan not found")

    return scan_id


def dssc_scan(cfg, scan_id, token):
    """Queries the scan of the given image from Smart Check"""

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/scans/" + scan_id
    data = {}
    post_header = {"Content-type": content_type, "authorization": "Bearer " + token}
    response = requests.get(
        url, data=json.dumps(data), headers=post_header, verify=False
    ).json()

    # query vulnerability database update time
    scanners_list = response["findings"].get("scanners", {})
    database_time = scanners_list.get("vulnerabilities", {}).get("updated", {})
    scan_requested_time = response["details"].get("requested", {})
    href = response.get("href", {})
    status = response.get("status", {})

    # iterate layers
    result_list = response["details"].get("results", {})

    vulns = {}
    vul_count_defcon1 = 0
    vul_count_critical = 0
    vul_count_high = 0
    vul_count_medium = 0

    for result in result_list:
        if "vulnerabilities" in result:

            url = (
                "https://"
                + cfg["dssc"]["service"]
                + result.get("vulnerabilities", {})
                + "?limit=10000"
            )
            data = {}
            post_header = {
                "Content-type": content_type,
                "authorization": "Bearer " + token,
            }
            response_layer = requests.get(
                url, data=json.dumps(data), headers=post_header, verify=False
            ).json()

            for item in response_layer.get("vulnerabilities", {}):
                affected = item.get("name", {})
                vulnerable_name = item.get("name", {})
                vulnerable_version = item.get("version", {})
                namespace_name = item.get("namespaceName", {})
                for vul in item.get("vulnerabilities", {}):
                    vul_cve = vul.get("name", {})

                    vul_severity = vul.get("severity", {}).lower()
                    if (vul_severity not in cfg["criticalities"]) and (
                        vul_severity != "unknown"
                    ):
                        continue

                    if vul_severity == "defcon1":
                        vul_count_defcon1 += 1
                    if vul_severity == "critical":
                        vul_count_critical += 1
                    if vul_severity == "high":
                        vul_count_high += 1
                    if vul_severity == "medium":
                        vul_count_medium += 1

                    vul_av2 = (
                        vul.get("metadata", {})
                        .get("NVD", {})
                        .get("CVSSv2", {})
                        .get("Vectors", {})
                    )
                    vul_av3 = (
                        vul.get("metadata", {})
                        .get("NVD", {})
                        .get("CVSSv3", {})
                        .get("Vectors", {})
                    )
                    if (str(vul_av2).find("AV:N") >= 0) or (
                        str(vul_av3).find("AV:N") >= 0
                    ):
                        vul_av = "network"
                    else:
                        vul_av = "local"

                    vulns[str(vul_cve)] = {
                        "name": str(vulnerable_name),
                        "version": str(vulnerable_version),
                        "severity": str(vul_severity),
                        "namespace_name": str(namespace_name),
                        "attackvector": str(vul_av),
                        "description": vul.get("description", "n/a"),
                        "link": vul.get("link", "n/a"),
                        "fixed_by": vul.get("fixedBy", "n/a"),
                    }

    scan_info = {
        "id": scan_id,
        "href": href,
        "requested": scan_requested_time,
        "status": status,
        "database_time": database_time,
        "findings": {
            "vulnerabilitites": {
                "defcon1": vul_count_defcon1,
                "critical": vul_count_critical,
                "high": vul_count_high,
                "medium": vul_count_medium,
            }
        }
    }

    return {"scan_info": scan_info, "vulns": vulns}


def dssc_report(cfg):
    """Queries the scan report of the given image from Smart Check"""

    token = dssc_auth(cfg)
    scan_id = dssc_latest_scan(cfg, token)
    scan_info = dssc_scan(cfg, scan_id, token)

    return scan_info


def create_vulns_list(dssc_vulns):
    """Creates a dictionary for the discovered vulnerabilities"""

    vulnerabilities_list = []

    for vul in {k: dssc_vulns[k] for k in sorted(dssc_vulns, reverse=True)}:

        vulnerabililty = {
            "id": vul,
            "name": str(dssc_vulns.get(vul, {}).get("name", {})),
            "version": str(dssc_vulns.get(vul, {}).get("version", {})),
            "fixed_by": str(dssc_vulns.get(vul, {}).get("fixed_by", {})),
            "advisory": str(dssc_vulns.get(vul, {}).get("link", {})),
            "rating": str(dssc_vulns.get(vul, {}).get("severity", {})),
            "description": str(dssc_vulns.get(vul, {}).get("description", {})),
            "attackvector": str(dssc_vulns.get(vul, {}).get("attackvector", {})),
            "source": {
                "name": str(dssc_vulns.get(vul, {}).get("namespace_name", {}))
            }
        }
        vulnerabilities_list.append(vulnerabililty)

    report_vulnerabilities = {
        "vulnerabilities": vulnerabilities_list
    }

    return report_vulnerabilities


def main():
    """main"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", type=str, help="image name")
    parser.add_argument("-t", "--image_tag", type=str, help="image tag")
    parser.add_argument("-s", "--service", type=str, help="image security url")
    parser.add_argument("-u", "--username", type=str, help="username")
    parser.add_argument("-p", "--password", type=str, help="password")
    parser.add_argument("-O", "--stdout", action="store_true", help="output to stdout")
    args = parser.parse_args()

    config_path = "."

    with open(config_path + "/config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    # Dirty override configuraton with command line parameters
    if args.name != None:
        cfg["repository"]["name"] = args.name
    if args.image_tag != None:
        cfg["repository"]["image_tag"] = args.image_tag
    if args.service != None:
        cfg["dssc"]["service"] = args.service
    if args.username != None:
        cfg["dssc"]["username"] = args.username
    if args.password != None:
        cfg["dssc"]["password"] = args.password

    # Query Report
    results = dssc_report(cfg)
    scan_info = results.get("scan_info", {})
    dssc_vulns = create_vulns_list(results.get("vulns", {}))

    scan_info['report'] = dssc_vulns
    print(json.dumps(scan_info))

    exit(0)


if __name__ == "__main__":
    main()
