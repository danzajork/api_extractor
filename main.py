#!/usr/bin/python3
import json
import sys
import requests
import tldextract
from tqdm import tqdm
import concurrent.futures
from argparse import ArgumentParser
import re

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def clean_matched_results(matches):
    endpoints = []

    for match in matches:
        endpoint = match.group(0).lstrip('"')
        endpoint = endpoint.rstrip('"')
        endpoint = endpoint.lstrip("'")
        endpoint = endpoint.rstrip("'")

        endpoints.append(endpoint)

    # return unique results
    return list(set(endpoints))

def extract_double_quoted_apis(text):

    regex = r'"(?<=(\"|\'|\`))\/api\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))"'
    matches = re.finditer(regex, text, re.MULTILINE)

    return clean_matched_results(matches)

def extract_single_quoted_apis(text):

    regex = r"'(?<=(\"|\'|\`))\/api\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))'"
    matches = re.finditer(regex, text, re.MULTILINE)

    return clean_matched_results(matches)

def build_get_urls(url, endpoints):

    get_endpoints = []

    scheme = "http://"
    if url.startswith("https://"):
        scheme = "https://"

    extracted_result = tldextract.extract(url)
    full_domain = f"{extracted_result.subdomain}.{extracted_result.domain}.{extracted_result.suffix}"

    for endpoint in endpoints:
        api_endpoint = f"{scheme}{full_domain}{endpoint}"
        get_endpoints.append(api_endpoint)

    return get_endpoints


def scan(url, threads, output):
    
    response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
    text = response.text

    endpoints = []

    endpoints.extend(extract_single_quoted_apis(text))
    endpoints.extend(extract_double_quoted_apis(text))

    get_endpoints = build_get_urls(url, endpoints)

    for e in get_endpoints:
        response = requests.get(e, timeout=5, verify=False)
        length = len(response.content)
       
        result = {
            "status_code": response.status_code,
            "length": length,
            "url": e
        }

        print(f"[*] {response.status_code} : {length} : {e}")

def main():
    """
    Main program
    """
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="url to target")
    parser.add_argument("-o", "--out", dest="output", help="file to output json")
    parser.add_argument("-t", "--threads", dest="threads", help="number of threads")
    
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        exit(1)

    thread_default = 40 
    if args.threads:
        thread_default = int(args.threads)

    scan(args.url, thread_default, args.output)


if __name__ == "__main__":
    main()