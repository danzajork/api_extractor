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

def extract_double_quoted_apis(text, prefix):

    regex = r'"(?<=(\"|\'|\`))' + prefix + r'\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))"'
    matches = re.finditer(regex, text, re.MULTILINE)

    return clean_matched_results(matches)

def extract_single_quoted_apis(text, prefix):

    regex = r"'(?<=(\"|\'|\`))" + prefix + r"\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))'"
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


def make_get_request(url):
    try:
        url = url.rstrip("/")
        response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
        length = len(response.content)
        
        result = {
            "status_code": response.status_code,
            "length": length,
            "url": url
        }

        return result
    except Exception as e:
        print(e)


def check_url(urls, num_threads = 20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(make_get_request, url): url for url in urls}
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(urls), unit=" urls"):
            sub_ns_sc = future_to_url[future]
            try:
                if future.result() is not None:
                    results.append(future.result())
            except Exception as e:
                print(f"{e}")
                raise
    return results


def scan(url, default_prefix, threads, output):
    
    response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
    text = response.text

    endpoints = []

    endpoints.extend(extract_single_quoted_apis(text, default_prefix))
    endpoints.extend(extract_double_quoted_apis(text, default_prefix))

    get_endpoints = build_get_urls(url, endpoints)

    results = check_url(get_endpoints, threads)

    for result in results:
        status_code = result["status_code"]
        length = result["length"]
        endpoint = result["url"]

        print(f"[*] {status_code} : {length} : {endpoint}")

def main():
    """
    Main program
    """
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="url to target")
    parser.add_argument("-p", "--prefix", dest="prefix", help="api prefix, default /api")
    parser.add_argument("-o", "--out", dest="output", help="file to output json")
    parser.add_argument("-t", "--threads", dest="threads", help="number of threads")
    
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        exit(1)

    thread_default = 40 
    if args.threads:
        thread_default = int(args.threads)

    default_prefix = r"\/api"
    if args.prefix:
        default_prefix = r"\/" + args.prefix.lstrip("/").rstrip("/")

    scan(args.url, default_prefix, thread_default, args.output)


if __name__ == "__main__":
    main()