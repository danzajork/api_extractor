#!/usr/bin/python3
import concurrent.futures
import json
import re
import sys
from argparse import ArgumentParser
from urllib.parse import urljoin

import requests
import tldextract
import urllib3
from bs4 import BeautifulSoup
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_domain_from_url(url):
    extracted_result = tldextract.extract(url)
    if extracted_result.subdomain:
        full_domain = f"{extracted_result.subdomain}.{extracted_result.domain}.{extracted_result.suffix}"
    else:
        full_domain = f"{extracted_result.domain}.{extracted_result.suffix}"

    return full_domain

def external_js_extract(url):
    js_links = []

    scheme = "http://"
    if url.startswith("https://"):
        scheme = "https://"

    extracted_result = tldextract.extract(url)
    if extracted_result.subdomain:
        base_url = f"{scheme}{extracted_result.subdomain}.{extracted_result.domain}.{extracted_result.suffix}"
    else:
        base_url = f"{scheme}{extracted_result.domain}.{extracted_result.suffix}"

    request = requests.get(url,
                           verify=False, timeout=15, allow_redirects=False)

    html = request.text
    soup = BeautifulSoup(html, features="html.parser")

    has_base_href = False
    for href in soup.find_all("base",href=True):
        has_base_href = True
        base_url = urljoin(url, href.get("href"))

    for link in soup.find_all("script"):
        if link.get("src"):
            if has_base_href:
                extracted_url = urljoin(base_url, link.get("src"))
            else:
                extracted_url = urljoin(url, link.get("src"))
            js_links.append(extracted_url)

    return js_links


def clean_matched_results(matches):
    endpoints = []

    for match in matches:
        endpoint = match.group(0).lstrip('"')
        endpoint = endpoint.rstrip('"')
        endpoint = endpoint.lstrip("'")
        endpoint = endpoint.rstrip("'")
        endpoint = endpoint.lstrip("`")
        endpoint = endpoint.rstrip("`")

        endpoints.append(endpoint)

    return endpoints


def extract_quoted_apis(text, prefix):

    regex = r"(?<=(\"|\'|\`))" + prefix + \
        r"\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))"
    matches = re.finditer(regex, text, re.MULTILINE)

    return clean_matched_results(matches)


def build_get_urls(url, endpoints, api_prefix):

    get_endpoints = []

    scheme = "http://"
    if url.startswith("https://"):
        scheme = "https://"

    full_domain = get_domain_from_url(url)

    for endpoint in endpoints:
        if api_prefix:
            if not api_prefix.startswith("/"):
                api_prefix = "/" + api_prefix

            if endpoint.startswith("/"):
                api_prefix = api_prefix.rstrip("/")

            get_endpoints.append(f"{scheme}{full_domain}{api_prefix}{endpoint}")

        else:
            get_endpoints.append(urljoin(f"{scheme}{full_domain}", endpoint))

    return get_endpoints


def make_get_request(url):
    try:
        url = url.rstrip("/")
        response = requests.get(
            url, timeout=5, allow_redirects=False, verify=False)
        length = len(response.content)

        result = {
            "status_code": response.status_code,
            "length": length,
            "url": url
        }

        return result
    except Exception as e:
        print(e)


def check_url(urls, num_threads=20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(
            make_get_request, url): url for url in urls}
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(urls), unit=" urls"):
            sub_ns_sc = future_to_url[future]
            try:
                if future.result() is not None:
                    results.append(future.result())
            except Exception as e:
                print(f"{e}")
                raise
    return results


def content_request(url):
    try:
        url = url.rstrip("/")
        response = requests.get(
            url, timeout=5, allow_redirects=False, verify=False)

        return response.text
    except Exception as e:
        print(e)


def collect_url(urls, num_threads=20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(
            content_request, url): url for url in urls}
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(urls), unit=" urls"):
            sub_ns_sc = future_to_url[future]
            try:
                if future.result() is not None:
                    results.append(future.result())
            except Exception as e:
                print(f"{e}")
                raise
    return results


def match_domain(url, requested_url):

    full_domain = get_domain_from_url(url)
    requested_full_domain = get_domain_from_url(requested_url)

    if full_domain in requested_full_domain:
        return True

    return False


def scan(url, default_search_prefix, base_url, api_prefix, threads, output):

    response = requests.get(url, timeout=15, verify=False)

    # only follow redirects to same domain
    if match_domain(url, response.url) == False:
        print("[!] redirected off domain, scan stopped.")
        return
    else:
        print(f"[i] new base URL: {response.url}")
        url = response.url
    
    text = response.text

    endpoints = []

    endpoints.extend(extract_quoted_apis(text, default_search_prefix))

    js_links = external_js_extract(url)

    contents = collect_url(js_links, threads)
    for content in contents:
        endpoints.extend(extract_quoted_apis(content, default_search_prefix))

    # get unique results
    endpoints = list(set(endpoints))

    if base_url:
        get_endpoints = build_get_urls(base_url, endpoints, api_prefix)
    else:
        get_endpoints = build_get_urls(url, endpoints, api_prefix)

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
    parser.add_argument("-s", "--search-prefix", dest="search_prefix",
                        help="api search prefix, default /api, api, /rest, rest, /service, and service")
    parser.add_argument("-p", "--prefix", dest="prefix",
                        help="path prefix to prepend to API calls")
    parser.add_argument("-b", "--base", dest="base",
                        help="base URL for API calls")
    parser.add_argument("-o", "--out", dest="output",
                        help="file to output json")
    parser.add_argument("-t", "--threads", dest="threads",
                        help="number of threads")

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        exit(1)

    thread_default = 10
    if args.threads:
        thread_default = int(args.threads)

    default_search_prefix = r"(\/api|api|\/rest|rest|\/service|service)"
    if args.search_prefix:
        if args.search_prefix.startswith("/"):
            default_search_prefix = r"\/" + args.search_prefix.lstrip("/").rstrip("/")
        else:
            default_search_prefix = args.search_prefix

    print(f"[i] using API search prefix: {default_search_prefix}")

    scan(args.url, default_search_prefix, args.base, args.prefix, thread_default, args.output)


if __name__ == "__main__":
    main()
