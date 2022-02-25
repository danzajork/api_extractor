#!/usr/bin/python3
import json
import sys
import os
import concurrent.futures
import requests
from tqdm import tqdm
from argparse import ArgumentParser
import re



import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan(url, threads, output):
    
    response = requests.get(url, timeout=5, allow_redirects=False, verify=False)

    pattern = re.compile(r"'(?<=(\"|\'|\`))\/api\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))'")
    matches = pattern.match(response.text)

    for match in matches:
        print(match)


def main():
    """
    Main program
    """
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="url to target")
    parser.add_argument("-w", "--word-list", dest="word_list", help="custom word list")
    parser.add_argument("-t", "--threads", dest="threads", help="number of threads")
    parser.add_argument("-o", "--out", dest="output", help="file to output json")
    
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