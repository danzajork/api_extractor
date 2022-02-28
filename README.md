# api_extractor
A tool to extract and call API endpoints from JavaScript.

Supports terminal and JSON output to integrate with other tools.

## api_extractor

### Requirements
```sh
Python 3
pip
```

### Installing Python Requirements
```sh
pip install -r requirements.txt
```

### Usage information

```console
% python3 main.py                                           
usage: main.py [-h] [-u URL] [-s SEARCH_PREFIX] [-p PREFIX] [-o OUTPUT] [-t THREADS]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url to target
  -s SEARCH_PREFIX, --search-prefix SEARCH_PREFIX
                        api search prefix, default /api, api, /rest, rest, /service, and service
  -p PREFIX, --prefix PREFIX
                        path prefix to prepend to API calls
  -o OUTPUT, --out OUTPUT
                        file to output json
  -t THREADS, --threads THREADS
                        number of threads

```
