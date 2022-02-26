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
usage: main.py [-h] [-u URL] [-p PREFIX] [-o OUTPUT] [-t THREADS]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url to target
  -p PREFIX, --prefix PREFIX
                        api prefix, default /api
  -o OUTPUT, --out OUTPUT
                        file to output json
  -t THREADS, --threads THREADS
                        number of threads
```
