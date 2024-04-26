## Dependencies
- `bitarray`, `python-magic`, and `argparse` modules: `pip install bitarray python-magic argparse`
- `libmagic` package: `apt-get install libmagic-dev` on Ubuntu/Debian, `brew install libmagic` on OSX

## Usage
Please refer to the help message for options:
```
$ python redebug.py -h
usage: redebug.py [-h] [-n NUM] [-c NUM] [-v] patch_path source_path

positional arguments:
  patch_path            path to patch files (in unified diff format)
  source_path           path to source files

optional arguments:
  -h, --help            show this help message and exit
  -n NUM, --ngram NUM   use n-gram of NUM lines (default: 4)
  -c NUM, --context NUM
                        print NUM lines of context (default: 10)
  -v, --verbose         enable verbose mode (default: False)
```
