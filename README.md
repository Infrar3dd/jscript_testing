# jscript_testing
INT-9 | Scripts to test and detect jscript malware samples + traces

### test.py usage

It needs poc_emulator_jscript server wirking on http://127.0.0.1:8080

Directory /samples with jscript malware samples with .jse, .js and .txt extension

### detect.py usage

```bash
python3 detect.py --help
usage: detect.py [-h] [--copy DIR] [--dry-run] paths [paths ...]

positional arguments:
  paths       trace/report files or directories

options:
  -h, --help  show this help message and exit
  --copy DIR  copy renamed files into DIR instead of renaming
  --dry-run   print suggested names, touch nothing

```

### /results - directory with traces