# Scanner

This is a PE file static analysis engine.

## Install

This is a poetry-managed python project.

```
/scanner$ poetry install
/scanner$ poetry run scanner gui
 * Serving Flask app '__main__'

[...]
```

For an offline install, you must first prepare the required packages (`dist` folder) using the `/scripts/vendorize.sh` script
and then run the following:

```
/downloads$ cd $(mktemp -d)
/tmp/tmp.6X4MSgVWhF$ python3.8 -m venv ./.env
/tmp/tmp.6X4MSgVWhF$ cp -r /downloads/dist/ .
/tmp/tmp.6X4MSgVWhF$ . ./.env/bin/activate
/tmp/tmp.6X4MSgVWhF$ pip install -r dist/requirements.txt --no-index --find-links dist/whl/
/tmp/tmp.6X4MSgVWhF$ pip install -r dist/dev-requirements.txt --no-index --find-links dist/dev-whl/
/tmp/tmp.6X4MSgVWhF$ pip install dist/scanner-0.2.1-py3-none-any.whl
/tmp/tmp.6X4MSgVWhF$ python3.8 -m scanner gui
```

## Test release

```
/scanner$ poetry build
Building scanner (0.1.0)
  - Building sdist
  - Built scanner-0.1.0.tar.gz
  - Building wheel
  - Built scanner-0.1.0-py3-none-any.whl
/scanner$ mkdir -p /tmp/test-scanner ; cd $_
/tmp/test-scanner$ python3 -m venv .venv
/tmp/test-scanner$ . ./venv/bin/activate
(.venv) /tmp/test-scanner$ pip install /scanner/dist/scanner-0.1.0-py3-none-any.whl
(.venv) /tmp/test-scanner$ python -m scanner
 * Serving Flask app '__main__'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 119-810-875
```

## GUI and CLI modes

You can use either the **gui** or the **cli** mode:

```console
/scanner$ poetry run scanner cli --help
usage: scanner cli [-h] [--file FILE] [--dir DIR] [--hash HASH] [--last]

The scanner command line mode

optional arguments:
  -h, --help   show this help message and exit
  --file FILE  Scan a file by path
  --dir DIR    Scan a directory by path
  --hash HASH  Retrieve scan results by hash
  --last       Retrieve the last analyzed files
```

```console
/scanner$ poetry run scanner gui --help
usage: scanner gui [-h]

The scanner GUI mode

optional arguments:
  -h, --help  show this help message and exit
```
