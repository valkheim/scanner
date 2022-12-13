# Install && run

```
/scanner$ poetry install
/scanner$ poetry run scanner
 * Serving Flask app '__main__'

[...]
```

# Test release

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
