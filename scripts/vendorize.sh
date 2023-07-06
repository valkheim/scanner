#!/bin/sh

echo "== Prepare build"

rm -rf dist

poetry install
poetry lock
poetry build

echo "== Vendorize dependencies"

poetry export -f requirements.txt --output dist/requirements.txt
poetry run pip download -r dist/requirements.txt -d dist/whl --no-cache-dir
# poetry run pip wheel -r dist/requirements.txt -w dist/whl --no-binary :all:

echo "== Vendorize dev-dependencies"

poetry export -f requirements.txt --output dist/dev-requirements.txt --only dev
poetry run pip download -r dist/dev-requirements.txt -d dist/dev-whl --no-cache-dir
