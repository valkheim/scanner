#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
CLASSIFIER_PATH="$SCRIPTPATH/../../../cache/random_forest.joblib"

poetry run scanner classify --classifier_path "$CLASSIFIER_PATH" --test_file "$1"
