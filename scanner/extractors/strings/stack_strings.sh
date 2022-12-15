#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
BINPATH="$SCRIPTPATH/_bin"

"$BINPATH/floss" --quiet --only "stack" -- "$1" 2> /dev/null | tr -s '\n'
