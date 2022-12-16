#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
BINPATH="$SCRIPTPATH/_bin"

"$BINPATH/floss" --quiet --only "tight" -- "$1" 2> /dev/null | sed '/^$/d'
