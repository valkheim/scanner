#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
BINPATH="$SCRIPTPATH/_bin"

"$BINPATH/manalyze" --pe "$1" # --plugins all
