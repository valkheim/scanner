#!/bin/sh

printf "algorithm,value\n"
printf "%s\n" "md5sum,$(md5sum $1 | cut -d ' ' -f1)"
printf "%s\n" "sha1sum,$(sha1sum $1 | cut -d ' ' -f1)"
printf "%s\n" "sha256sum,$(sha256sum $1 | cut -d ' ' -f1)"
printf "%s\n" "sha512sum,$(sha512sum $1 | cut -d ' ' -f1)"
