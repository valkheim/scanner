statically built from

https://github.com/ssdeep-project/ssdeep/releases/tag/release-2.14.1
ssdeep-2.14.1.tar.gz

using

./configure CFLAGS="-static"
make LDFLAGS="-all-static"
