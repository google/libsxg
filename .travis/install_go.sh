#!/bin/sh

DEPS_DIR="${TRAVIS_BUILD_DIR}/go1.13"
mkdir ${DEPS_DIR} && pushd ${DEPS_DIR}
GO="go1.13.9.linux-amd64"
GO_TAR="${GO}.tar.gz"
travis_retry wget --no-check-certificate https://dl.google.com/go/${GO_TAR}
echo "72a391f8b82836adfd4be8d9d554ffb1 ${GO_TAR}" > go_md5.txt
md5sum -c go_md5.txt
tar -xf ${GO_TAR}
export GOROOT=${DEPS_DIR}/go
export PATH=$GOROOT/bin:$PATH
popd
