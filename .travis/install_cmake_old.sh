#!/bin/sh

DEPS_DIR="${TRAVIS_BUILD_DIR}/deps"
mkdir ${DEPS_DIR} && pushd ${DEPS_DIR}
CMAKE="cmake-3.1.0-Linux-x86_64"
CMAKE_TAR="${CMAKE}.tar.gz"
travis_retry wget --no-check-certificate "https://github.com/Kitware/CMake/releases/download/v3.1.0/${CMAKE_TAR}"
echo "9fb313d98eac5eedc654a3164d33becd ${CMAKE_TAR}" > cmake_md5.txt
md5sum -c cmake_md5.txt
tar -xf "${CMAKE_TAR}"
mv "${CMAKE}" cmake-install
export "PATH=${DEPS_DIR}/cmake-install:${DEPS_DIR}/cmake-install/bin:$PATH"
popd
