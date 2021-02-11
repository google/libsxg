#!/bin/sh
BORINGSSL="chromium-stable"
BORINGSSL_ZIP="boringssl-${BORINGSSL}.zip"
travis_retry wget --no-check-certificate -O ${BORINGSSL_ZIP} https://github.com/google/boringssl/archive/${BORINGSSL}.zip 
echo "1acff89fe89096959156b337493dd524  ${BORINGSSL_ZIP}" > boringssl_md5.txt
md5sum -c boringssl_md5.txt
unzip ${BORINGSSL_ZIP}
pushd boringssl-${BORINGSSL}
mkdir build
cd build
cmake ..
make -j`nproc`
popd
