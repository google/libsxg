#!/bin/sh
BORINGSSL="chromium-stable"
BORINGSSL_ZIP="boringssl-${BORINGSSL}.zip"
# travis_retry wget --no-check-certificate -o boringssl-${BORINGSSL}.zip https://github.com/google/boringssl/archive/${BORINGSSL}.zip 
wget --no-check-certificate -o ${BORINGSSL_ZIP} https://github.com/google/boringssl/archive/${BORINGSSL}.zip
echo "c8306c37c9f0e0a88ff13a90e2a8f468  ${BORINGSSL_ZIP}" > boringssl_md5.txt
md5sum -c boringssl_md5.txt
unzip ${BORINGSSL_ZIP}
pushd boringssl-${BORINGSSL}
mkdir build
cd build
cmake ..
make -j`nproc`
popd
