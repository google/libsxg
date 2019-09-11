FROM debian:stretch
LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN apt-get update && \
    apt-get install -y --no-install-recommends -q \
                    clang \
                    cmake \
                    git \
                    libssl-dev \
                    make && \
    rm -rf /var/lib/apt/lists/*

ADD . /libsxg
RUN mkdir libsxg/docker_build -p && \
    cd libsxg/docker_build && \
    cmake .. \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_C_COMPILER=clang \
          -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DSKIP_TEST=TRUE && \
    make sxg && \
    make install

CMD "/bin/bash"
