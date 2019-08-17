FROM debian:buster-slim
LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN apt-get update && \
    apt-get install -y --no-install-recommends -q \
    wget \
    unzip \
    perl \
    make \
    clang \
    gcc \
    git && \
    rm -rf /var/lib/apt/lists/*

RUN wget --no-check-certificate https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2-Linux-x86_64.tar.gz && \
     tar -xf cmake-3.15.2-Linux-x86_64.tar.gz
ENV PATH $PATH:/cmake-3.15.2-Linux-x86_64/bin

RUN wget --no-check-certificate https://github.com/openssl/openssl/archive/OpenSSL_1_1_1c.zip && \
    unzip OpenSSL_1_1_1c.zip && \
    cd openssl-OpenSSL_1_1_1c && \
    ./config && \
    make -j`nproc` && \
    make install

WORKDIR /

ADD . /libsxg
RUN mkdir libsxg/docker_build -p && \
    cd libsxg/docker_build && \
    cmake .. && \
    make sxg

CMD "/bin/bash"
