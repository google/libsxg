ARG base_image
FROM ${base_image}
ARG repository

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata &&\
    apt-get install -y --no-install-recommends -q \
                    build-essential \
                    cmake \
                    debhelper \
                    devscripts \
                    fakeroot \
                    git \
                    libssl-dev \
                    lintian \
                    lsb-release && \
    rm -rf /var/lib/apt/lists/*

ADD . /libsxg
WORKDIR /libsxg

ADD packaging /packaging
WORKDIR /packaging

CMD ["./build_deb", "/libsxg"]
