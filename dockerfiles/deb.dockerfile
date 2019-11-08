ARG base_image
FROM ${base_image}

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN apt-get update && \
    apt-get install -y --no-install-recommends -q \
                    build-essential \
                    cmake \
                    debhelper \
                    devscripts \
                    fakeroot \
                    git \
                    libssl-dev \
                    lsb-release && \
    rm -rf /var/lib/apt/lists/*

ADD . /libsxg
WORKDIR /libsxg

ENTRYPOINT ["packaging/build_deb", "docker_output"]
