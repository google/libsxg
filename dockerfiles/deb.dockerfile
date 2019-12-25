ARG base_image
FROM ${base_image}
ARG repository

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
		    lintian \
                    lsb-release \
		    ronn && \
    rm -rf /var/lib/apt/lists/*

ADD ${repository} /libsxg
ADD . /packaging
WORKDIR /packaging

RUN sed -i -e "s/debuild -b/debuild -b -us -uc/" /packaging/build_deb

ENTRYPOINT ["./build_deb", "/libsxg"]
