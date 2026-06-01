FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile scansnap.c ./
RUN make

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENV HOME=/config
ENV XDG_CONFIG_HOME=/config

COPY --from=build /src/scansnap /usr/local/bin/scansnap

ENTRYPOINT ["/usr/local/bin/scansnap"]
CMD ["-h"]
