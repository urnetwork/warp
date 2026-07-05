FROM ubuntu:24.04
# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

ARG TARGETPLATFORM
ARG TARGETARCH
ARG warp_env
ENV WARP_ENV=$warp_env

# grafana + loki + alloy bundle behind the go http front (see main.go)
# the go front enforces basic auth from vault/<env>/grafana.yml and routes:
#   /status   -> warp status
#   /loki/... -> loki (push and query paths with separate service users)
#   /         -> grafana ui
# alloy ships the docker container logs of the host to the local loki

RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    ca-certificates \
    lsb-release \
    ubuntu-keyring \
    unzip

# grafana oss from the grafana apt repo
# https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/
RUN mkdir -p /etc/apt/keyrings && \
    curl https://apt.grafana.com/gpg.key | gpg --dearmor \
    | tee /etc/apt/keyrings/grafana.gpg > /dev/null

RUN echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] \
https://apt.grafana.com stable main" \
    | tee /etc/apt/sources.list.d/grafana.list

RUN apt-get update && apt-get install -y grafana alloy

# print the grafana and alloy versions
RUN /usr/share/grafana/bin/grafana --version
RUN /usr/bin/alloy --version

# loki release binary
# https://github.com/grafana/loki/releases
ARG loki_version=3.7.3
RUN curl -L -o /tmp/loki.zip \
    "https://github.com/grafana/loki/releases/download/v${loki_version}/loki-linux-${TARGETARCH}.zip" && \
    unzip /tmp/loki.zip -d /tmp/ && \
    mv "/tmp/loki-linux-${TARGETARCH}" /usr/local/sbin/loki && \
    rm /tmp/loki.zip

# print the loki version
RUN /usr/local/sbin/loki --version

# mimir release binary
# https://github.com/grafana/mimir/releases
ARG mimir_version=3.1.1
RUN curl -L -o /usr/local/sbin/mimir \
    "https://github.com/grafana/mimir/releases/download/mimir-${mimir_version}/mimir-linux-${TARGETARCH}" && \
    chmod 755 /usr/local/sbin/mimir

# print the mimir version
RUN /usr/local/sbin/mimir --version

COPY build/$TARGETPLATFORM/grafana /usr/local/sbin/warp-grafana

# the go front forwards TERM to loki (flush on shutdown) and grafana
STOPSIGNAL SIGTERM
CMD ["/usr/local/sbin/warp-grafana"]
