FROM ubuntu:24.04
# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

ARG TARGETPLATFORM
ARG TARGETARCH
ARG warp_env
ARG DEBIAN_FRONTEND=noninteractive
ENV WARP_ENV=$warp_env

# grafana + loki + mimir bundle behind the go http front (see main.go)
# the go front enforces basic auth from its scoped grafana.yml secret and routes:
#   /status   -> warp status
#   /loki/... -> loki (push and query paths with separate service users)
#   /         -> grafana ui
# host-managed Fluent Bit ships Docker journald records to the local Loki

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

ARG grafana_version=13.2.0
RUN apt-get update && apt-get install -y "grafana=${grafana_version}" && \
    rm -rf /var/lib/apt/lists/*

# print the grafana version
RUN /usr/share/grafana/bin/grafana --version

# Bake Logs Drilldown into the image instead of relying on Grafana's
# asynchronous startup-time plugin downloader. The checksum is published by
# the Grafana plugin catalog for this exact release.
ARG logs_drilldown_version=2.5.2
ARG logs_drilldown_sha256=315aae6ddec2a548547856a1bd884651507da2e182f358191988379f6522d05d
RUN mkdir -p /var/lib/grafana/plugins && \
    curl -fsSL --retry 3 -o /tmp/grafana-lokiexplore-app.zip \
    "https://grafana.com/api/plugins/grafana-lokiexplore-app/versions/${logs_drilldown_version}/download" && \
    echo "${logs_drilldown_sha256}  /tmp/grafana-lokiexplore-app.zip" | sha256sum --check - && \
    unzip -q /tmp/grafana-lokiexplore-app.zip -d /var/lib/grafana/plugins && \
    rm /tmp/grafana-lokiexplore-app.zip

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

# A fixed high uid/gid is declared in services.yml too, making the parent and
# every third-party child unprivileged even if either image or runtime drifts.
RUN groupadd --gid 65532 warp-grafana && \
    useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin warp-grafana && \
    mkdir -p /run/warp-grafana /srv/warp/secrets /var/lib/grafana /var/lib/loki /var/lib/mimir && \
    chown -R 65532:65532 /run/warp-grafana /srv/warp/secrets /var/lib/grafana /var/lib/loki /var/lib/mimir

USER 65532:65532

# the go front forwards TERM to loki (flush on shutdown) and grafana
STOPSIGNAL SIGTERM
CMD ["/usr/local/sbin/warp-grafana"]
