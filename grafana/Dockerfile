ARG loki_go_version=1.26.4

# Loki 3.7.3 decrements the active-tail gauges twice when its internal
# one-hour close is followed by TailHandler's deferred close. Official main
# still carries the same non-idempotent path, so build the pinned release
# source with narrow regression-tested lifecycle and backend-attribution
# patches in this directory.
FROM --platform=$BUILDPLATFORM golang:${loki_go_version} AS loki-build
ARG TARGETOS
ARG TARGETARCH
ARG loki_version=3.7.3
ARG loki_source_sha256=1f74768fc476978796b49455fd962587a6b0e3b75212215ed8449f792aa5c776
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    patch && \
    rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 3 -o /tmp/loki.tar.gz \
    "https://github.com/grafana/loki/archive/refs/tags/v${loki_version}.tar.gz" && \
    echo "${loki_source_sha256}  /tmp/loki.tar.gz" | sha256sum --check - && \
    mkdir -p /src/loki && \
    tar -xzf /tmp/loki.tar.gz --strip-components=1 -C /src/loki && \
    rm /tmp/loki.tar.gz
COPY loki-tailer-close.patch /tmp/loki-tailer-close.patch
WORKDIR /src/loki
RUN patch --batch --forward -p1 < /tmp/loki-tailer-close.patch && \
    go test ./pkg/querier/tail \
      -run '^Test(TailerCloseIsIdempotent|TailClientReceiveErrorIncludesBackendAddress)$' \
      -count=1
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=vendor -trimpath -tags netgo \
    -ldflags="-s -w \
      -X github.com/grafana/loki/v3/pkg/util/build.Branch=release-3.7.x \
      -X github.com/grafana/loki/v3/pkg/util/build.Version=${loki_version}-urnetwork.2 \
      -X github.com/grafana/loki/v3/pkg/util/build.Revision=82cdcdc0+tail-close-once+tail-backend-addr" \
    -o /out/loki ./cmd/loki

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

# Grafana 13.2 extracted the formerly-core Prometheus datasource into a
# standalone plugin. Runtime downloads are disabled in grafana.ini so startup
# and readiness do not depend on internet access; bake the signed, checksum-
# pinned native package for each image architecture just like Logs Drilldown.
# Without this, provisioned Mimir datasources still exist in the database but
# every dashboard and all file-provisioned rules fail with
# [plugin.notRegistered].
ARG prometheus_plugin_version=13.1.7
ARG prometheus_plugin_sha256_amd64=31b0e919ae51db0fdb91ffb2ba0991f358bbd5e02fac676b6ffad56cc223d57c
ARG prometheus_plugin_sha256_arm64=c2a29c56683d31d4dfaf71907a60ed47f4f378990ff381be99549fa3c2639010
RUN case "$TARGETARCH" in \
      amd64) prometheus_plugin_sha256="$prometheus_plugin_sha256_amd64" ;; \
      arm64) prometheus_plugin_sha256="$prometheus_plugin_sha256_arm64" ;; \
      *) echo "unsupported Prometheus plugin architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL --retry 3 -o /tmp/prometheus.zip \
    "https://grafana.com/api/plugins/prometheus/versions/${prometheus_plugin_version}/download?os=linux&arch=${TARGETARCH}" && \
    echo "${prometheus_plugin_sha256}  /tmp/prometheus.zip" | sha256sum --check - && \
    unzip -q /tmp/prometheus.zip -d /var/lib/grafana/plugins && \
    rm /tmp/prometheus.zip

# Regression-patched Loki from the checksum-pinned source stage above.
COPY --from=loki-build /out/loki /usr/local/sbin/loki

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
