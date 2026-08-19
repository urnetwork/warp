FROM ubuntu:24.04 AS nginx-build

# This is the first upstream nginx commit that can emit PROXY protocol v2 to
# UDP backends. Pin both the immutable commit and the downloaded source bytes;
# do not float on a branch, tag, package repository, or redirect target.
ARG NGINX_COMMIT=11d11b5f0d3d8ace5215e1a77918e9dc219ce7db
ARG NGINX_SOURCE_SHA256=dbc96585a7ddc6f3c3a8faae9487ecdf5ad4e1e2eeb77a8b26e69d935434c9de

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libpcre2-dev \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl --fail --location --retry 3 \
        --output nginx.tar.gz \
        "https://codeload.github.com/nginx/nginx/tar.gz/${NGINX_COMMIT}" \
    && echo "${NGINX_SOURCE_SHA256}  nginx.tar.gz" | sha256sum --check --strict \
    && mkdir nginx \
    && tar --extract --gzip --file nginx.tar.gz --directory nginx --strip-components=1 \
    && rm nginx.tar.gz

WORKDIR /src/nginx
RUN ./auto/configure \
        --build="urnetwork-${NGINX_COMMIT}" \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/run/nginx.pid \
        --lock-path=/run/nginx.lock \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --user=www-data \
        --group=www-data \
        --with-compat \
        --with-file-aio \
        --with-threads \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_realip_module \
        --with-http_stub_status_module \
        --with-http_gzip_static_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-cc-opt='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIC' \
        --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed' \
    && make -j"$(nproc)" \
    && strip objs/nginx \
    && objs/nginx -V

FROM ubuntu:24.04

ARG TARGETPLATFORM
ARG warp_env
ARG NGINX_COMMIT=11d11b5f0d3d8ace5215e1a77918e9dc219ce7db
ARG NGINX_SOURCE_SHA256=dbc96585a7ddc6f3c3a8faae9487ecdf5ad4e1e2eeb77a8b26e69d935434c9de
ENV WARP_ENV=$warp_env

LABEL org.opencontainers.image.source="https://github.com/urnetwork/warp" \
      org.opencontainers.image.title="URnetwork edge load balancer" \
      org.opencontainers.image.vendor="URnetwork" \
      org.opencontainers.image.nginx.commit="${NGINX_COMMIT}" \
      org.opencontainers.image.nginx.source-sha256="${NGINX_SOURCE_SHA256}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcre2-8-0 \
        openssl \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p \
        /etc/nginx/modules-enabled \
        /usr/share/doc/nginx \
        /var/cache/nginx/client_temp \
        /var/cache/nginx/fastcgi_temp \
        /var/cache/nginx/proxy_temp \
        /var/cache/nginx/scgi_temp \
        /var/cache/nginx/uwsgi_temp \
        /var/log/nginx

COPY --from=nginx-build /src/nginx/objs/nginx /usr/sbin/nginx
COPY --from=nginx-build /src/nginx/LICENSE /usr/share/doc/nginx/copyright

# Fail the image build if the copied binary or its runtime linkage is broken,
# and retain the exact build/module list in the build log for provenance.
RUN ldd /usr/sbin/nginx \
    && nginx -V

RUN openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096

COPY nginx/mime.types /etc/nginx/mime.types
ADD build/${WARP_ENV}/nginx.conf /srv/warp/nginx.conf

COPY build/${WARP_ENV}/status.json /srv/warp/status/status.json

COPY build/$TARGETPLATFORM/lb /usr/local/sbin/lb

# See https://ubuntu.com/blog/avoiding-dropped-connections-in-nginx-containers-with-stopsignal-sigquit
STOPSIGNAL SIGQUIT
CMD ["/usr/local/sbin/lb"]
