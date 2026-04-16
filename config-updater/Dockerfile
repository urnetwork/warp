FROM ubuntu:24.04
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/

ARG TARGETPLATFORM
ARG warp_env
ENV WARP_ENV=$warp_env

# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
RUN apt-get update && apt-get install -y \
	ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

COPY build/$TARGETPLATFORM/config-updater /usr/local/sbin/config-updater

RUN mkdir -p /root/config
ADD build/$WARP_ENV/config /root/config

CMD ["/usr/local/sbin/config-updater", "/root/config", "/srv/warp/config"]
