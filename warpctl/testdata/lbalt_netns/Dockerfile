# The image of the lb_alt network-namespace harness (lbalt_netns_test.go):
# Ubuntu 24.04, as the edges run, with the nf_tables iptables and ip6tables
# (1.8.10), iptables-restore, conntrack and iproute2's ip and ss. sudo is
# there because warpctl runs its iptables and ip commands through it; the
# harness runs as root, so sudo needs no configuration.
FROM ubuntu:24.04

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		conntrack \
		iproute2 \
		iptables \
		sudo \
	&& rm -rf /var/lib/apt/lists/*
