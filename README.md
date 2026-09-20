# warp
Warp control. Fluid iteration and zero downtime continuous release on any server (colo+cloud).

```
warpctl stage version local
warpctl build <env> <service>/Makefile
warpctl deploy <env> <service> latest-local --percent=50
```


## Overview

The goal of warp is to enable developers to deploy fast on any server (colo+cloud) with best practices and tools that enable no downtime. Best practices include redundancy, rolling deployments, and uniform dev and production environments. Using the `warpctl` tool on your dev machine and servers gives you a standard workflow:

0. Develop and test locally
1. Stage a version
2. Build services
3. Gradually deploy services to an environment
4. Validate and run deployed services in an environment

The `warpctl` tool installs as a systemd unit on your hosts for each service block. A service have one or more blocks that allow it to be validated and gradually deployed. See the services.yml section for more details.


## Get started

Requires Go 1.18+

Build the `warpctl` tool, add it to the PATH.

```
cd warpctl
make
export PATH="$PATH:$(pwd)/build"
warpctl
```

```
export WARP_HOME=/my/project/home
warpctl init --docker_namespace=<docker_namespace>
```

On your dev machine, WARP_HOME will typically be your project home. More advanced users can place the `vault`, `config`, and `site` directories anywhere (using `warctl init`), but to get started create these directories in the default place under WARP_HOME:

```
$WARP_HOME
	config/
	  local/ # this is the env name
	    # add files that your services read to configure their behavior
	  myfirstenv/
	vault/
	  local/
	    services.yml
	  myfirstenv/
	   	services.yml
      tls/
        star_mydomain_com/
          star_mydomain_com.pem
          star_mydomain_com.key
	site/
	  # add files specific to this host
```

## services.yml

All deployment configuration comes from a single file `$WARP_VAULT_HOME/<env>/services.yml`. Edit `vault/local/services.yml` inside an env to define the services and hosts for the local env.

[An example services.yml](warpctl/config-sample/services.yml):

```yml
# hostnames use reverse flattened notation,
# e.g. "service.canary.bringyour.com" has hostname canary-service.bringyour.com
# this must be done for wildcard certs of the domain which cover only one level

domain: bringyour.com
hidden_prefixes:
    - callused-bronchus-eastern-quinine
    - formosa-eat-rookie-trow
# lb uses the same hidden prefixes unless specified below
lb_hidden_prefixes:
    - virgo-arkansas-mao-zircon
    - breaker-gawk-sanskrit-mudd
# if false, the tls dir is named `domain` and must have SAN of each host
# tls_wildcard: true

versions:
# append new versions to the top
# The head version is the latest spec, but older versions are needed to keep the ports consistent with the following rules.
# These rules are needed in the case when a single live host is updated across many versions,
# which takes in account running services deployed in various cadence and router forwarding to the host.
# RULES:
# 1. Once an internal port is associated to a service-block, it can never be associated to another service-block.
# 2. Each service-block-<serviceport> has a fixed external port that will never change.
#    If the port is removed from the exteral ports list, that is a config error.
# 3. An lb-block has a fixed routing table that will never change 
# 4. An internal port can't use a port ever used by as an external; and vice-versa
-   external_ports: 80,443,7000-7200
    internal_ports: 7201-9000
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: warpservices
    lb:
        ports:
            - 80
            - 443
        # udp_ports:
        #     - 8000
        interfaces:
            # each <host>-<interface> is a block
            by-us-fmt-1-edge-0.bringyour.com:
                en0:
                    docker_network: warpen0
                    concurrent_clients: 753664
                    cores: 92
                    external_ports:
                        # <externalport>: <port> forces an external port
                        80: 80
                        443: 443
                    # this follows the convention at http://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req
                    # rate_limit:
                    #     requests_per_second: 5
                    #     burst: 50
                    #     delay: 25
    services:
        web:
            # if defined, this is the url of the web app
            cors_origins:
                - https://bringyour.com
            # set to no if this service does not have a standard /status route
            # status: no
            # expose these hostnames as aliases for the service.
            # The aliases must be covered by the same tls cert as the domain
            # expose_aliases:
            #     - bringyour.com
            # (default true) if false, no entry is created for <env>-<service>.<domain>
            # exposed: false
            # (default true) if false, no route is created for <env>-lb.<domain>
            # lb_exposed: true
            # if no hosts list, all lb hosts are used
            # hosts:
            #   - by-us-fmt-1-edge-0.bringyour.com
            ports:
                - 80
            # udp_ports:
            #     - 8000
            # public udp ports this service owns on each of its `hosts`, with no
            # lb in front. Requires a hosts list. Each one allocates a host port
            # exactly like `ports`, and warp DNATs the public port to it on the
            # host interface, the same rule it uses for the lb interfaces. The
            # container reads the mapping from WARP_PORTS and must never bind
            # the public port itself. The lb on those hosts stops publishing the
            # port on udp, and keeps publishing it on tcp.
            # external_udp_ports:
            #     - 443
            #     - 4053
            # public udp ports aliased to one of the external_udp_ports on the
            # same host dnat, like the lb's udp_forward_ports, on both address
            # families. The router in front only admits the public port.
            # external_udp_forward_ports:
            #     53: 4053
            blocks:
                - beta: 1
                - g1: 24
                - g2: 25
                - g3: 25
                - g4: 25

```


## What is config?

`warpctl` allows injecting config into service blocks. Config are like hard coded configuration that your services read. This can be anything that tunes the behavior of the services, for example ML weights or performance parameters.

Instead of creating new service versions to deploy new configurations, new config is injected into existing versions using the config-updater. This is like changing the command line args but for all the config files.


## What is vault?

This is where you put sensistive files that should never be in a docker repo. These are usually stored in some encrypoted way and set up on the target host in some secure way.


## Local routing

The `local_routing_on` target of the warp makefile edits `/etc/hosts` to direct the service hostnames of the `local` env to this host. The hostname of your dev computer is also used as an alias so that you can create DNS entries for your dev computer for second-device/mobile testing.

```
make local_routing_on
make local_routing_off
```


## Set up a deployment environment

You create a deployment environment where you want services to run. Each environment needs a host and a network interface. Each network interface runs its own lb. For example if you have three interfaces, you can have three public IPs and run three lbs. The lb is meant to receive traffic directly from the internet without a NAT so that the source IPs are preserved. Each public IP would typically be exposed in the service DNS records.

Create systemd units for all your services, organized by host.

```
warpctl service create-units <env> --out=<outdir> --target_warp_home=/srv/warp --target_warpctl=/usr/local/bin/warpctl
```

On the target server host, create the target WARP_HOME.

```
/srv/warp
  config
  vault
  site
```

Create the docker networks and init the routing tables.

```
# execute the commands printed here
warpctl service docker-networks <env>
# append the config printed here to the bottom of /etc/iproute2/rt_tables
warpctl service routing-tables <env>
```

Also make sure the log dir exists and that docker is logged in.

```
mkdir /var/log/warp
sudo docker login
```

Configure vault and site outside of warp (e.g. Ansible or some secure system image tool). We will deploy the config as the final step.

Copy `warpctl` to the host into `/usr/local/bin`.

```
export WARP_HOME=/srv/warp
warpctl init --docker_namespace=<docker_namespace> --dockerhub_username=<dockerhub_username> --dockerhub_token=<dockerhub_token>
```

Now copy the systemd units for the host into place (e.g. `/etc/system/system.d/`) and enable all the units.

```
for s in `find /etc/systemd/system -iname 'warp-*.service' | xargs -n 1 basename`; do
    sudo systemctl enable $s;
    sudo systemctl restart $s;
done
```


## Build and deploy

```
warpctl stage version local
warpctl build <env> <service>/Makefile
warpctl deploy <env> <service> latest-local --percent=50
```


## Build

Each service needs a Makefile that builds its release binaries and publishes a Docker image. Before using `warpctl build`, install the Go vulnerability scanner:

```
go install golang.org/x/vuln/cmd/govulncheck@latest
```

`warpctl build <env> <Makefile>` runs the Makefile's `all` target, runs `govulncheck -mode=binary` against every Go executable under `build/linux/{amd64,arm64}`, and only then runs `warp_build_image`. A missing scanner, missing release binary, scan error, or reported vulnerability stops the build before the image target can publish anything.

Service Makefiles must keep compilation in `all` and image publication in `warp_build_image`. The legacy `warp_build` target is reserved as a fail-closed guard against bypassing the scan. `warpctl build` exposes these env vars to both targets and to the scanner:

- WARP_ENV
- WARP_SERVICE
- WARP_VERSION
- WARP_DOCKER_NAMESPACE


## Validation

To allow validation during deployment, the service needs to listen on http port 80 to the `/status` route, and response with a status object:

```
{
	"version": ""
	"configVersion": ""
	"status": ""
}
```


## MacOS local developer setup

Hostname matters for local versions. Make sure you have a unique one for your team.

```
sudo scutil --set HostName <YOURHOSTNAME>
sudo scutil --set LocalHostName <YOURHOSTNAME>
sudo scutil --set ComputerName <YOURHOSTNAME>
```


## Router setup guides

Do not connect the LB interfaces directly to the WAN without setting a firewall policy to expose only the LB external ports. It's best to use a high packet-per-second router in front of the LB interfaces to apply traffic shaping, standard firewall rules, and only expose the LB external ports.

- [EdgeRouter basic setup guide](router-setup/edgerouter.md)

### Generated EdgeOS router configuration

`warpctl vyos` renders the complete `config.boot` of each EdgeOS router in
front of the LB interfaces from `services.yml`, so the router firewall opens
exactly what warp publishes on each interface and nothing else:

```
warpctl vyos hosts <env>                                  # <router> <management ipv4> per line
warpctl vyos list-gateway-routes <env> [<router>]         # what the upstream gateway must route to the routers
warpctl vyos create-config <env> [<router>] [--out=<outdir>]
warpctl vyos create-migration <env> [<router>] --in=<indir> [--out=<outdir>] [--commit-confirm=<minutes>]
```

`create-config` writes `<outdir>/<router>-config.boot`. `create-migration`
reads each router's live configuration (`show configuration`, or `show` in
configure mode) from `<indir>/<router>-live.config` and writes
`<outdir>/<router>-migration.sh`, a vbash configure session of `delete` and
`set` commands that turns the live configuration into the generated one and
commits it. A failed command ends the session before commit. The script
refuses to delete under the WAN interface, the management vpn, ssh, the
login users or the default gateway, since any of those could cut the
management path to a remote router. A live secret that `show` masks as
`****************` is taken to already match.

`services.yml` describes the routers in a top level `routers` section and
attaches each LB interface to a router port with `router` and
`router_interface`. A router named `<site>-<n>-<m>` derives everything else
from the digits `nm`: its WAN IPv6 address is `<prefix>::nm/64` (the
gateway's /64, never the whole /48, which would put every site address
on-link on the WAN port and cut the router off from the blocks the upstream
routes to the other routers), port `ethP` advertises `<prefix>:nmP0::/64`
inside the router's `<prefix>:nm00::/56` (which the upstream must route to
the router's WAN address: `list-gateway-routes` prints the request, one
IPv6 route per router, the note that IPv4 needs none since the block is
on-link and the routers proxy-arp for their hosts, and the pre-convention
`/64` routes to retire), and the management bridge is `192.168.nm.0/24`.
The router blackholes the rest of its /56 and the pre-convention
`<prefix>:nm::/64` of its id, so an unrouted address is dropped on the
router instead of looping back to the upstream. An attached interface holds
its public IPv4 address itself (the host's netplan sets it, with the
block's gateway as its default route) and gets its IPv6 address by SLAAC
from the port; the router proxy-arps for the host on both sides and routes
the /32 to the port. Per attached interface the router opens what is served
there. On a plain LB interface: the LB http ports on tcp, each LB stream
port on the protocol of the service it maps to when that service runs on
the host (forward targets and ports kept private for a draining LB
generation stay closed), and the LB forward ports whose target is served on
the host (warp's host-side dnat rewrites them to the LB's listener there on
both address families, so the router only admits the public port). On a
transparent
interface no LB front runs, so only the host-pinned services' own ports
open: their `external_udp_ports` and the allocated external port of every
service port listed in `public_ports`. Firewall rule descriptions name the
host, interface and owner, e.g. `warp fireside eno1np0 proxy g1 socks`.

A host-pinned service's `external_udp_forward_ports` alias a public udp port
to one of its `external_udp_ports` on the block's own interface dnat, the
same mechanism as the LB's `udp_forward_ports`, on both address families
(the alt service: `53: 4053`, so whodis answers on the dns port). The router
in front only admits the public port. Destination nat on a router itself is
declared in `services.yml`, never inferred: an LB interface declares
`router_tcp_forward_ports` and `router_udp_forward_ports` for custom
rewrites to that host, and the router also opens the target port; EdgeOS
nat is IPv4-only, so these are. A rewrite of a port that is served on the
interface, or two rewrites of one public port, is refused.

Every router gets the same hardening: the WAN chains drop by default and
log a rate-limited sample of the drops (rule 9000, `limit 5/second`) instead
of logging every drop, echo requests to the router itself are admitted at
`10/second` and dropped above that while every other icmp type passes
unthrottled (path mtu discovery, neighbour discovery), forwarded icmp is
never limited, the router sends no redirects, ssh takes keys only (every
router must carry an admin login with a public key, which `services.yml`
validation enforces), the gui refuses the older tls ciphers, nothing is
reported to the vendor, and the conntrack helpers are off. Per router,
`services.yml` sets what differs between the boxes: `conntrack_table_size`
and `conntrack_hash_size` (an EdgeRouter Infinity runs 1048576/131072, a
1 GB EdgeRouter 4 keeps the platform defaults by leaving them unset),
`offload_ipv4_forwarding` (default on) and `offload_ipv6_forwarding`
(default off; needs IPv4 offload, and is a measured toggle since offloaded
packets bypass the firewall counters), and `masquerade_wan_block` (default
false: the hosts' public addresses are excluded from the egress masquerade
and only the management bridge is translated).

`xops/main/ansible/run-routers.sh` builds warpctl, backs up each router's
`/config/config.boot` to `/config/bak/`, applies the migration, verifies the
running configuration converged, and only then installs the generated
`config.boot`. The migration runs detached from the ssh session and reports
its exit status through a file the script polls, reconnecting as needed,
because a commit that replaces the router's WAN address (the migration
guard allows replacing an address in the same commit, never removing one)
drops the management vpn for a minute or two. EdgeOS v3.0.1 has no
`commit-confirm`, so the saved configuration is the fallback: a reboot
restores it until the new one is installed. `--commit-confirm=<minutes>`
exists for a VyOS router. The first run against a router that does not
carry the fleet key yet prompts for the password; the commit installs the
key and turns password authentication off in the same step.

### Generated DNS records

`warpctl dns` derives the public records of every domain in `domains` from
`services.yml` and reconciles the registrar with them (`route53` or
`cloudflare`, from the `domains` map):

```
warpctl dns plan <env> [--envalias=<envalias>] [--domain=<domain>] [--cloudflare-token-file=<path>]
warpctl dns sync <env> [--envalias=<envalias>] [--domain=<domain>] [--cloudflare-token-file=<path>]
```

`plan` prints every derived name and the changes each registrar would make;
`sync` applies them. Per domain `D` the derived records are: `<host>-<iface>.D`
for every LB interface (A, and AAAA when it has an IPv6 address);
`<env>-lb.D`, the interfaces that run an LB front (not the transparent
ones), as a weighted record set with a health check per member and address
family on route53 (`http://<address>:80/<lb hidden prefix>/status`, host
`<env>-lb.<primary domain>`; the member weight is the interface's
`dns_weight`, 100 by default) and as round robin on cloudflare, plus
`<env>-lb-v4.D` and `<env>-lb-v6.D` for one family each; `<env>-<service>.D`
for every exposed service and the service's `expose_aliases` and
`expose_domains` under `D`, as aliases of `<env>-lb.D` (a name whose first
label ends in `-v4` or `-v6` carries that family only; on cloudflare a
single family alias carries the addresses, since a CNAME cannot); for a
host-pinned service with no LB in front (alt), `<env>-<service>.D` and its
`dns_aliases` resolve straight to the interface addresses of its hosts, with
the same `-v4`/`-v6` rule; and a top level expose alias `<host>.D` of an LB
host carries the host's addresses, `*.<host>.D` aliases it. The top level
`dns` block sets the record `ttl` (60) and lists `unmanaged` names the sync
never touches even though they are derived, such as an apex that fronts a
CDN. Names at domains outside `domains`, expose aliases of hosts that have
no LB interface, and everything not derived are reported and left alone.
Route53 health checks with the LB status path and host that no member
references any more are removed. The route53 credentials come from the
standard AWS environment or `~/.aws`; the cloudflare token from
`CLOUDFLARE_API_TOKEN`, `--cloudflare-token-file`, or
`<WARP_HOME>/root/servers/cloudflare`, and it needs the zones' DNS edit
permission.



![Warp Control](res/images/warpr.webp "Warp Control")
