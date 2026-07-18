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

Each service needs a Makefile that builds and publishes a docker image. `warpctl build <Makefile>` exposes these env vars to the build:

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



![Warp Control](res/images/warpr.webp "Warp Control")

