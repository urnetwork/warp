# Router configuration design: `warpctl vyos`

Status: design for review. Every router configuration described here is
rendered and tested, and the migrations have been rendered against live
captures of every production router, but no migration has been applied
yet. The gateway class has never run on hardware.

Companion material:

- `warp/README.md`, "Generated EdgeOS router configuration": the operator
  summary and the command reference.
- `warp/warpctl/testdata/services-vyos.yml` and
  `warp/warpctl/testdata/settings-vyos.yml`: the test site this document
  uses for every example. It is a scaled copy of the production site on
  documentation address space (`203.0.113.0/24`, `198.51.100.0/24`,
  `192.0.2.0/24`, `2001:db8::/32`).
- `warp/warpctl/testdata/vyos/<router>-config.boot`: the complete rendering
  of each test router. These goldens are the detailed configuration this
  document explains; a reviewer should read them alongside it.
- `warp/warpctl/vyos.go` (the generator), `warp/services/routers.go`,
  `gateways.go`, `settings.go` (schema and validation), `warp/vyos`
  (config.boot parsing, diffing and the migration script),
  `xops/main/ansible/run-routers.sh` (the rollout).

The production inventory is `vault/main/services.yml`; this document does
not reproduce its addresses.

## 1. Goals and scope

The EdgeOS routers are the only packet filter in front of the edge hosts.
Until now they were configured by hand, so what each one admitted, routed
and translated drifted from what warp actually served. The design here
makes `services.yml` the single source of truth for every router:

1. `warpctl vyos create-config` renders the complete `config.boot` of each
   router from `services.yml` (plus `config/<env>/settings.yml` for the lan
   class). Nothing on a router is hand-configured except the management
   vpn profile it ships with.
2. The firewall of an edge router opens exactly what warp publishes on each
   attached interface and nothing else, derived from the same service
   definitions that drive the load balancer.
3. Rollout is a reviewed migration (a `set`/`delete` configure session
   computed against the router's live configuration) that commits only when
   every command is accepted, and cannot delete the management path.
4. There are three router classes with one shared hardened base:
   `edge` (fronts lb interfaces), `lan` (the site's private regional lan)
   and `gateway` (an upstream of ours between the ISP and the other two).

Out of scope: the hosts' own network configuration (netplan under
`xops/main/ansible/host_files`), the DNS records (`warpctl dns`), and the
switches.

## 2. Topology

A site is `<site>-<n>`, e.g. `r-us-tst-5`. It has one or more gateways, the
upstreams that own its address blocks. Behind each gateway sit routers on
that gateway's blocks. The test site:

```
                        ISP
     ┌───────────────────┼─────────────────────┐
     │                   │                     │
 gateway-1 (ISP's)   gateway-2 (ISP's)     gateway-3 (ours, class gateway)
 203.0.113.64/27     198.51.100.32/27      192.0.2.192/27 on-link at the ISP's .193
 2001:db8:99::/48    2001:db8:173::/48     2001:db8:535::/48 over a /126 tunnel
     │                   │                  eth1 ISP, eth2 management, eth3-8 "Blocks" bridge
     │                   │                     │
 ┌───┴────┬────────┐   r-us-tst-5-2          r-us-tst-5-3 (edge, planned)
 5-8    5-9      5-1   (edge, EdgeRouter 4)
 edge   edge     lan
  │      │        │
 edge-3  edge-5   the regional lan 192.168.51.0/24: builder, edge-2, edge-3,
 (2 lb   fireside edge-6, fireside (masqueraded; 8022/8023 forwarded to lan
  NICs)  (lb +    hosts for the planetoid backup pulls)
         transparent)
```

- A **gateway entry** (`gateways:` in `services.yml`) records an upstream's
  blocks whether or not we manage it: the IPv4 block and the ISP's gateway
  address in it, the IPv6 /48 and the gateway address on its first /64.
  An ISP gateway is tracked for its blocks only. A gateway of ours is also
  a router of `class: gateway` with the same name.
- An **edge router** fronts one or more edge hosts. Each host NIC that
  carries an lb interface plugs into its own router port. The host holds
  its public IPv4 address itself and takes its IPv6 address by SLAAC from
  the port; the router proxy-arps for the host on the WAN, routes its /32
  to the port and filters what reaches it.
- The **lan router** bridges every port but the WAN into the site's private
  lan, pins the hosts by dhcp, masquerades them and forwards a few declared
  public ports in.
- A **gateway router** of ours carries the routers behind it to the ISP:
  the IPv4 block is on-link at the ISP and proxy-arped through; the /48
  arrives over a point to point tunnel and is routed down as one /56 per
  router.

## 3. Source of truth

### 3.1 `gateways`

```yaml
gateways:
    r-us-tst-5-gateway-1:
        description: tst 10gbps dedicated, the isp's
        ipv4: 203.0.113.64/27
        ipv4_gateway: 203.0.113.65
        ipv6: 2001:db8:99::/48
        ipv6_gateway: 2001:db8:99::1
```

| field | meaning | validation |
|---|---|---|
| name | `<site>-<n>-gateway-<k>` | pattern enforced; non-overlapping blocks across gateways |
| `ipv4` | the IPv4 block | zero host bits, shorter than /31 |
| `ipv4_gateway` | the ISP's address in it (the routers' default gateway) | inside `ipv4`, neither network nor broadcast |
| `ipv6` | the site's /48 | exactly /48, zero host bits |
| `ipv6_gateway` | the gateway address on the first /64 (`::1`) | inside the first /64, not the prefix address |

### 3.2 `routers`

Common to every class:

| field | meaning | validation |
|---|---|---|
| `class` | `edge` (default), `lan`, `gateway` | |
| `planned` | rendered but not rolled out: `vyos hosts` omits it and `management_ipv4` may be empty | |
| `management_ipv4` | the address on the management vpn that `run-routers.sh` and planetoid use | IPv4, unique; required unless planned |
| `unms` | the UISP connection string, or `pending` for a router not attached yet | required |
| `edgeos_release`, `edgeos_config_version` | the `config.boot` footer markers | required |
| `login` | `system login user` entries: `encrypted_password`, `level` (`admin` default, or `operator`), `public_keys` (name to `type`+`key`) | at least one admin, and an admin with a public key, because ssh password authentication is off |
| `name_servers` | resolvers (default `1.1.1.1`, `9.9.9.9`, `2606:4700:4700::1111`); the IPv6 ones are also advertised to hosts | parse as addresses |
| `management_vpn_config_file` | the openvpn profile of `vtun1` (default `/config/by-pre.ovpn`) | |
| `conntrack_table_size`, `conntrack_hash_size` | `system conntrack`; unset keeps the platform default | 0..50000000, hash ≤ table |
| `offload_ipv4_forwarding`, `offload_ipv6_forwarding` | `system offload`; defaults on and off | IPv6 offload needs IPv4 offload |

Per class:

| field | edge | lan | gateway |
|---|---|---|---|
| `gateway` (a `gateways` entry) | required | required | forbidden (the gateway is its own entry) |
| `wan_interface` | required | required | forbidden (`isp_interface` instead) |
| `wan_ipv4` | own address on the gateway's block | same | own address on the block, on the ISP link |
| `wan_gateway_ipv4`, `wan_ipv6_prefix`, `wan_gateway_ipv6` | derived from the gateway at load; refused if set by hand | same | derived |
| `lan_interfaces` | ≥ 1, `ethP` with single digit P: the host ports | forbidden | forbidden |
| `bridge_interfaces` | the management bridge members (optional) | ≥ 1: every port but the WAN | the management port (optional) |
| `lan_ipv4` | overrides `192.168.nm.1/24` | same | required with `bridge_interfaces`; convention `192.168.(200+k).1/24` |
| `public_ports` | forbidden (ports come from the lb interfaces) | forwards to lan hosts | forbidden |
| `isp_interface`, `isp_ipv6`, `block_interfaces` | forbidden | forbidden | required (`isp_ipv6` a /126 with zero host bits; ≥ 1 block port) |
| `masquerade_wan_block` | optional (default false) | ignored (the lan is always masqueraded) | no nat |

Every listed interface may appear once per router. `wan_ipv4` must lie on
the gateway's block and be neither the network, broadcast, ISP gateway,
nor another router's WAN address. Derived WAN IPv6 identities must be
unique and cannot claim a gateway or subnet-router anycast address. The
common resolver, conntrack and offload checks apply to the gateway class
too, before class-specific validation returns.

### 3.3 Attachments (edge class)

An lb interface in the `lb.interfaces` section attaches to a router port:

```yaml
lb:
    interfaces:
        edge-5.example.com:
            enp33s0f1np1:
                ipv4: 203.0.113.91
                ipv6: "2001:db8:99:5930:9a03:9bff:fe56:593"
                router: r-us-tst-5-9
                router_interface: eth3
                router_tcp_forward_ports:   # optional custom rewrites on the router
                    8022: 22
        fireside.example.com:
            eno1np0:
                transparent: true           # no lb front: the host's own services bind it
                ...
```

Validation: `router` and `router_interface` come together; the router is
an edge router and the port one of its `lan_interfaces`; a port carries at
most one interface; `ipv4` is required and inside the router's WAN block;
network, broadcast, gateway and router addresses are reserved, and no two
attachments in one version may claim the same public address. `ipv6`, if
set, lies in the /64 that port advertises and is neither its subnet-router
anycast address (`::0`) nor the port router's address (`::1`). Ownership is
checked per version: a stable attachment repeated in historical versions
is not a second owner. Management and private bridge addresses remain
separate routing domains. `router_*_forward_ports`
need an attached router and are non-identity pairs in 1..65535. An interface
without `router` is a legacy attachment and is ignored by the generator.

### 3.4 `config/<env>/settings.yml` (lan class)

```yaml
lan_hosts:
    edge-2:
        ip: 192.168.51.43
        mac: e4:43:4b:56:79:10
```

Host names are lowercase, addresses IPv4, macs lowercase colon separated,
and no two hosts share an address or a mac. The LAN network, broadcast and
router bridge address cannot be assigned to a host. Every per-host `routes`
map in the same file (the addresses hosts use to reach each other) must
agree with `lan_hosts` for addresses inside the selected router's LAN;
generation checks later maps as well as the first, including YAML aliases.
An in-LAN route without a matching `lan_hosts` entry fails. Outside-LAN
overrides remain valid and unrelated edge rendering is unaffected. The
block is rewritten textually so the yaml anchors and comments around it
survive.

## 4. Addressing conventions

A router named `<site>-<n>-<m>` (single digits) has the router id `nm`.
Everything below is derived; only `wan_ipv4` is declared.

| what | value | example (r-us-tst-5-8 behind gateway-1) |
|---|---|---|
| WAN IPv4 | declared, on the gateway's block | `203.0.113.81/27` |
| WAN IPv6 | `<prefix>::nm/64`, on the gateway's first /64 | `2001:db8:99::58/64` |
| IPv4 default gateway | the gateway entry's `ipv4_gateway` | `203.0.113.65` |
| IPv6 default gateway | the gateway entry's `ipv6_gateway`, via the WAN port | `2001:db8:99::1` |
| routed block | `<prefix>:nm00::/56`, blackholed on the router | `2001:db8:99:5800::/56` |
| port `ethP` prefix (edge) | `<prefix>:nmP0::/64`, router at `::1` | eth8: `2001:db8:99:5880::/64` |
| lan bridge prefix (lan) | `<prefix>:nm00::/64`, router at `::1` | 5-1: `2001:db8:99:5100::/64` |
| legacy prefix | `<prefix>:nm::/64`, blackholed (pre-convention hosts) | `2001:db8:99:58::/64` |
| management or lan bridge | `192.168.nm.1/24`, dhcp `.38`–`.243` | `192.168.58.1/24` |
| gateway k management bridge | `192.168.(200+k).1/24` by convention (`lan_ipv4`) | gateway-3: `192.168.203.1/24` |

A host on edge port `ethP` therefore gets an IPv6 address by SLAAC inside
`<prefix>:nmP0::/64` (the fixture's edge-3 eno1np0 on 5-8 eth8 is
`2001:db8:99:5880:e643:4bff:fe94:e380`), and its IPv4 address is one of the
gateway's /27, declared on the interface.

Two decisions here need a reviewer's eye:

- **The WAN IPv6 address is on the gateway's /64, not the /48.** With the
  /48 on-link, a packet for any site address the router does not route
  itself triggers neighbour discovery on the WAN port instead of leaving
  through the gateway, which cut the two routers that had it from every
  block routed to the other routers (verified live with ping6 "Address
  unreachable" from the router itself).
- **Each router owns a /56, not a /64.** Each host NIC sits on its own
  router port and takes a SLAAC address from that port's /64, so a router
  with up to seven host ports needs up to seven /64s; `nm00::/56` holds
  them as `nmP0::/64`. The upstream must route the /56 to the router's WAN
  address: a gateway of ours renders that route itself, an ISP gateway must
  be asked for it. `warpctl vyos list-gateway-routes <env>` prints the
  request per gateway, including the pre-convention `nm::/64` routes to
  retire. Until the upstream routes a /56, hosts behind that router get
  IPv6 addresses nobody can reach, so the routes are a cutover
  prerequisite. The router blackholes its /56 and the legacy /64 so an
  address nobody advertises is dropped on the router instead of looping
  between router and upstream.

IPv4 needs no upstream route anywhere: each block is on-link at its
gateway, and every router proxy-arps for the addresses it routes.

## 5. The shared base

Every class renders the same base. The rendering order is the device's own
(sorted by name, then tag), so a generated file diffs cleanly against `show
configuration` and parses back to an identical tree.

### 5.1 Firewall globals

```
firewall {
    all-ping enable
    broadcast-ping disable
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    receive-redirects disable
    send-redirects disable
    source-validation disable
    syn-cookies enable
}
```

`source-validation disable` (no reverse path filter) is carried over from
the live routers on every class; see the review notes in section 11.

### 5.2 Chain layout and rule numbering

Four chains exist on every router, bound to the WAN or ISP port only:
`WAN_IN`/`WANv6_IN` on `in` (forwarded traffic) and `WAN_LOCAL`/`WANv6_LOCAL`
on `local` (traffic to the router). No other interface carries a firewall.
The rule numbers are fixed so operators can wedge a temporary rule between
ours and so migrations stay small:

| rule | chain | edge | lan | gateway |
|---|---|---|---|---|
| 1–4 | LOCAL (IPv6) | | | accept exact ND types 133–136 |
| 4 | IN, LOCAL (IPv4) | | | accept icmp from the ISP's gateway address |
| 5 | IN; LOCAL (IPv4) | | | drop sources in `BOGONS`/`BOGONS6` |
| 5–8 | LOCAL (IPv6) | | | accept error types 1–4 from `fe80::/10` only |
| 9 | LOCAL (IPv6) | | | accept membership query type 130 from `fe80::/10` only |
| 10 | all | accept established/related | same | LOCAL IPv4: established/related; LOCAL IPv6: bogon drop |
| 11 | LOCAL (IPv6) | | | accept established/related |
| 20 | all | drop invalid | same | LOCAL only |
| 30 | IN | accept any source in the site's own block (v4 /27, v6 /48) | absent | absent |
| 30, 31 | LOCAL | accept echo requests at `10/second` burst 20, then drop echo | same | same |
| 32 | LOCAL | accept every other icmp type | same | same |
| 40 | IN | accept all icmp (forwarded icmp is never limited) | same | absent |
| 100, 110, … | IN | one accept per published port per attached interface | one accept per `public_ports` forward | absent |
| 9000 | all | drop and log at `5/second` burst 10 | same | LOCAL only |
| default | all | drop | drop | IN: accept; LOCAL: drop |

The IN chains' default drop is what protects the hosts; rule 9000 samples
what it drops into the log instead of the unbounded default logging. On
the LOCAL chains nothing but established replies and icmp reaches the router
from the WAN: ssh and the gui are reachable from the management vpn and the
bridges only.

### 5.3 System

```
system {
    analytics-handler { send-analytics-report false }
    conntrack {
        hash-size 131072            # only when conntrack_hash_size is set
        modules { ftp disable, gre disable, h323 disable, pptp disable, sip disable, tftp disable }
        table-size 1048576          # only when conntrack_table_size is set
    }
    crash-handler { send-crash-report false }
    gateway-address <ipv4 gateway>
    host-name <router>
    login { user <name> { authentication { encrypted-password <hash>; public-keys <key name> { key, type } } level admin|operator } }
    name-server <each resolver>
    ntp { server 0..3.ubnt.pool.ntp.org }
    offload { ipv4 { forwarding enable|disable } ipv6 { forwarding enable|disable } }
    syslog { global { facility all { level notice } facility protocols { level debug } } }
    time-zone UTC
}
```

The conntrack helpers are off because they can be abused to open ports from
inside (nat slipstreaming) and nothing here needs them. Conntrack sizing is
per router: an EdgeRouter Infinity carrying lb traffic runs 1048576/131072,
a 1 GB EdgeRouter 4 keeps the platform defaults (262144/32768 on EdgeOS 3).
IPv4 forwarding offload is on by default; IPv6 offload is off by default
and is an explicit toggle because offloaded packets bypass the firewall
counters (the fixture's 5-9 has it on).

### 5.4 Services

```
service {
    dns { forwarding { cache-size 10000; force-public-dns-boost; listen-on <bridge> } }
    gui { http-port 80; https-port 443; older-ciphers disable }
    ssh { disable-password-authentication; port 22; protocol-version v2 }
    unms { connection <uisp key> }      # or the empty stanza for `pending`
}
```

ssh takes keys only; the fleet key is installed through `login`, and
validation refuses a router without an admin key so a migration can never
lock ssh out. The gui keeps the password. Every router is attached to UISP;
a router not attached yet renders the empty `unms { }` stanza that EdgeOS
keeps, so the attachment is a later one-line change.

### 5.5 Management vpn and footer

`interfaces openvpn vtun1 { config-file /config/by-pre.ovpn }` references
the profile already on the router; the generator does not produce the
profile. The `config.boot` footer carries `edgeos_config_version` and
`edgeos_release` so the file is one the firmware accepts as its own. Every
router runs EdgeOS v3.0.1.

### 5.6 Bridges

Every bridge (management, lan, blocks) renders identically apart from its
addresses and description:

```
bridge brN {
    address ...
    aging 300
    bridged-conntrack disable
    description "Local Bridge" | Blocks
    hello-time 2
    max-age 20
    priority 32768
    promiscuous enable
    stp false
}
```

and every member port is `bridge-group { bridge brN }`, `duplex auto`,
`speed auto`. Every bridge with an IPv4 address runs dhcp
(`shared-network-name LAN_BR`, `authoritative enable`, `lease 86400`,
range `.38`–`.243`, `default-router` and `dns-server` the bridge address,
`hostfile-update disable`, `static-arp disable`, `use-dnsmasq disable`) and
the resolver listens on it.

## 6. Edge class

Golden: `testdata/vyos/r-us-tst-5-8-config.boot` (Infinity, six host ports,
two lb interfaces of edge-3), `r-us-tst-5-9-config.boot` (Infinity with a
plain lb interface, a transparent interface, a router forward,
`masquerade_wan_block` and IPv6 offload), `r-us-tst-5-2-config.boot`
(EdgeRouter 4: WAN eth3, host port eth0, bridge eth1+eth2).

### 6.1 Interfaces

```
ethernet eth1 {                                 # WAN
    address 203.0.113.81/27
    address 2001:db8:99::58/64
    description Internet
    firewall { in { ipv6-name WANv6_IN; name WAN_IN } local { ipv6-name WANv6_LOCAL; name WAN_LOCAL } }
    ip { enable-proxy-arp }
}
ethernet eth8 {                                 # a host port
    address 2001:db8:99:5880::1/64
    ip { enable-proxy-arp }
    ipv6 {
        dup-addr-detect-transmits 1
        router-advert {
            cur-hop-limit 64; link-mtu 0; managed-flag false; max-interval 600
            name-server 2606:4700:4700::1111    # the IPv6 resolvers of name_servers
            other-config-flag false
            prefix 2001:db8:99:5880::/64 { autonomous-flag true; on-link-flag true; valid-lifetime 2592000 }
            reachable-time 0; retrans-timer 0; send-advert true
        }
    }
}
bridge br0 { address 192.168.58.1/24 ... }      # management bridge, members eth0 and eth2
```

- The WAN port carries the declared IPv4 address and the derived IPv6
  address, both firewall bindings, and proxy-arp so the router answers the
  upstream's ARP for the host addresses it routes.
- Every `lan_interfaces` port is fully rendered whether or not a host is
  attached: the port's `::1/64`, proxy-arp (so the host's ARP for its
  default gateway, the ISP's address, is answered by the router), and
  router advertisements of the port's /64 with the resolvers. A host port
  has no IPv4 address: the host's IPv4 default gateway is the ISP's, on
  what the host believes is its on-link /27, and the router bridges that
  belief with proxy-arp on both sides.
- The management bridge has the router id's /24 and dhcp; it is where an
  operator plugs in, and what the egress masquerade is for.

### 6.2 Routing

```
protocols static {
    interface-route 203.0.113.84/32 { next-hop-interface eth8 }   # one per attached interface
    interface-route 203.0.113.85/32 { next-hop-interface eth6 }
    route6 2001:db8:99:58::/64 { blackhole }                       # legacy /64
    route6 2001:db8:99:5800::/56 { blackhole }                     # the router's block
    route6 ::/0 { next-hop 2001:db8:99::1 { interface eth1 } }
}
system gateway-address 203.0.113.65
```

The /32 interface routes are what make the proxy-arp answers correct: Linux
answers an ARP request when its route to the target leaves through a
different interface than the request came in on, so the WAN answers for the
hosts and the host ports answer for the gateway. The /64s advertised on the
ports are connected routes and need nothing static.

### 6.3 What the firewall opens, and why

Per attached interface the generator derives accept rules for the address
of that interface only (`destination address` + `port`), one rule per
port, numbered from 100 in steps of 10, IPv4 in `WAN_IN` and IPv6 in
`WANv6_IN` (only when the interface has an IPv6 address). The label in the
description names host, interface and owner, e.g.
`warp edge-3 eno1np0 lb 443`.

On a **plain lb interface** (an lb front runs there):

1. every lb http port (`lb.ports`) on tcp: `lb 80 tcp`;
2. every lb stream port on the protocol of the service it maps to, when
   that service runs on this host, unless the port is a forward target or
   is kept private while a previous lb generation drains: `lb 444 tcp`,
   `lb 53 udp`;
3. every lb forward port (`udp_forward_ports` and the tcp equivalent) whose
   target service runs on the host. Warp's host-side dnat rewrites the
   public port to the lb's listener on both families, so the router only
   admits the public port and has no dnat of its own for it.

A port one owner publishes on both protocols renders once as `tcp_udp`
(`lb 443`).

On a **transparent interface** (no lb front; the host-pinned services bind
the interface themselves) none of the lb ports open. Only:

1. the `external_udp_ports` of each host-pinned service on the host:
   `alt 443 udp`, `alt 4053 udp`;
2. the public ports its `external_udp_forward_ports` alias (`53: 4053` makes
   whodis answer on the dns port): `alt 53 udp`;
3. the allocated external port of every service port a host-pinned service
   lists in `public_ports`, per block, on both protocols:
   `proxy g1 socks`, `proxy g2 wg`. The rest of the port pool, and the
   service's http status port, stay closed.

**Router destination nat** exists only when declared: an interface's
`router_tcp_forward_ports`/`router_udp_forward_ports` become
`service nat rule 100+` entries (`type destination`, `inbound-interface`
the WAN, `destination address` the host and `port` the public port,
`inside-address` the host and the target port) plus an accept rule for the
target port, IPv4 only since EdgeOS nat is. A public port that is both
served and rewritten, or rewritten twice, is refused at generation time
because the rewrite would silently capture served traffic.

Rule-number capacity is checked across all attachments of a router, not
independently per host. Each firewall family admits at most 890 generated
rules (100 through 8990); rule 9000 remains the log-drop rule. Destination
NAT admits at most 490 rules (100 through 4990), reserving the entire range
from 5000 even when a particular router omits the exclusion. Generation
fails before returning a config that would merge host rules into a fixed
rule; it does not renumber or truncate published ports.

### 6.4 NAT

```
nat {
    rule 5000 { description "Exclude local"; exclude; outbound-interface eth1; protocol all; source { address 203.0.113.64/27 }; type masquerade }
    rule 5001 { description "masquerade for WAN"; outbound-interface eth1; protocol all; type masquerade }
}
```

Hosts hold public addresses and egress with them, so the WAN block is
excluded from the masquerade; only the management bridge is translated.
`masquerade_wan_block: true` drops rule 5000 (the fixture's 5-9 keeps the
legacy behaviour of translating its hosts to the router's address).

### 6.5 Host side

An attached host NIC has its public IPv4 address and the block's gateway as
a static route in netplan, IPv6 by SLAAC, and the resolvers point at the
lan router (the edge router only forwards). The router is invisible to the
host at layer 3 on IPv4: it answers ARP for the gateway and forwards.

## 7. Lan class

Golden: `testdata/vyos/r-us-tst-5-1-config.boot`. The lan router is the
site's regional lan: the hosts' out-of-band interfaces, the builder, the
console devices.

### 7.1 Interfaces

```
bridge br0 {
    address 192.168.51.1/24
    address 2001:db8:99:5100::1/64
    ipv6 { router-advert { ... name-server 2001:db8:99:5100::1; prefix 2001:db8:99:5100::/64 { ... } } }
}
ethernet eth0, eth2..eth8 { bridge-group { bridge br0 } }
ethernet eth1 {                                  # WAN, no proxy-arp
    address 203.0.113.73/27
    address 2001:db8:99::51/64
    firewall { ... the four chains ... }
}
```

Every port but the WAN is a member of the lan bridge. The bridge advertises
the first /64 of the router's /56 with the router itself as the IPv6
resolver, and dhcp names the router as the IPv4 resolver: the lan hosts
resolve through the router on both families. The WAN has no proxy-arp: the
lan holds no public addresses.

### 7.2 dhcp and `lan_hosts`

The dhcp subnet carries one `static-mapping <host> { ip-address, mac-address }`
per `lan_hosts` entry whose address lies inside this router's lan, so a
host keeps its address across reinstalls and the per host `routes` in
`settings.yml` stay true. Dynamic leases come from `.38`–`.243`.
Static mappings cannot use the subnet endpoints or the router's own
bridge address; all per-host in-LAN route claims are checked for agreement.

`run-routers.sh --update-settings` seeds and extends the block from the
live routers: it captures each lan router, `warpctl vyos update-settings`
reads the dhcp static mappings inside the lan, adds the hosts the block
lacks, reports (and leaves alone) a host whose live address or mac differs,
removes nothing, and rewrites only the block. It changes no router; the
operator reviews and commits `config/<env>` before the next run renders
the lan router from it.

### 7.3 Firewall, forwards and nat

The lan is private, so there is no "allow local" rule: nothing from the WAN
block reaches the lan on its own. The only inbound openings are the
router's `public_ports`, each an accept rule to the lan host and port and a
destination nat from the public port on the WAN:

```
firewall name WAN_IN rule 100 { action accept; description "warp edge-2 backup ssh"; destination { address 192.168.51.43; port 22 }; protocol tcp }
service nat rule 100 { description "warp edge-2 backup ssh"; destination { port 8022 }; inbound-interface eth1; inside-address { address 192.168.51.43; port 22 }; protocol tcp; type destination }
service nat rule 5001 { masquerade for WAN, no exclusion }
```

The forward's `host` must be a `lan_hosts` entry inside the lan, otherwise
generation fails. The shared destination-NAT numbering reserves 5000 and
above, so at most 490 declared forwards render, with a deterministic error
instead of an overlapping rule. In production the forwards are the planetoid backup pulls
(ssh to the database and redis hosts), which bypass the management vpn on
purpose for throughput; an xops test checks the planetoid inventory agrees
with the vault's `public_ports`.

### 7.4 Routing

The same default routes and blackholes as an edge router (`::/0` via the
gateway on the WAN, the /56 and the legacy /64 blackholed). No interface
routes: the lan is a connected /24 and /64.

## 8. Gateway class

Golden: `testdata/vyos/r-us-tst-5-gateway-3-config.boot`, with
`r-us-tst-5-3-config.boot` as the edge router behind it. This class has not
run on hardware yet; section 8.6 lists what to verify at installation.

### 8.1 How the two families arrive

The ISP delivers the two blocks differently, and the design follows that:

- **IPv4**: the ISP keeps the /27 on-link on the fiber at its own gateway
  address (`ipv4_gateway`, `.193` in the fixture). There is no IPv4
  tunnel. Our gateway holds the next address (`wan_ipv4`, `.194/27`) on the
  ISP port and carries the routers behind it exactly as an edge router
  carries its hosts: each router's address and every host attached behind
  it are /32 interface routes to the block bridge, proxy-arped for on the
  ISP port; the ISP's gateway address is proxy-arped for on the bridge. The
  routers behind keep `.193` as their default gateway and are unaware of
  the box in between.
- **IPv6**: the /48 arrives over a point to point /126 (`isp_ipv6`, the ISP
  at `::1`, the gateway at `::2`) on the same port. The site's
  `ipv6_gateway` (`::1` of the first /64) sits on the block bridge, so the
  routers behind reach their default gateway as on an ISP gateway; the
  gateway routes each router's /56 to that router's WAN address and
  blackholes the rest of the /48.

### 8.2 Interfaces

```
ethernet eth1 {                                  # ISP
    address 192.0.2.194/27
    address 2001:db8:3c3:1::2/126
    description ISP
    firewall { in { ipv6-name WANv6_IN; name WAN_IN } local { ipv6-name WANv6_LOCAL; name WAN_LOCAL } }
    ip { enable-proxy-arp }
}
bridge br0 {                                     # Blocks: eth3..eth8
    address 2001:db8:535::1/64
    description Blocks
    ip { enable-proxy-arp }
}
bridge br1 { address 192.168.203.1/24; description "Local Bridge" }   # management: eth2
```

By convention on the EdgeRouter Infinity the fiber lands on eth1 (the first
SFP+ port), eth2 is the management port, and eth3 to eth8 carry the routers
behind it. The block bridge has no IPv4 address: IPv4 is routed and
proxy-arped through it, the ISP's gateway being on the other side.

### 8.3 Routing

```
protocols static {
    interface-route 192.0.2.195/32 { next-hop-interface br0 }      # r-us-tst-5-3's WAN address,
                                                                    # then each host attached behind it
    route6 2001:db8:535:5300::/56 { next-hop 2001:db8:535::53 { interface br0 } }   # per router behind
    route6 2001:db8:535::/48 { blackhole }
    route6 ::/0 { next-hop 2001:db8:3c3:1::1 { interface eth1 } }
}
system gateway-address 192.0.2.193
```

The routers behind a gateway are those whose `gateway:` names it (edge and
lan). Their host addresses come from the same attachments the edge
generator uses, so attaching a host to a router behind our gateway changes
the gateway's configuration too; `run-routers.sh` renders and pushes every
router with a change.

### 8.4 Firewall

The gateway forwards everything to the blocks unfiltered, since the
routers behind it filter, but it drops what can never legitimately arrive
from the ISP side:

```
firewall group {
    network-group BOGONS { network 192.0.2.192/27 (the site's own block); 0.0.0.0/8; 10.0.0.0/8; 100.64.0.0/10; 127.0.0.0/8; 169.254.0.0/16; 172.16.0.0/12; 192.0.0.0/24; 192.0.2.0/24; 192.168.0.0/16; 198.18.0.0/15; 198.51.100.0/24; 203.0.113.0/24; 224.0.0.0/4; 240.0.0.0/4 }
    ipv6-network-group BOGONS6 { 2001:db8:535::/48 (the site's /48); ::/128; ::1/128; ::ffff:0:0/96; 100::/64; 2001:2::/48; 2001:db8::/32; 3ffe::/16; fc00::/7; fe80::/10; fec0::/10; ff00::/8 }
}
name WAN_IN {
    default-action accept
    rule 4 { accept icmp from 192.0.2.193 }
    rule 5 { drop source group BOGONS }
}
name WAN_LOCAL {
    default-action drop
    rule 4, rule 5 as above, then 10 established, 20 invalid, 30/31 echo limit, 32 icmp, 9000 log sample
}
ipv6-name WANv6_IN { default-action accept; rule 5 { drop source group BOGONS6 } }
ipv6-name WANv6_LOCAL {
    default-action drop
    rules 1–4 { accept ipv6-icmp types 133, 134, 135, 136 respectively }
    rules 5–8 { accept ipv6-icmp types 1, 2, 3, 4 respectively; source fe80::/10 }
    rule 9 { accept ipv6-icmp type 130; source fe80::/10 }
    rule 10 { drop source group BOGONS6 }
    rule 11 { accept established/related }
    rules 20, 30, 31, 32, 9000 as above
}
```

The site's own blocks are in the bogon groups because a packet claiming a
site source can only arrive from the ISP side if it is spoofed. The IPv4
exception is the ISP's gateway address, which lies inside the
IPv4 block: its icmp (path mtu, unreachables, echo replies to our pings) is
admitted by rule 4 ahead of the drop. IPv6 needs its own local control
exceptions: valid discovery can use link-local or unspecified sources,
and local errors, including Packet Too Big, can arrive from a link-local
neighbor. Exact types precede the source-group drop only in `WANv6_LOCAL`;
transit rules and the source groups are unchanged. Unspecified/non-link-local
bogon errors and unrelated link-local informational messages remain dropped.
Nonbogon errors still reach the unchanged generic ICMP rule; echo limits
are unchanged. The kernel retains ND/MLD validity checks; these rules do
not introduce an unverified hop-limit CLI match.

The query-only type 130 exception lets the gateway refresh its own
multicast membership, which can matter for solicited-node reachability on
a snooping link. It does not enable multicast routing or blanket-permit
reports or redirects. These are standards-based resilience corrections,
not evidence that the current ISP uses snooping or experienced this failure.
See [RFC 4890 §4.4.1](https://www.rfc-editor.org/rfc/rfc4890.html#section-4.4.1)
and [RFC 3810 §5.1.14](https://www.rfc-editor.org/rfc/rfc3810.html#section-5.1.14).

Synthetic policy tests check rendered match/order and exact type/source
scope, not kernel packet validation or acceptance on target hardware.
Documentation-prefix fixture traffic is itself a bogon; a synthetic
nonbogon class tests unchanged ordinary PMTU handling without borrowing a
real address. Target firmware and physical-link acceptance remain required
before deployment.

### 8.5 Services

No nat of any kind. dhcp and the resolver run on the management bridge
`br1` only. gui, ssh and unms are the shared base; a gateway not yet in
UISP is `pending`.

### 8.6 What to verify at installation

The gateway relies on Linux proxy-arp semantics that the edge routers
already exercise live, but in a new arrangement. The checks, from the
fixture's addresses:

1. From the ISP side, ARP for a router behind (`.195`) and for a host
   behind it is answered by the gateway's eth1 MAC; ARP for the gateway's
   own `.194` likewise; ARP for an address the gateway does not route is
   not answered (the route is the connected /27 on eth1 itself).
2. From a router behind, ARP for `.193` on the block bridge is answered by
   the gateway's br0 MAC (the /32 route to `.193` is the connected /27 on
   eth1, a different interface). ARP between two routers behind, or for a
   host behind another router, is answered by that router, not the
   gateway.
3. `ping 192.0.2.193` from the gateway and from a router behind. The
   proxy-ARP gateway still routes IPv4 and decrements its TTL: it is not
   hop-transparent. Traceroute visibility depends on ICMP responses and
   filtering; an absent displayed hop is not evidence of no routed hop.
   IPv6 is routed too.
4. The IPv6 default route is active with the tunnel up, the /56 routes
   resolve to the routers' WAN addresses on br0, and an address in the /48
   that no router owns returns unreachable from the gateway, not from the
   ISP.
5. Path MTU discovery through the tunnel works (rule 4 admits the ISP
   gateway's IPv4 icmp; ICMPv6 from the tunnel address is not a bogon).

## 9. Migration and rollout

### 9.1 The `vyos` package

`Parse` reads a `config.boot` or the output of `show configuration` (a
configure-mode `show` with change markers is rejected). `Migrate(live,
desired)` computes the configure session that turns one into the other:

- a container only in live is one `delete` of the subtree; a container
  only in desired is `set` leaf by leaf;
- a leaf value only in live is deleted by value, so a multi-valued leaf
  (addresses, name servers) keeps its other values; a single value that
  changes is deleted then set, never set twice;
- a concealed comparison containing `****************` produces no secret
  change and increments `UnverifiedComparisons`. An unchanged concealed
  value and a changed one are indistinguishable; neither is verified equal.
  A masked desired value is never installed as a literal credential;
- every delete comes before every set, each in device order, and the
  output is deterministic.

Protected paths: a migration that would delete under, or delete an ancestor of,
`interfaces ethernet <uplink>`, `interfaces openvpn`, `service ssh`,
`system gateway-address` or `system login` is refused, because any of
those could cut the management path to a remote router. The one allowed
delete under a protected path is an interface `address` value when the
same migration sets a new address of the same family that live lacks: the
commit replaces the address rather than removing it. This is what lets the
legacy routers move to new WAN addresses. This preserves the supported
same-interface address replacement; it does not prove that a new address,
route or login key will maintain reachability. Protection covers both the
rendered uplink and any live uplink identifiable by a `WAN_LOCAL` or
`WANv6_LOCAL` local-firewall attachment. An unidentified live uplink is
reported as such in the script; the guard does not guess a missing path.
Ordinary refusal diagnostics omit delete values, which may be credentials.

The script is a vbash configure session using the device's own
`script-template`; failed template sourcing or session entry aborts before
mutation, without attempting cleanup of a session it never entered.
Every `set`/`delete` is `|| fail $LINENO`, which tears
the session down before `commit`. A commit failure or a subsequent
`configure_exit` failure does not prove the running router is unchanged.
It ends with `configure_exit` and no `save`. A header
line `# warpctl-vyos-migration changes=N deletes=D sets=S unverified=U`
separates command count from unknown comparisons. `Empty()` describes only
the command count. EdgeOS v3.0.1 has no `commit-confirm`
(verified on a live router); `--commit-confirm` exists for a VyOS router
and fails before commit on EdgeOS.

### 9.2 `run-routers.sh`

Per router, in `vyos hosts` order, stopping at the first failure:

1. build `warpctl`, list the routers (`<router> <management ipv4> <class>`,
   planned routers omitted), render every `config.boot` up front and refuse
   to touch any router if generation fails;
2. capture the live configuration over the management vpn;
3. render with `create-migration --desired=<rendered directory>` and print
   change and unverified counts. This mode requires an explicit router,
   checks both captured and desired hostnames, and derives protection from
   these files without reloading services/settings. `--check` stops here
   and prints the script, including unknown comparisons. An automatic run
   refuses before backup or apply if any concealed comparison is unresolved;
4. copy `/config/config.boot` to `/config/bak/config.boot.<unix ms>`,
   keeping the newest ten;
5. if there are changes, copy the script to the router and run it detached
   (`nohup`, exit status written to a file), because a commit that replaces
   the WAN address drops the management vpn for a minute or two; poll the
   status file, reconnecting as needed (default 600 s, every 5 s). The
   monotonic deadline includes transport time; zero poll intervals are
   rejected. Each local SSH is limited to 30 s, or the remaining poll
   budget, and its owned process group is killed and reaped on timeout or
   cancellation. This does not cancel a detached remote commit. Keep the
   migration log private; nonzero status, disconnect or timeout leaves an
   unknown outcome requiring inspection, not an automatic retry;
6. capture again and require zero commands and zero unverified comparisons
   against the same already-rendered desired file. No settings reread can
   change this target. Confirm only a verified commit when a confirm timer
   was explicitly requested;
7. upload the same desired bytes to a private, exclusive
   `/config/.warp-config.<unix ms>.boot`, read it back with successful SSH
   status and byte-compare it, then atomically rename it over
   `/config/config.boot` on the same filesystem and verify the installed
   file. Partial upload or failed staging verification leaves the old
   default intact. A lost rename response is unknown: inspect both files.
   Until the atomic rename the saved configuration is the previous one, which is the
   recovery path on a firmware without `commit-confirm`: a reboot from UISP
   or the console restores it. Recovery is not autonomous on EdgeOS;
   no failure branch initiates a reboot.

On failure, the mode-0700 local workspace and remote migration/status/log
files are retained for bounded operator diagnosis. Raw configuration and
device logs are not printed during normal apply failures. On full success,
temporary local and remote migration artifacts are removed. Concealed
fields require a trusted unmasked observation or explicit reconciliation
before automatic rollout; the script neither assumes equality nor forces
credential rotation, and offers no bypass for this unknown.

The first run against a router that lacks the fleet key prompts for the
password; that same commit installs the key and turns password
authentication off. Planetoid archives every router's saved `config.boot`
daily at 05:00 over the management vpn (one tarball with a manifest,
failing closed and keeping the previous archive if a router is unreachable
or its file names another host); the router list is the same `routers`
section.

### 9.3 Read-only snapshot comparison

`warpctl vyos compare-config <router> --desired=<directory> --in=<directory>`
reads one `<router>-config.boot` from the desired directory and optional
`<router>-live.config` / `<router>-saved.config` captures from the input
directory. It reads and parses the desired file once, never constructs a
generator, and never reads settings, the vault or a router. Each input is
limited to 4 MiB and checked for the selected hostname and essential generated
configuration shape. Keep these directories and the output private.

The command emits one JSON object with `schema_version: 1`. `running` and
`saved` each expose `complete`, `changes`, `deletes`, `sets`, `unverified`,
`protected_delete` and a fixed `reason`. Counts never contain command text,
paths or secret values. Protected deletion drift stays visible in the counts;
this read-only operation does not admit the migration. A concealed comparison
remains incomplete, even when its command count is zero. The required capture
shape can reject partial input; it cannot prove a running capture was atomic.

`topology` has independent `complete` and `reason` fields, a bounded
`neighbors` array (at most 1024 entries, each with `interface`, `family`,
`address`, `role`), and `conntrack`. Neighbor authority is limited to the
generated WAN's unique IPv4 gateway attachment, explicit IPv6 next-hop and
interface pairs, exact IPv4 /32 interface routes, and exact generated IPv6
host-rule destinations joined to one configured per-port /64 or explicit
on-link advertised prefix. A prefix alone is not a host inventory. A bare
advertised spare/dynamic port creates no inferred host: known neighbors remain
usable with `reason: derived-explicit-neighbors-only`, qualifying the unknown
downstream census separately. `topology.complete` describes extraction of
explicit expectations, not discovery of all hosts. Unsupported or ambiguous
exact expectations return no partial neighbor list. Bridge/proxy-ARP routes
identify only expected next-hop addresses on that bridge, not a physical host
or member port. This is neither a live neighbor check nor a host census;
absence from an idle ARP/ND cache alone is not proof of failure.

`conntrack` preserves each valid explicit `table_size` and `hash_size`
independently. Zero means that field is unset or invalid/unknown, never a
platform default; `explicit` is true if at least one field is known. Neighbor
incompleteness does not erase a known capacity field. Missing live/saved files
produce `complete: false` / `reason: input-unavailable` independently, so an
empty input directory supports topology-only use without any router reads.
The top-level completion bit combines the three layer completion bits, not
equality or full capacity authority. Consumers must use their own layer and
field authority; an incomplete result is not a health or recovery receipt.

## 10. Test coverage

Go (`go test ./...` in `warp`):

- `TestVyosGoldenConfigs`: every fixture router matches its golden byte for
  byte, parses back to the same tree, is in device order, and migrates to
  itself with no commands. `WARP_UPDATE_GOLDEN=1` rewrites the goldens
  after a reviewed change.
- `TestVyosRouterConventions`, `TestVyosAddressDerivation`: the derived
  addresses of section 4, including the WAN /64 and the /56.
- `TestVyosHardening`: the hardening of section 5 on an edge router (the
  echo limit pair, the drop sample, redirects, keys-only ssh, the gui
  ciphers, conntrack sizing, offload toggles); the lan and gateway tests
  check the same rules on their classes.
- `TestVyosRulesForAnLbInterface`, `TestVyosRulesForATransparentInterface`,
  `TestVyosInterfaceForwardsBecomeRouterDnat`, `TestVyosRefusesConflictingForwards`,
  `TestVyosSkipsLegacyInterfaces`: the edge firewall derivation of 6.3.
- `TestVyosLanRouter`, `TestVyosLanRouterChecksTheSettings`,
  `TestVyosUpdateSettingsMergesTheLiveLanHosts`, plus the `services`
  settings tests: section 7.
- `TestVyosGatewayRouter`, `TestVyosListGatewayRoutes`: section 8 and the
  routes listing, including a host attached behind the gateway.
- `TestVyosProtectedPathsGuardTheManagementPath`,
  `TestVyosMigrationScriptChecksTheCaptureHostName`, and the `vyos` package
  tests (synthetic device-format round trips, protected ancestor and
  descendant deletes, address replacement, masked comparison metadata,
  value-free refusal diagnostics, script ordering and determinism): section
  9.1. `TestVyosDesiredSnapshot*` verifies the real command's rendered-file
  authority, capture/target hostname checks and both identifiable uplinks.
- `TestMigrationScript*` executes synthetic local template/session failures
  and healthy entry before mutation. `TestVyosCompareConfig*` covers the real
  snapshot-only command, privacy, masked/protected drift, missing and malformed
  input, exact versus ambiguous neighbor authority and independent capacity.
- `services`: `TestLoadServicesConfigRejectsBadRouters` and friends cover
  every validation rule of section 3; `TestVaultMainRouterAttachments`
  loads the production vault and checks its routers, gateways and derived
  fields.

Shell (`python3 -m pytest tests` in `xops/main/ansible`):
`test_run_routers.py` drives `run-routers.sh` against a fake ssh and covers
the order of operations, check mode, convergence failure, a migration that
fails or never reports, a dropped vpn during polling, backup rotation and
`--update-settings`. Deterministic failure controls also cover partial and
corrupt staging, failed readback/rename, post-commit cleanup failure,
render-time input drift, concealed preflight refusal, elapsed transport
budget, child reaping and controlling-terminal ownership. These fake
transports prove driver decisions, not device commit atomicity or live
reachability. `test_planetoid_router_config.py` covers the archive
and the agreement between the planetoid backup pulls and the lan router's
public ports.

## 11. Review notes

Decisions a reviewer should weigh, and the limitations known at the time of
writing:

1. **No reverse path filtering** (`source-validation disable`) on any
   class, as the live routers had. Anti-spoofing on the ISP side is the
   gateway's bogon group; the ISP gateways do whatever they do. A router
   behind an ISP gateway accepts any source on its WAN.
2. **Edge `WAN_IN` rule 30 trusts the site.** Anything sourced from the
   site's own /27 or /48 is forwarded to the hosts unfiltered. This is what
   lets hosts of the same site talk on ports the public does not get, and
   it also means one compromised site address reaches every port of every
   host. The lan class deliberately lacks this rule.
3. **The gateway forwards stateless and unfiltered** (`WAN_IN` default
   accept, no state rules), by design: the routers behind it filter. The
   cost is that the gateway offers the blocks no protection of its own
   beyond bogons.
4. **No `local` firewall on the host ports or bridges.** An attached host
   can reach its edge router's ssh (keys only) and gui (password) through
   the port, and a router behind our gateway can reach the gateway's. This
   is unchanged from the live routers.
5. **Host-dependent gateway configuration.** Because IPv4 is carried by
   /32 routes, our gateway is re-rendered whenever a host is attached
   behind it. The alternative (routing the whole /27 to the bridge with
   more specific routes shadowing the ISP link's connected route) was not
   chosen; it needs no host knowledge but is harder to read.
6. **IPv6 forwarding offload is off by default** because the firewall
   counters stop seeing offloaded packets; it costs throughput on the
   Infinity and is a per-router toggle.
7. **Logging is local only** (syslog to the router itself, a rate-limited
   sample of drops). There is no remote syslog. The old `commit-archive`
   push was dropped in favour of the planetoid archive of the saved
   configuration.
8. **Cutover prerequisites outside this repo.** The upstream /56 routes
   (section 4) for the routers that do not have them yet; the hosts'
   netplan moving the public addresses onto the hosts before the legacy
   routers migrate; the gateway hardware, its tunnel and its vpn profile.
9. **Open naming question.** Router ids are two single digits, so a tenth
   router of a site (`<site>-5-10`) does not fit the convention; the
   management /24 and the hextet layout both assume `nm`.
10. **What is not generated**: the management vpn profile on each router,
    the UISP enrolment (only the connection string), and the switches.
