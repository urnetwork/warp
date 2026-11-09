# Rolling out the SNI split

The runbook for §13.4's split on the lb interfaces (W1, D-TLS-2): how an interface moves from the http servers on TCP 443 to the stream server that reads the SNI and sends names under `<root>` to tlsedge. Every step that touches production is the owner's.

## Before the first interface

- **The gate.** `splitbench` (this directory) runs the same nginx binary and config unsplit and split on one test interface, at the observed peak and at `concurrent_clients` (786,432), and scores §13.4's limits: at most 5% less throughput on connect's H1 transport, at most 1 ms more p99 for connect and api, head-to-hint p99 at most 2 s, at most 15% more CPU per Gbit/s, memory within the host's headroom. Head-to-hint p99 and the headroom are measured apart and given to it (`--head-to-hint-p99`, `--memory-headroom`). It exits 1 when a limit fails. Nothing flips until it passes, and its report goes with the change. `proxy_buffer_size` in `lb.tls_split` is what the gate sizes.
- **The config.** vault's `services.yml` carries `lb.tls_split` (roots, service, proxy_buffer_size, and `client_hello` equal to `config/<env>/tlsedge.yml`'s), the tlsedge service on every lb host with tcp stream port 443, and 8443, 8883 and 5671 in `tcp_stream_port_services` (W7). warpctl refuses a render whose platform names under a root carry an unreserved label, so platform names and company MX leave `ur.network` first (§12.4).
- **The checks.** Route 53's lb checks probe HTTPS with SNI on 443 (`warpctl dns sync`), so a broken split drops an interface from the platform answers. The dns edges' `probe.edge.<root>` hello answers tlsedge's `unrecognized_name` only through a working split.

## Each interface, one at a time

1. **Drain.** Add the interface to `config/<env>/sidecar.yml`'s `drained`, named as the `<env>-lb` sets name their members (`<host>-<iface>`, the host without the domain), and run `warpctl dns sync <env>`. The interface leaves the `<env>-lb` sets in both families on every domain; its own record and its health checks stay. The dns edges reread the file within 60 s and leave it out of user-name answers. Wait out the records' ttl.
2. **Flip.** `warpctl deploy main lb <version> <block>`, where `<version>` is the lb version built with `tls_split`: config is baked per lb version, so the split goes out as a deploy, and only to that block.
3. **Probe.** While drained, only probes and the gate's bench reach it. The dns edges' probe of `probe.edge.<root>` must answer `unrecognized_name`, monitor's verified handshake must pass, and its Route 53 HTTPS checks must be healthy. A platform name, the apex, an unknown name and a hello without SNI must reach the http servers; a user's name must reach tlsedge.
4. **Rejoin.** Take the interface out of `drained` and run `warpctl dns sync <env>`. Its member sets come back on the health checks they kept.
5. **Hold 24 h.** Compare it with the unsplit interfaces on the gate's metrics. Then the next interface.

## Rollback

The prior lb version: `warpctl deploy main lb <prior version> <block>`. Drain the interface first when there is time. An interface whose split probe fails pages at any hour from M5 and rolls back after 30 min (§19.8).

## Later

From M6, an interface rejoins only once it is current for the newest custom-host map version (§13.4), which lbmap reports (TLS-M6-01).
