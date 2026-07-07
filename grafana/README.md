# warp grafana

Self-hosted logging and stats for warp: a grafana + loki + mimir + alloy
bundle behind a go http front, running on every service host. Each host
serves the grafana ui and the loki/mimir apis, ships its own docker container
logs to the local loki, and receives stats pushed by the services on the
host. Log chunks and stats blocks are stored in a single node minio.

```
containers --docker api--> alloy (in bundle) --push--> local loki
services --push /metrics/job/...--> 127.0.0.1:<local_port> --> go front --> local mimir
                                                          |
<env>-grafana.<domain> (lb, tls) --> go front (basic auth from vault grafana.yml)
       /status | /loki/... | /metrics/job/... | /prometheus/... | /stats | / (grafana ui)
                                                          |
                                loki + mimir rings over the host lan (settings.yml routes)
                                                          |
                                                   minio s3 (loki + mimir buckets)
```

- `warpctl logs <env> <service>` queries loki through the lb (`--source=cloudwatch` still reads cloudwatch).
- Services publish stats with the prometheus client push package to the local
  publish port (`local_port` in grafana.yml) every 15s, keyed by
  {env, service, block, host} (see server/grafana.go in the server repo).
  The go front stamps the receive time and forwards to mimir as remote write
  (see push.go), so series go stale when a service stops pushing —
  no pushgateway staleness.
- Default dashboards load with `bringyourctl grafana load-defaults`
  (server repo, urnetwork folder).
- Grafana state (dashboards, users) lives in the env postgres. Loki and mimir
  data lives in minio. Alloy read positions live in the mount_data volume.
  The containers are otherwise stateless and can be redeployed freely: loki
  and mimir flush to minio on stop, and the replication factor covers unclean
  stops.
- `warpctl service run` starts every container with the `local` docker log
  driver (rotated files on the host, `docker logs` works), and the bundled
  alloy ships the logs to loki. Grafana is the only log destination.

## Public dashboards

Dashboards tagged `public` (in the dashboard json `tags`, see server/grafana)
are published as grafana public dashboards — read-only, no login — by
`bringyourctl grafana load-defaults`. The go front serves a directory of them:

- `<env>-grafana.<domain>/stats` — html list linking to each read-only dashboard
- `<env>-grafana.<domain>/stats.json` — json feed (title, uid, accessToken, view
  url, and grafana public data api url per dashboard; `Access-Control-Allow-Origin: *`
  so other sites can consume it)

Each public dashboard is served by grafana at `/public-dashboards/<accessToken>`,
and its data is queryable without login under `/api/public/dashboards/<accessToken>`.
The `/stats` directory is read live from grafana's public dashboards api (admin
credentials from grafana.yml), cached ~30s. Grafana public dashboards do not
support template variables, so public dashboards use fixed queries (no
`$env`/`$service`/... selectors) — they are separate dashboards from the
internal ones.

## One time setup

1. Postgres (hostname from settings.yml `env_vars.BRINGYOUR_POSTGRES_HOSTNAME`),
   with the password from `vault/<env>/grafana.yml`:

    ```sql
    create user grafana with password '<postgres.password>';
    create database grafana owner grafana;
    ```

2. MinIO on the storage host (data under `/data/minio`, port 23900 on the lan ip):

    ```
    cd xops/main/ansible
    ./run-minio.sh
    ```

3. DNS: `<env>-grafana.<domain>` resolves to the lb ips like any exposed
   service. The wildcard tls cert already covers the name.

4. Units: regenerate and install the systemd units
   (`warpctl service create-units <env>`) so the new grafana units exist on
   the hosts, then enable them.

## Deploy

```
warpctl stage version next release --message="grafana"
warpctl build <env> grafana/Makefile
warpctl deploy <env> grafana latest --percent=100
```

## Cloudwatch

Cloudwatch is no longer a log destination: containers switch from the
`awslogs` driver to the `local` driver as they redeploy with the new warpctl.
The history remains readable with `warpctl logs --source=cloudwatch`.
Once all containers have rolled, the aws creds can be removed from the
docker systemd drop-ins on the hosts.

## Notes

- **Topology**: the bundle runs on all lb hosts (plus the `host_services`
  hosts). The loki ring membership follows settings.yml `routes`
  automatically; instances join and leave the ring on deploy. Keep
  `loki.replication_factor` (grafana.yml) at 3 with 3+ hosts.
- **Redeploys**: the single block updates all hosts within the same deploy
  polling window, so restarts overlap rather than roll. The service declares
  ports 80 (go front), 3000 (grafana ui), and 3101 (loki http) in
  services.yml, and warp allocates unique internal ports per deploy for all
  three (WARP_PORTS) — so the old and new containers never collide, with no
  SO_REUSEPORT needed. The go front additionally serves the stable publish
  address `:3100` (all interfaces) with SO_REUSEPORT, so the old and new
  containers both hold it during the overlap, each proxying to its own loki.
  The gossip/grpc ports stay fixed, so the new loki joins the ring only after
  the old container stops — deliberate, since two lokis on one host would
  collide on the ring identity. Alloy (also serialized on its fixed http
  port, protecting its positions file) resumes from the positions volume and
  backfills any gap from the docker log files.
- **Ports**: service ports 80/3000/3101/3201 are warp allocated per deploy.
  Loki gossip 23946, loki grpc 23095, mimir gossip 23947, mimir grpc 23096,
  alloy http 23012, minio 23900/23901 are fixed and reserved outside the warp
  `external_ports`/`internal_ports` ranges. The stable publish address is
  `:<local_port>` from grafana.yml (default 3100), bound on all interfaces —
  on-host services publish to `127.0.0.1:<local_port>`, and hosts that don't
  run grafana (e.g. fluent-bit on the db/redis/subtensor hosts, via the
  main-grafana.local /etc/hosts alias) publish to a grafana host's lan ip.
  It is unauthenticated; the wan is firewalled. If the warp port ranges ever
  grow, keep the fixed ports out of them.
- **Ingest limits**: the bundle raises loki defaults (16MB/s per tenant,
  5MB/s per stream, 20000 entries per query page). Tune in `grafana/main.go`.
- **Retention and storage caps**: `loki.retention` in grafana.yml (default
  744h = 31 days) is enforced by the loki compactor, and
  `mimir.retention` (default 2160h) by the mimir compactor — retention is
  time based (loki and mimir have no size based retention).
  `loki.max_storage` / `mimir.max_storage` in grafana.yml set hard minio
  bucket quotas as a disk backstop, applied by `run-minio.sh` (rerun it after
  changing them). When a quota is reached minio rejects new writes and
  ingestion degrades until retention frees space — so size retention to stay
  well below the quota. MinIO holds a single copy: back up `/data/minio` if
  history matters.
- **Loki push limits**: pushes older than 168h are rejected, and out of order
  entries are accepted within ~1h per stream. A host that was down for longer
  backfills what fits these windows.
- **Metrics later**: the bundled alloy is the natural place for prometheus
  collection (prometheus.exporter.unix / cadvisor + remote_write) when a
  metrics store is added.
