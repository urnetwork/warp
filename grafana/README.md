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
- Browse and filter every Loki stream under **Drilldown > Logs**. The
  checksum-pinned Grafana Logs Drilldown plugin is baked into the image,
  provisioned against `warp-loki`, and linked from the `urnetwork / service
  logs` dashboard. Use its **Open in Explore** action whenever a raw LogQL
  query is more useful than point-and-click filtering.
- Alert rules (grafana unified alerting) are file provisioned: the yamls in
  `grafana/alerting/` are embedded in the go front and written to
  `provisioning/alerting/` at container start, so they re-provision on every
  deploy ("urnetwork alerts" folder, read only in the ui — edit the yaml and
  redeploy). Rules carry a `severity` label (`page` | `warn`).
  This includes contract-failure rate rules backed by the bounded
  `urnetwork_connect_contract_failures_total` counter; the corresponding
  application logs are rate-limited exemplars and must not be used to
  reconstruct failure rates.
- Contact points and the notification-policy tree are not file provisioned.
  They live in the env postgres, so they survive redeploys, and stay editable
  in the ui. `bringyourctl grafana reconcile-alerting` (server repo; also run
  by `load-defaults`) writes them through Grafana's provisioning API: the
  `urnetwork-default` contact point, a Slack integration whose webhook is
  vault `monitor.yml` `alerts.slack_webhook_url`, is the default receiver for
  every alert no child route matches. The canonical competition warn/page child
  route uses that same existing main receiver; support@ur.xyz remains the
  competition incident owner in rule labels and operational records, not a
  separately provisioned email transport. Unrelated/manual routes and existing
  contact points, including any historical email contact, remain untouched.
  With an empty webhook it leaves the default receiver alone and warns when
  that receiver has no integrations. `bringyourctl grafana test-alert` sends a
  test notification through Grafana's stored Slack integration. Grafana has no
  `[smtp]`, so an email contact point is not a delivery path. Reconciliation
  refuses an unconfigured native main integration rather than creating a dead
  email destination. Configured routing is not notification-delivery proof;
  any real test notification requires its own explicit operator approval.
- Grafana state (dashboards, users) lives in the env postgres. Loki and mimir
  data lives in minio. Alloy read positions live in the mount_data volume.
  The containers are otherwise stateless and can be redeployed freely: loki
  and mimir flush to minio on stop, and the replication factor covers unclean
  stops.
- **Metrics across redeploys**: a deploy replaces every Mimir ingester at
  once, and each new one starts with an empty head. The TSDB directory stays
  inside the container on purpose: warpctl starts the new container before it
  drains the old one, and Mimir opens the TSDB without a lock file, so a
  shared host path would put two ingesters on one WAL. The old ingesters flush
  their heads to minio on stop. The queriers read every time range from the
  store-gateways as well as from the ingesters (`query_store_after` and
  `ignore_blocks_within` are 0). The flushed history is readable once the
  compactor's next bucket-index update lists it (`cleanup_interval: 5m`),
  within about 10 minutes of the deploy. With Mimir's defaults, the 12 hours
  before each deploy stayed unreadable until they were 12 hours old. A head
  that cannot reach minio when its container stops is lost: history is
  missing for parts of 2026-10-11 and 2026-10-12, when edge-6's full minio
  refused writes.
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

2. MinIO on the storage host (on Main, edge-5: one erasure set over
   `/mnt/blob1/minio` to `/mnt/blob4/minio`, port 23900 on the lan ip):

    ```
    cd xops/main/ansible
    ./run-minio-clusters.sh
    ```

3. DNS: `<env>-grafana.<domain>` resolves to the lb ips like any exposed
   service. The wildcard tls cert already covers the name.

4. Units: regenerate and install the systemd units
   (`warpctl service create-units <env>`) so the new grafana units exist on
   the hosts, then enable them.

## Deploy

On Main, the Go front reads `api_key` from the scoped runtime mount
`vault/main/carto.yml` and configures Grafana's default Geomap baselayer as
CARTO XYZ tiles. The key is not part of the image or ordinary config. Stage
`carto.yml` on every Grafana host and install the `services.yml` unit changes
that mount it **before** deploying a Grafana image with this feature; Main
fails startup if the scoped file or key is absent. Other environments retain
their existing baselayer. Tile requests run in the viewer's browser, so this
is a browser-visible map key: restrict it to the Grafana domains and an
appropriate CARTO quota, not a server-only credential.

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
  `:<local_port>` from grafana.yml (default 3100), bound only to loopback, the
  host's LAN route, and exact `publish_routes` addresses — on-host services
  publish to `127.0.0.1:<local_port>`, local infrastructure publishes to a
  Grafana host's LAN IP, and offsite infrastructure such as Planetoid uses its
  VPN IP. Push routes require a configured service credential on every bind;
  query routes remain loopback-only. If the warp port ranges ever grow, keep
  the fixed ports out of them.
- **Ingest limits**: the bundle raises loki defaults (16MB/s per tenant,
  5MB/s per stream, 20000 entries per query page). Tune in `grafana/main.go`.
  `mimir.max_global_series_per_user` in `grafana.yml` sets the in-memory
  series admission limit per tenant across the cluster, before replication.
  Omit it to keep Mimir's default, or explicitly set `0` to disable the limit.
  Main sets it to 2,000,000; with six writable ingesters and replication factor
  3 this corresponds to 1,000,000 series per ingester. Higher actual series
  counts consume more ingester memory; check host headroom during rollout.
  `mimir.ingestion_rate` (samples/s, default 10000) and
  `mimir.ingestion_burst_size` (default 200000) set the tenant's distributor
  token bucket. Each distributor admits the rate divided by the healthy
  distributors, and publishers reach the distributor co-located with their
  front, so size the rate for the busiest distributor plus a rollout overlap,
  not for the fleet sum. Requests over it are discarded as `rate_limited`.
  The burst applies whole on each distributor and must be at least the rate
  (Mimir's burst factor is likewise at least 1); the render fails otherwise,
  counting Mimir's default for an omitted setting. Main sets 64000 samples/s
  (10667/s per distributor across six) with a 1,280,000 burst, Mimir's default
  20 s burst-to-rate proportion. The rate and the series limit take effect
  only when the children restart, so redeploy the grafana block after a
  config push.
- **Retention and storage caps**: `loki.retention` in grafana.yml (default
  744h = 31 days) is enforced by the loki compactor, and
  `mimir.retention` (default 2160h) by the mimir compactor — retention is
  time based (loki and mimir have no size based retention).
  `loki.max_storage` / `mimir.max_storage` in grafana.yml set hard minio
  bucket quotas as a disk backstop, applied by `run-minio-clusters.sh` (rerun
  it after changing them). When a quota is reached minio rejects new writes and
  ingestion degrades until retention frees space — so size retention to stay
  well below the quota. MinIO runs on one host: its erasure set survives failed
  drives, not the loss of the host, so back up the buckets if history matters.
- **Loki push limits**: pushes older than 168h are rejected, and out of order
  entries are accepted within ~1h per stream. A host that was down for longer
  backfills what fits these windows.
- **Metrics later**: the bundled alloy is the natural place for prometheus
  collection (prometheus.exporter.unix / cadvisor + remote_write) when a
  metrics store is added.
