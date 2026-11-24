# The sidecar's service blocks

These are the blocks DESIGN.md §19.4 adds to `vault/<env>/services.yml`, written as fragments, since nobody who
builds them may read the vault (plan-OPS-vault-blocks, QD-574). Each fragment is checked where it is written,
by `sidecar_blocks_test.go`, against a synthetic base through warp's own loader, and the owner merges it into
the vault's file with `sidecarctl services apply-fragment` (server/sidecarctl/cmd_services_apply_fragment.go),
which runs the same merge on the real file.

| Fragment | What it adds | Milestone |
|---|---|---|
| `evs.yml` | the evs service, `evs.bringyour.com`, allowing the key origin's page Worker, and its own gate bearer for its Quota, `internal-gate-evs.yml` | M2, M4 |
| `gkm.yml` | the gkm service, `gkm.bringyour.com`, allowing the key origin's page Worker, and its own gate bearer for its Quota, `internal-gate-gkm.yml` | M2, M4 |
| `api.yml` | api's first-cluster credentials, W8's path-only access log, the key origin among its `cors_origins`, `monitor.yml` for §21.8's notice pager, `internal_routes` keeping `/internal/gate/` to the site's ranges (W8), and gkm's url, `UR_GKM_URL`, for the report intake's seal key | M2, M4, M5 |
| `taskworker.yml` | taskworker's every-cluster credentials, the push sender's APNs and FCM keys, `wake-vendors.yml`, the mail breakers' Postmaster Tools and SNDS credentials, `abuse-postmaster-tools.yml` and `abuse-snds.yml`, and `monitor.yml` for §21.8's notice pager | M2, M5, M8, M9 |
| `mmm.yml` | W10's `recurd.dev` and `www.recurd.dev`, which mmm forwards to https://ur.io/recurd, and the key origin `sidecar.ur.io`, as mmm's names; `recurd.dev` in `domains`; `sidecar.ur.io` in the dns block's `unproxied` and in `no_frame_options` | M4 |
| `sockets.yml` | the sockets service, `sockets.bringyour.com`, with W2's per-address zones for registration and Find | M5 |
| `dns.yml` | the dns API, `dns.bringyour.com`, holding Postgres and Redis, the DNSKEY windows, a read-only core API projection credential, vault's `services.yml`, and `internal_routes` keeping `/dns/internal/` to the site's ranges and the off-site monitor (W8) | M5 |
| `dnsedge.yml` | the two dns edges, `dnsedge-1` on ns1 and `dnsedge-2` on ns2, each a transparent interface of its own host, UDP and TCP 53, and the ZSK | M5 |
| `tlsedge.yml` | tlsedge on every lb host, its four stream ports, and 8443, 8883 and 5671 unsplit on every interface (W7) | M5 |
| `mxedge-platform.yml` | mxedge's platform listener on `rpt.bringyour.com`'s two hosts, TCP 25 on their two interfaces (W4), the platform-mail key, and its own gate bearer for role mail's notices and the report intake's seal keys, `internal-gate-mxedge-platform.yml` | M5 |
| `alt.yml` | gkm's url, `UR_GKM_URL`, in alt's environment, as in api's, since alt runs api's installs; nothing else of alt's block, and only in an env that runs alt | M5 |
| `mxedge.yml` | mxedge's router on every lb host, and TCP 25 on every other interface (W4) | M7 |
| `smtpedge.yml` | smtpedge on the two sending hosts, unexposed, one g1 block, with `cap_net_admin` for its SO_MARK | M9 |
| `mxedge-platform-x-ur-ref.yml` | smtpedge's X-UR-Ref keys, `smtpedge-x-ur-ref.yml`, on the platform listener, for its report intake's attribution and halts | M9 |

The key origin (§18.8) is `https://sidecar.ur.io`. Its page Worker calls api, auth, evs and gkm across origins
with its own token (§18.9's required hosts), so that origin joins api's, evs's and gkm's `cors_origins`.
`auth.bringyour.com` is a name the lb routes to api (server/api/api.go), so api's list covers it; routing that name
to api is the issuer's own rollout (server/IDP.md §12), which no fragment here adds. A service whose
`cors_origins_from` names api takes the origin too.

## Service urls and internal routes

Each block whose binary reads another service is given that service's url in its environment, from its fragment's
`env_vars`, and the binary's flag reads it as its default (server's `sidecarhost.ServiceUrlFlag`), or, where the
process takes no flag for it, the install that uses it reads the variable itself, so a deployed block needs no
argument:

- `UR_API_URL: "https://api.${WARP_DOMAIN}"`, api's internal gate, for dns (signed projection reads), evs and gkm (their Quota), sockets (the
  projection and the over-limit list), tlsedge, mxedge's router and smtpedge (their Quota and edge clients) and the
  platform listener (role mail's notices and the report intake's seal keys); each dns edge's is
  `"https://dns.${WARP_DOMAIN}"`, the dns API block's internal feed;
- `UR_SOCKETS_URL: "https://sockets.${WARP_DOMAIN}"` for tlsedge's and the router's Finds and smtpedge's
  registration;
- `UR_GKM_URL: "https://gkm.${WARP_DOMAIN}"`, gkm's drop-key route, for api, whose report key source reads each
  network's seal key there for the platform listener (server's `controller.SmtpReportKeySource`, read by api's
  projection install as `sidecarhost.GkmUrlEnvName`), and for alt, which runs the same installs
  (`controller.InstallApiRoutes`), from `api.yml` and `alt.yml`. alt's front refuses `/internal/gate/`, the source's
  one route, so alt reads gkm for nothing; the url keeps its install api's own, which says nothing of a missing url.

`${WARP_DOMAIN}` is the primary domain warp hands every block as `WARP_DOMAIN`, and `warpctl service create-units`
writes it out when it renders a block's unit, so no fragment holds a production name and each env's blocks call its
own services. Create the units with a warpctl that does: an older one leaves `${WARP_DOMAIN}` in the unit, which
systemd reads as its own variable, unset there, so the url names no host and the block stays not ready.

api's `/internal/gate/` and the dns API's `/dns/internal/` answer only the site's own sources (§8.9, §19.5's W8;
QD-027, QD-680). `api.yml` and `dns.yml` give each service `internal_routes`, and on every name the lb serves it by,
and on the lb hosts' `/by/service/` and `/by/b/` routes, a request under the prefix from a source outside
`allow_subnets` is answered 403 and never reaches the service; the bearers stay each route's own check. The sources
are production ranges no fragment holds, so each is a placeholder the owner fills in, with as many cidr blocks as
it needs:

- `fill-in-site-ipv4-range` and `fill-in-site-ipv6-range`, in both: every range the site's blocks reach the lb
  from, its hosts' LAN and docker networks and the gateways' blocks. Each lb interface's `rate_limit.exclude_subnets`
  must cover the same ranges, or the blocks' gate calls count in the lb's per-address limits, as the edges' Finds
  would.
- `fill-in-monitor-outside-address`, in `dns.yml`: the off-site monitor host's address, a /32 or /128.

Build the lb image with a warpctl that reads `internal_routes`: the loader reads services.yml without refusing a key
it does not know, so an older one builds an lb that refuses neither prefix, the bearers alone guarding the routes as
before, and an `apply-fragment` built before it refuses the two fragments.

## A fragment

A fragment holds `version`, a mapping in a services.yml version's shape. Applying it appends one new version on
top of the file's versions, as warp's README asks of every change: a copy of the current top version with the
fragment merged in. A fragment only adds:

- a key the top version lacks is added whole, so a new service arrives as its whole block;
- a mapping the top version has is merged key by key;
- `secret_files`, `cors_origins` and `expose_aliases` gain the entries the fragment lists, and `secret_files`
  stays sorted;
- anything else the fragment names must already be what the fragment says, or the fragment is refused.

Beside `version`, a fragment may add three things warp keeps outside its versions, so they add no version:

- `domains`, a mapping of registrar domains to their registrars. A domain the file has must have the registrar
  the fragment gives, and the registrar must be `route53` or `cloudflare`, the two `warpctl certs issue` and
  `warpctl dns` know. Anything else is refused when the fragment is applied: that is how a placeholder the owner
  has not yet filled in stops the merge.
- `dns: {unproxied: [...]}`, exact names a registrar that proxies must never proxy. On cloudflare `warpctl dns`
  refuses to plan or sync a domain while it proxies one of them, whether or not it derives the name (QD-012).
- `no_frame_options: [...]`, exact hosts to whose responses the lb adds no `X-Frame-Options`, which it adds as
  `SAMEORIGIN` to every other host's; each keeps the lb's other security headers. `warpctl lb create-config`,
  which the lb image's build runs, refuses while one names a host the lb does not serve, as it refuses for
  `no_access_log` (QD-678).

Each goes in as the first entry of the file's `domains` mapping, `unproxied` list or `no_frame_options` list, or,
when the file has none, as a block of its own just above `versions`.

A value only the owner knows, a production host's name, interface, router, router port, docker network or address,
is written in a fragment's version as a placeholder beginning `fill-in-`, as a key or as a value.
`sidecar_blocks_test.go` fills each with a synthetic value before it checks the fragment, and `apply-fragment`
refuses a fragment that still holds one, naming its line, so the owner fills every one in first. `api.yml`,
`dns.yml`, `dnsedge.yml`, `mxedge-platform.yml` and `smtpedge.yml` hold them.

The merged file must pass every check warp's loader makes, everything outside its versions must decode as before
but for these additions, and warp's allocator must give every port block the file already had exactly the ports
it had (warp/README.md's RULES). Otherwise nothing is written. A fragment applied twice adds nothing the second
time, and then no version is added.

## New blocks

Every new block follows §19.4 and D-OPS-1:

- `beta: 1` and `g1: 99` on every lb host, unless its row says otherwise;
- `mount: {vault: no, config: yes, site: no}` and `user: "65532:65532"`;
- `env_vars: {WARP_VAULT_HOME: /srv/warp/secrets}`, where warp mounts `secret_files`, so the server's vault reader
  finds them (plan-OPS-small-readings #4), and beside it the service urls the block's binary reads, `UR_API_URL` and
  `UR_SOCKETS_URL` (above);
- sorted `secret_files`, naming only the block's own secrets: its audience's public JWKS (`oauth-jwks-svc.json`),
  never a signing key (`auth.yml`, `jwt.yml`) and never `grafana.yml`, whose push-only replacement is
  `grafana-push-<service>.yml` (QD-249);
- `log_uri: true` on every lb service, so the lb logs its paths and never its query strings (W8);
- `cap_net_admin: true` on smtpedge alone, which warp grants to it and proxy and refuses every other service, in
  its loader and again at run (plan-OPS-small-readings #14); its image sets the capability on the binary, since the
  block runs as 65532;
- a Postgres role only where the block reads or writes rows, at most one: the platform's `pg.yml` for dns and the
  platform listener; for tlsedge and mxedge's router, a restricted role in a vault file of their own
  (`pg-tlsedge.yml`, `pg-mxedge.yml`, QD-029), which server's pool reads in place of `pg.yml` (QD-992), each a
  role the owner makes with QD-029's grants alone; smtpedge the same way, `pg-smtpedge.yml`, a role for `smtp_*`,
  the halt rule's reads and the abuse gate's;
- the ZSK (`dns-zsk.private`) on the two dns edges alone, and the platform-mail certificate and key
  (`platform-mail.pem`, `platform-mail.key`) on the platform listener alone (§12.6, §19.4, mx-4); never `auth.yml`,
  which holds the issuer's signing keys: sockets verifies its callers' service tokens with `oauth-jwks-svc.json`, as
  evs, gkm and dns do (QD-1029).

## Applying them

Before a fragment is applied, every file its `secret_files` names must be in the vault, since warp refuses to
start a block whose scoped secret is missing, and the edges playbook must have run, which makes each such file
65532:65532 mode 0400 (xops/main/ansible/playbook-edges.yml), or the block cannot read it. The file clusters'
users are made from the same `file-clusters-<service>.yml` files (xops/main/ansible/FILE-CLUSTERS.md).

`evs.yml` and `gkm.yml` name `internal-gate-evs.yml` and `internal-gate-gkm.yml`, each block's own internal gate
bearer, on which its binary reads its Quota from api's `/internal/gate/` (server's `quotahost.NewBlockQuota` on the
classes `evs` and `gkm`; §19.4's gate paragraph, QD-055, QD-1142). No other block mounts either. The owner draws them
at M2, before the two fragments are applied, with `sidecarctl internal bearer-keygen --class=evs` and `--class=gkm`,
each into its own `--out` and api's one verify file, as for every class (QD-1102; the gate bearers, below), and
deploys api with that verify file before evs and gkm. A block that cannot read its bearer, or reads no api url, has
no Quota: evs then stays not ready, and gkm weighs every network's writes as Community's.

`taskworker.yml` names `wake-vendors.yml` from M8, the push sender's keys (server/taskworker/wake_sender.go): under
`apns`, `endpoint`, `topic`, `team_id`, `key_id` and the `.p8` key in PEM as `private_key`; under `fcm`, `endpoint`
and the project's service account JSON as `service_account`. Each section may be absent, and a file naming neither
vendor starts no sender, so until the APNs and FCM accounts exist the file can hold `{}`, which keeps taskworker
starting once the fragment is applied. taskworker keeps its own mounts, so the edges playbook does not restrict it.

From M9 it also names the mail breakers' credentials (§21.5, §21.16; owner decision 611), which taskworker reads at
start to build the breakers' outside measures: `abuse-postmaster-tools.yml`, the Postmaster Tools service account's
`client_id`, `client_secret` and `refresh_token` (server/mail_measures_postmaster.go), and `abuse-snds.yml`, SNDS's
automated data access key as `key` (server/mail_measures_snds.go). The two accounts are the owner's to create
(§23.7). Until one exists its file can hold `{}`, which keeps taskworker starting: taskworker says once that the
credential is not usable, and that measure stays unknown, which holds the breakers. The fragment names no copy of the
listing feed's mirror for taskworker's `--feed_dir`, since no pull sets one up on any host yet and mxedge's router
names none either, so the breakers' listing stays unknown until the feed's pull lands with a copy on taskworker's
host.

From M5 `api.yml` and `taskworker.yml` both name `monitor.yml`, the monitor's own file, already in the vault: each
process reads `alerts.pager_webhook_url` from it at start and installs a retrying sink over that webhook for §21.8's
registrar, registry and law-enforcement notices (server's `controller.InstallAbuseNoticePager`; QD-1070, owner
decision 612). api pages a notice from the process that committed its case, a staff member's `file_notice` or a role
mail the platform listener sends it, and taskworker's clock pass pages again each minute a notice whose page was left
owed. A file whose webhook cannot be used installs no pager and says so: every notice's case still opens, and its page
stays owed until a process has a pager. These are two more readers of the pager's credential, beside the monitor.

`mxedge-platform.yml` names `internal-gate-mxedge-platform.yml`, the platform listener's own internal gate bearer,
256 random bits as `current` and, during a rotation, `previous`, on which its role-mail intake files each role
mail's notice at api's `/internal/gate/abuse-notice` (QD-1070, owner decision 612; QD-1121) and its report intake
reads the key it seals each network's reports to at api's `/internal/gate/report-key/<network_id>`
(plan-SMTP-report-seal-key, QD-075), which api reads from gkm at `UR_GKM_URL` (above). It is a class of its own,
`mxedge-platform`, which only those two routes take, and api's verify file holds its SHA-256 under that class; the
owner draws both with `sidecarctl internal bearer-keygen --class=mxedge-platform --out=<file> --verify=<file>`, as
for every class (QD-1102). Until the file is in the vault the
fragment cannot be applied, since warp refuses to start a block whose scoped secret is missing; a listener with no
bearer, or no `-api_url`, files no notice and answers role mail as before, and seals no report, dropping each one's
raw bytes unread and keeping its fields. With both, a network's report is sealed only where api's source reads gkm:
an api with no `UR_GKM_URL` answers every network with no key.

```
sidecarctl services apply-fragment <env> warp/services/sidecar-blocks/evs.yml warp/services/sidecar-blocks/gkm.yml \
    warp/services/sidecar-blocks/api.yml warp/services/sidecar-blocks/taskworker.yml --out=<new services.yml>
```

M5's fragments go in the same way, `mxedge-platform.yml` before M7's `mxedge.yml`, since the router's lb-wide TCP 25
leaves only the interfaces that already name the platform listener to it. Before applying them:

- **The dns edges.** Fill in `dnsedge.yml` with ns1's and ns2's host names, their transparent interfaces, the
  routers and router ports they are plugged into, their docker networks and their addresses on gateway-1's and
  gateway-2's HE blocks, and set up the hosts (xops/main/ansible/DNS-EDGES.md). Their files are not on the lb
  hosts: the dns edges play copies each host its own.
- **The report host.** Fill in `mxedge-platform.yml` with the two hosts that carry `rpt.bringyour.com`'s two
  interfaces (W11, OPS-M5-02) and those interfaces' names.
- **The vault files.** sockets: `socket-ticket-keys.yml` (§9.8; QD-902's `sidecarctl sockets ticket-keygen`, not
  built yet, writes it), `internal-gate-sockets.yml`, `oauth-jwks-svc.json` and `file-clusters-sockets.yml` (its
  MinIO user on the first metadata cluster, reading rev/ alone, which xops/main/ansible/FILE-CLUSTERS.md's playbook
  makes); dns: `internal-gate-dns.yml` for signed projection reads, `internal-verify.yml` with the dns edges' and monitors' bearer digests, and
  `dns-key-windows-ur.network.json` from the first key ceremony; tlsedge and the router:
  `internal-gate-tlsedge.yml`, `internal-gate-mxedge.yml` and `internal-gate-edge.yml` (QD-812); the platform
  listener: `platform-mail.pem`, `platform-mail.key` and its own `internal-gate-mxedge-platform.yml` (QD-1121),
  with its digest in api's verify file; each service's `grafana-push-<service>.yml`; and the restricted roles,
  `pg-tlsedge.yml` and `pg-mxedge.yml`.
- **The gate bearers.** Each class's bearer file, `internal-gate-<class>.yml`, and api's verify file,
  `internal-gate-verify.yml` (server/internal_gate.go's `InternalGateVerifyFileName`, not the dns API's
  `internal-verify.yml`), are drawn together by `sidecarctl internal bearer-keygen --class=<class> --out=<file>
  --verify=<file>` (QD-1102): `--out` the class's file, `--verify` api's, the same verify file each time, so it
  gathers every class's digest. Run it at M2 for `evs` and `gkm` (`sidecarctl internal bearer-keygen --class=evs`,
  `--class=gkm`; above), here for `dns`, `sockets`, `tlsedge`, `mxedge`, `edge` and `mxedge-platform`, and at M9 for
  `smtpedge`. A rotation is the same command over the two files the vault holds. api is deployed with the new verify
  file before the blocks with the new bearers.
- **The edges' own Finds.** W2 exempts the edges' Finds from sockets' per-address zones through each lb
  interface's `rate_limit.exclude_subnets`, which name production ranges no fragment holds: each interface's list
  must cover the addresses the edge blocks reach sockets from.
- **gkm's url.** `api.yml` gives api `UR_GKM_URL` from M5; applied again over a file that holds its earlier parts,
  it adds only what the file lacks, the variable among them. Apply `alt.yml` with them only in an env whose
  services.yml runs alt (the proxy hosts' block): its change must read `services.alt.env_vars`, or
  `services.alt.env_vars.UR_GKM_URL` where alt's block already sets variables. One that reads `services.alt` alone
  means the env runs no alt, and that output is not moved into the vault: run the command again without `alt.yml`.

It reads `<vault>/<env>/services.yml` from the vault warpctl uses, prints what each fragment adds and the ports
the new version assigns, and writes the merged file to `--out`, which must not exist. The owner reviews it and
moves it into the vault.

A service joins `staged_services` or `single_pass_services` in build/all/deploy-rollout.zsh with its fragment and
its image (plan-OPS-small-readings #12), on the `sidecar` branches. `warpctl deploy` stops on a service with no
blocks, so each fragment in this directory must be applied to the vault before those branches merge to `main`, or
the first release from `main` stops at that service. That step is the owner's, and each gate reports it open.

## smtpedge.yml, at M9

`smtpedge.yml` goes in once HE's outbound TCP 25 and reverse delegation are in hand (§14.9's prerequisites). Before
applying it:

- **The two sending hosts.** Fill in `fill-in-smtp-host-1` and `fill-in-smtp-host-2` with the lb hosts the edge
  sends from.
- **`config/<env>/smtpedge.yml`.** Its `sending_addresses` list each sending address, an lb interface's IPv4
  address on one of those hosts, with its HELO name under `helo_domain` (`o<k>.out.bringyour.com`) and its fwmark.
  warp gives the block one mark, the routing table of its host's first lb interface by name, which a sending
  address of fwmark 0 takes; an address on another lb interface of the host names that interface's routing table
  (`warpctl service routing-tables <env>`). warp reads the same list twice more and refuses an address that is no
  lb interface's or is on a host that does not run the edge:
  - `warpctl vyos` renders W7's rule on our gateways' isp link and every edge router's WAN link: forwarded TCP 25
    leaves from those addresses and from no other source, IPv6 carries none, and nothing else leaving changes. An
    env with no `smtpedge.yml` renders no such rule, so a router changes only once the file exists; one whose file
    lists no address drops all outbound mail. Lan routers are not touched.
  - `warpctl dns plan` and `sync` publish each HELO name's A record, that address alone (W11), on route53, as the
    dns block's `records` are published.
- **The reverse zone.** Each address's PTR must name its HELO name, which §12's reverse zones serve; no address
  sends until its PTR and A record agree, which the edge checks itself (FCrDNS).
- **The vault files.** `internal-gate-smtpedge.yml` (`sidecarctl internal bearer-keygen --class=smtpedge`, its digest
  in api's `internal-gate-verify.yml`) and `internal-gate-edge.yml` (QD-812), `smtpedge-x-ur-ref.yml`
  (`issue_key_id` and `keys`, each an `id` from 1 to 255 and a base64 `key`), `grafana-push-smtpedge.yml`,
  `redis.yml` and `pg-smtpedge.yml`, the block's own Postgres role.
- **The image.** docker's `--cap-add` reaches no process that is not root, so `server/cli/smtpedge`'s image must set
  `cap_net_admin` on its binary; without it SO_MARK fails at the first dial from an address that names a mark.

Apply `mxedge-platform-x-ur-ref.yml` with it. It mounts the same `smtpedge-x-ur-ref.yml` on the platform listener
(server's `model.SmtpXUrRefKeyFileName`), whose report intake, in a binary that links MG9, attributes a feedback
loop's report or a role mail to the network whose send it names (SMTP-M9-15) and runs each attributed complaint
through §14.8's halt rule (SMTP-M9-16): the halts reach every smtpedge at its next reload and §21's mail pass in
taskworker, and an attributed role mail opens §21's case. The attribution verifies each X-UR-Ref under these keys,
and without them drops every report that carries one, so a listener that cannot read the file attributes nothing and
says so at start. The ladder reads tiers through the block's own `pg.yml`, so it needs no route of api's internal
gate. The listener holds the keys from M9, when they first exist and it first has a send log to join against, and
not from M5, when it has none.

smtpedge deploys in one pass (`single_pass_services` in build/all/deploy-rollout.zsh, D-OPS-11) and stays dark
behind `config/<env>/sidecar.yml`'s smtpedge gate until D-SMTP-16 passes.

## mmm.yml, in order

`mmm.yml` carries `recurd.dev: fill-in-route53-or-cloudflare`. The registrar is whichever of `route53` and
`cloudflare` holds recurd.dev's zone, which only the owner knows, since it decides which DNS provider
`warpctl certs issue` asks for the certificate's DNS-01 records and `warpctl dns` publishes to. Replace the
placeholder before applying; `apply-fragment` refuses it otherwise and names the line. `ur.io: cloudflare` is listed
as QD-012 has it: the merge adds nothing when the file has it so, and refuses another registrar.

Then, in this order:

1. Apply `mmm.yml` with the others, review, and move the result into the vault.
2. `warpctl certs issue <env>` for W5's certificates: recurd.dev's own Let's Encrypt set, with `www.recurd.dev`,
   `<env>-lb.recurd.dev` and every `<env>-<service>.recurd.dev`, and `sidecar.ur.io` with ur.io's names. The lb image
   reads a certificate for every name it serves when it is built, and refuses one it finds none for, but for a name
   with more labels than its domain it falls back to the domain's certificate without checking the name is on it,
   so issue before the lb image is built.
3. Deploy the certificates, then `warpctl dns plan <env>` and `warpctl dns sync <env>`. `warpctl dns` publishes a
   domain other than the primary only for the services the dns block lists in `other_domain_services`, so recurd.dev's
   names and `sidecar.ur.io` are published from there only if mmm is listed; otherwise they are made by hand, and
   `sidecar.ur.io` unproxied either way. A plan of ur.io refuses while Cloudflare proxies `sidecar.ur.io`.
4. Build and deploy the lb with a warpctl that reads `no_frame_options` (below), then mmm with W10's block
   (mmm/mmm/nginx/nginx.conf.j2). Until mmm's block is deployed, mmm answers recurd.dev with its default server,
   which serves only `/status`.

The lb adds `X-Frame-Options: SAMEORIGIN` to every response of every service host but those `no_frame_options`
lists, and `mmm.yml` lists `sidecar.ur.io` there (QD-678), so the key origin's framing rests on mmm's
`frame-ancestors https://ur.io` alone, as the design asks, while ur.io and every other name keep the header. The
loader reads services.yml without refusing a key it does not know, so a warpctl older than `no_frame_options`
builds an lb that sends the key origin `SAMEORIGIN`, which forbids ur.io's frame wherever a browser honors it over
`frame-ancestors`. `apply-fragment` built before it refuses `mmm.yml` instead.
