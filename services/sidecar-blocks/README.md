# The sidecar's service blocks

These are the blocks DESIGN.md §19.4 adds to `vault/<env>/services.yml`, written as fragments, since nobody who
builds them may read the vault (plan-OPS-vault-blocks, QD-574). Each fragment is checked where it is written,
by `sidecar_blocks_test.go`, against a synthetic base through warp's own loader, and the owner merges it into
the vault's file with `sidecarctl services apply-fragment` (server/sidecarctl/cmd_services_apply_fragment.go),
which runs the same merge on the real file.

| Fragment | What it adds | Milestone |
|---|---|---|
| `evs.yml` | the evs service, `evs.bringyour.com`, allowing the key origin's page Worker | M2, M4 |
| `gkm.yml` | the gkm service, `gkm.bringyour.com`, allowing the key origin's page Worker | M2, M4 |
| `api.yml` | api's first-cluster credentials, W8's path-only access log, and the key origin among its `cors_origins` | M2, M4 |
| `taskworker.yml` | taskworker's every-cluster credentials | M2 |
| `mmm.yml` | W10's `recurd.dev` and `www.recurd.dev`, which mmm forwards to https://ur.io/recurd, and the key origin `sidecar.ur.io`, as mmm's names; `recurd.dev` in `domains`; `sidecar.ur.io` in the dns block's `unproxied` and in `no_frame_options` | M4 |

Later milestones add sockets, dns and the dns edges, tlsedge, mxedge and its platform listener, and smtpedge
here, each with its own task.

The key origin (§18.8) is `https://sidecar.ur.io`. Its page Worker calls api, auth, evs and gkm across origins
with its own token (§18.9's required hosts), so that origin joins api's, evs's and gkm's `cors_origins`.
`auth.bringyour.com` is a name the lb routes to api (server/api/api.go), so api's list covers it; routing that name
to api is the issuer's own rollout (server/IDP.md §12), which no fragment here adds. A service whose
`cors_origins_from` names api takes the origin too.

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

The merged file must pass every check warp's loader makes, everything outside its versions must decode as before
but for these additions, and warp's allocator must give every port block the file already had exactly the ports
it had (warp/README.md's RULES). Otherwise nothing is written. A fragment applied twice adds nothing the second
time, and then no version is added.

## New blocks

Every new block follows §19.4 and D-OPS-1:

- `beta: 1` and `g1: 99` on every lb host, unless its row says otherwise;
- `mount: {vault: no, config: yes, site: no}` and `user: "65532:65532"`;
- `env_vars: {WARP_VAULT_HOME: /srv/warp/secrets}`, where warp mounts `secret_files`, so the server's vault reader
  finds them (plan-OPS-small-readings #4);
- sorted `secret_files`, naming only the block's own secrets: its audience's public JWKS (`oauth-jwks-svc.json`),
  never a signing key (`auth.yml`, `jwt.yml`) and never `grafana.yml`, whose push-only replacement is
  `grafana-push-<service>.yml` (QD-249);
- `log_uri: true` on a service with sidecar routes (W8).

## Applying them

Before a fragment is applied, every file its `secret_files` names must be in the vault, since warp refuses to
start a block whose scoped secret is missing, and the edges playbook must have run, which makes each such file
65532:65532 mode 0400 (xops/main/ansible/playbook-edges.yml), or the block cannot read it. The file clusters'
users are made from the same `file-clusters-<service>.yml` files (xops/main/ansible/FILE-CLUSTERS.md).

```
sidecarctl services apply-fragment <env> warp/services/sidecar-blocks/evs.yml warp/services/sidecar-blocks/gkm.yml \
    warp/services/sidecar-blocks/api.yml warp/services/sidecar-blocks/taskworker.yml --out=<new services.yml>
```

It reads `<vault>/<env>/services.yml` from the vault warpctl uses, prints what each fragment adds and the ports
the new version assigns, and writes the merged file to `--out`, which must not exist. The owner reviews it and
moves it into the vault.

A service joins `staged_services` or `single_pass_services` in build/all/deploy-rollout.zsh with its fragment and
its image (plan-OPS-small-readings #12), on the `sidecar` branches. `warpctl deploy` stops on a service with no
blocks, so each fragment in this directory must be applied to the vault before those branches merge to `main`, or
the first release from `main` stops at that service. That step is the owner's, and each gate reports it open.

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
