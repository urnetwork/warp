# Warpctl router configuration: correctness and resilience review

Reviewed 2026-09-22 UTC. Scope: `warp/warpctl/VYOS.md`, generator/schema/parser/migration code, the Xops rollout driver, and the relevant `server/monitor/SIGNALS.md` contracts. Warp HEAD `4e1fee650d16b01f65c517e372b9a10e9077b1e0`; Xops HEAD `8667ef09f3f6e5be3c16f4b6a1afd1e54115cffb`.

**Recommendation: fix the three P1 findings before broad rollout.** The design usefully centralizes host addressing and public-port ownership, but a clean render or successful management reconnection is not yet a sufficient safety gate. These are source/local-test findings, not evidence that a production router currently has these failures. The design document itself says no migration has been applied and the gateway class has not run on hardware.

This review made no repository, configuration, or router changes. All added controls lived privately under `monitor/`, used synthetic fixtures/fake transports, and were not installed as product tests. Existing monitoring continued separately with the router-migration host exclusions unchanged.

The sound parts are worth retaining: service-port rendering reuses host-side ownership helpers, the WAN IPv6 /64 avoids treating the whole site /48 as on-link, more-specific host/port routes sit above blackhole aggregates, and migration commands are quoted and checked before commit. The existing golden/round-trip tests cover those structural contracts. None substitutes for the failure-boundary controls below.

## Findings, highest priority first

### 1. P1 — Gateway IPv6 filtering drops valid neighbor discovery

At [vyos.go:652](/Users/brien/urnetwork/warp/warpctl/vyos.go:652), `WANv6_LOCAL` installs the bogon drop as rule 5 before ICMPv6 admission at rule 32. The source group includes both link-local `fe80::/10` and unspecified `::/128` ([vyos.go:554](/Users/brien/urnetwork/warp/warpctl/vyos.go:554)). This local chain is attached to the ISP Ethernet interface that holds the point-to-point IPv6 addresses.

A valid link-local-source Neighbor Solicitation/Advertisement, or an unspecified-source DAD solicitation, therefore matches the drop before the intended ICMP exception. The static default route does not eliminate Ethernet neighbor resolution. This can break neighbor establishment/recovery while the generated route looks correct.

Lower-numbered rules take precedence in [EdgeOS](https://help.uisp.com/hc/en-us/articles/22591212348695-EdgeRouter-Reordering-Firewall-and-NAT-Rules). The needed local traffic is described by [RFC4861](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.3) and [RFC4890 §4.4.1](https://www.rfc-editor.org/rfc/rfc4890.html#section-4.4.1).

Correction: narrowly admit valid local ND/DAD before the local bogon rule; retain transit bogon protection, default deny, and echo limits. Test valid and invalid ND packet conditions, not only the generated rule list. Hardware acceptance must include cold neighbor establishment and later re-resolution, plus PMTU.

Qualification: this is a source-proven policy defect, not an observed hardware failure. Not every peer uses a link-local source for every exchange. RA rejection alone would not prove this statically routed gateway fails; ND/DAD establishes the defect.

### 2. P1 — Interrupted upload destroys the default boot recovery file

[run-routers.sh:425](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:425) streams directly into `/config/config.boot`. Opening that path truncates the old file before transfer completes. A disconnect can leave a partial file, and the subsequent failure path does not restore it.

The synthetic driver control reproduced an upload failure after partial writing: running configuration had changed, the default boot file was truncated, and the driver exited 1. The old copy survived in `/config/bak`, but an ordinary reboot does not select that backup. This undermines the documented reboot recovery path.

Correction: upload into a new file on the same filesystem, verify complete bytes and admissibility, then atomically rename it over the boot path. Keep the previous boot file intact for every failure before promotion. Retain interrupted-upload and verification-failure tests.

### 3. P1 — Migration and verification can use different desired settings from the saved file

[run-routers.sh:262](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:262) renders all boot files once. Later calls at [line 286](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:286) invoke `create-migration` afresh. Each invocation reloads settings through [vyos_cmd.go:261](/Users/brien/urnetwork/warp/warpctl/vyos_cmd.go:261) and generates desired configuration again at line 301. Finally the driver saves the original boot file.

If inputs change from A to B between these calls, runtime B can be applied and verified against B while boot file A is installed successfully. A reboot then restores a different configuration from the one verified. The actual shell driver reproduced this sequence with fake generator/transport boundaries and returned success.

Correction: bind apply, verification, and saving to the exact desired snapshot already rendered for that router. This does **not** require rejecting dirty checkouts or changing the build workflow; local checkout changes remain supported. Add an A/B mutation regression proving the three phases cannot diverge.

Qualification: the local control exercised the real driver and fake command boundaries. The real Go generator's reload behavior is separately established by source inspection; no live router was changed.

### 4. P2 — Conflicting address ownership passes validation and full generation

[routers.go:372](/Users/brien/urnetwork/warp/services/routers.go:372) checks parsing and subnet membership, but not all reserved addresses or ownership conflicts. Rendering then unconditionally creates host /32 routes at [vyos.go:829](/Users/brien/urnetwork/warp/warpctl/vyos.go:829).

Eleven synthetic full-loader/full-generator cases produced one healthy pass and ten failures of the intended rejection assertion:

- host IPv4 at network, broadcast, ISP gateway, own-router WAN, or sibling-router WAN;
- duplicate host IPv4 on different ports of one router or across routers;
- host IPv6 equal to the port router's `::1`;
- duplicate router WAN IPv4;
- two differently named routers deriving the same WAN IPv6 and routed /56 from the same final name digits.

For example, accepting the ISP gateway as a host creates a more-specific route for that upstream identity down a host port. Validate ownership across the relevant gateway/routing domain before rendering. Keep legitimate separate address domains and valid derivation unchanged. No current inventory collision is claimed.

### 5. P2 — LAN agreement validation silently ignores later hosts

[settings.go:73](/Users/brien/urnetwork/warp/services/settings.go:73) assumes every host's route map is an identical YAML alias and stops at the first nonempty map. That premise is not enforced. Consequently [vyos.go:928](/Users/brien/urnetwork/warp/warpctl/vyos.go:928) cannot compare later route claims with `lan_hosts`.

A deterministic control showed that a conflicting in-LAN mapping is rejected when placed in the first host's settings, but accepted when placed in a later host's settings. Agreement and outside-LAN override controls passed.

Correction: validate every relevant per-host in-LAN route claim. Preserve intentional outside-LAN overrides rather than requiring every map to be globally identical. This directly relates to the stale LAN identities described in SIGNALS §11.17a and §11.20b.

### 6. P2 — Nonzero status is incorrectly reported as proof that nothing committed

[run-routers.sh:395](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:395) reports every nonzero migration status as “failed before commit; the router is unchanged.” But [migrate.go:351](/Users/brien/urnetwork/warp/vyos/migrate.go:351) can commit successfully before the final `configure_exit` fails or the process is interrupted.

The fake-transport control applied the new running configuration, then returned a post-commit error. The driver still claimed unchanged state and removed the remote diagnostic files. Printed output survived in the private control transcript, but the remote evidence was gone.

Correction: distinguish pre-commit failure from committed/uncertain state. Preserve phase evidence and inspect current running state before making an unchanged/rollback claim. Keep the post-commit-failure regression. This does not claim a specific EdgeOS commit-atomicity failure.

### 7. P2 — The migration wait is not a reliable wall-clock bound

[run-routers.sh:98](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:98) accepts a zero polling interval. [The wait loop](/Users/brien/urnetwork/xops/main/ansible/run-routers.sh:305) increments its elapsed counter only by that interval, so zero polling with a positive wait and a permanently missing status never reaches the deadline. With normal settings, SSH duration is also excluded from the advertised wait.

Correction: require a positive polling interval and use an actual elapsed-time deadline that includes transport duration. Add a bounded fake-clock/status-unavailable test. This finding is source-proven; no deliberately unbounded process was launched.

## Additional hardening and documentation items

- Gateway validation returns early at [routers.go:94](/Users/brien/urnetwork/warp/services/routers.go:94), bypassing nameserver, conntrack-size/hash, and offload-dependency checks applied to other classes. The shared renderer still emits these fields. Move shared checks onto the shared validation path. This is source review, not a hardware admission test.
- Rule allocation uses `100 + 10*n` without reserving/limiting ranges. Enough custom DNAT entries can reuse NAT rule 5000, and enough host rules can reuse firewall rule 9000, merging nodes rather than rejecting the configuration. Add explicit capacity/range checks and boundary controls before relying on larger inventories. No deployed inventory or hardware failure is claimed.
- Generic protected-path checking tests only descendant deletions, not deletion of a protected path's ancestor. The renderer normally retains the relevant parent trees, so generic API weakness alone is not proof of a reachable current rollout failure. Changing the uplink also requires examining the live management path; the current protected uplink is chosen from desired settings.
- Masked live secrets are treated as equal to any single desired value. Such a comparison cannot establish credential equality. Keep unknown credential comparison distinct from verified convergence, especially before replacing a complete saved configuration. This review did not establish that the live capture used by this driver masks a currently differing value.
- [VYOS.md:704](/Users/brien/urnetwork/warp/warpctl/VYOS.md:704) promises no additional IPv4 traceroute hop. Proxy-ARP routing is still Layer 3 forwarding, for which TTL decreases; a missing ICMP response can hide a hop, not prove bridge-like transparency. Correct the acceptance criterion. See [RFC1812 §5.3.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.1).
- SIGNALS §16.6 describes the Connect UDP/53 alias as IPv4-only. Current [host rule generation](/Users/brien/urnetwork/warp/warpctl/run.go:2954) and VyOS rendering support aliases on both families. Reconcile the normative catalog with the actual service owner/path. Connect's private target and an Alt-owned explicitly public external UDP port are different policies; do not reinterpret an Alt direct port as a Connect leak. Preserve dated historical rollout evidence, and do not infer deployed generation from source.
- Existing parser/migration tests and tracked device-written captures still contain non-documentation public addresses and production-style host labels, despite the standing rule to use synthetic test data. For example, see [migrate_test.go:108](/Users/brien/urnetwork/warp/vyos/migrate_test.go:108). Sanitize these while preserving the device output shape. A bounded inspection counted credential-like fields but did not expose or assess their values, so this review does not assert that an active secret was leaked. Newly authored review controls used the synthetic site only.

## Monitoring and acceptance gaps relative to SIGNALS.md

The existing exact-edge checks deliberately filter to active nontransparent edge interfaces ([monitor/config.go:1186](/Users/brien/urnetwork/server/monitor/config.go:1186)). Router and transparent-interface coverage is not automatically provided by those checks. Other provider probes may test service behavior, but they do not establish router configuration or neighbor health.

| Known failure / catalog owner | Required discriminator for this rollout | Misleading result to avoid |
| --- | --- | --- |
| Exact IPv6 identity/ingress, §18.1 | Active Vault address = live host address = exact router destination/prefix; fresh ND and correct upstream /56 route; externally pinned same-SNI HTTPS | A DNS-selected healthy sibling, a static route, or successful management SSH clearing a failed exact address |
| Public UDP and return tuple, §14.5/§16.4/§16.5 | Fresh flow through each affected family/alias; correct listener; reply observed from the exact requested public tuple | Treating HTTPS/ping or a rendered permit as proof of QUIC/WireGuard/UDP service health |
| Conntrack capacity after restart, §11.12 | Running count/max/hash and insert/drop deltas, tied to router boot/config generation and resource capacity | Declared table size alone proving it applied; increasing capacity without checking router memory |
| Backup direct forwarding, §11.22 | Both direct public SSH forwards reach the expected source host after cutover; long-lived/resumed transfer behavior remains correct | Using management VPN success as backup-path proof or switching archive traffic back to VPN |
| LAN identity, §11.17a/§11.20b | All per-host route maps agree with authoritative DHCP ownership; host actually holds the expected address | A correct first YAML alias or generated DHCP mapping proving every consumer is correct |
| Observer route loss, §18.1 | Same-window observer default-route/RA lifetime and independent control path | Calling simultaneous observer IPv6 loss a fleet router outage |
| Router apply/reboot durability (new coverage) | Desired, running, and saved generation agree; apply phase and last-known-good boot identity are retained | “Converged”, a zero exit, or a surviving backup alone proving safe reboot |

Operational acceptance should be one router at a time, with the management VPN/profile, upstream routing and host netplan prerequisites independently ready. On the documented EdgeOS firmware, automatic commit-confirm rollback is unavailable; out-of-band recovery remains a real prerequisite, not something the monitor can synthesize. Do not schedule reboots as remediation. Any restart/recovery or deployment needs its own operator authorization.

The gateway requires hardware proof of proxy ARP, ND/re-resolution, PMTU, expected transit routing, and forwarding capacity before production approval. Keep the documented trust model, default-deny downstream filters, source-validation/asymmetric-route policy, and offload choices separate from bugs. Local-only router logs are an explicit design choice but limit post-incident attribution; retain bounded diagnostic evidence when an incident occurs.

## Test evidence and limits

Existing scoped suites all passed: 28 `vyos` top-level tests; 6 router-schema top-level tests with 64 subtests; 23 Warpctl VyOS top-level tests; 14 fake-transport Xops rollout tests. These establish existing fixture contracts, not hardware safety.

Additional private controls:

- LAN agreement: one intended rejection failure, three healthy/negative controls passing.
- Address ownership: ten intended rejection failures, healthy control passing; all reached the final unsafe-acceptance assertion, with no fixture/precondition failure.
- Rollout boundaries: three controls reproduced partial boot overwrite, A/B running/saved drift, and incorrect unchanged-after-commit reporting. Their test PASS means reproduction of a defect, not product correctness.

The first rollout-control invocation stopped before running any case because its required-empty output directory contained outer capture files. It was preserved; one corrected invocation ran all three cases. No product test was silently rerun to obtain a pass.

Evidence: [baseline receipt](/Users/brien/urnetwork/monitor/vyos-router-unit-gate.Y9pYmj/result.safe.json), [Xops stderr qualification](/Users/brien/urnetwork/monitor/vyos-router-unit-gate.Y9pYmj/xops-stderr-qualification.safe.json), [LAN receipt](/Users/brien/urnetwork/monitor/vyos-lan-route-overlay-red.duvw3q/result.safe.json), [address receipt](/Users/brien/urnetwork/monitor/vyos-address-ownership-overlay.srikuw/result.safe.json), [independent address qualification](/Users/brien/urnetwork/monitor/vyos-data-plane-review-astra.rDHwdV/address-validation-supplement.safe.json), [rollout control results](/Users/brien/urnetwork/monitor/vyos-rollout-controls-astra.5RT38daV/execution.pl2Iz5/results.safe.json).

Repository fixes, catalog/probe changes, integration of permanent regression tests, and actual rollout acceptance remain unperformed. This review is not a deployment approval.
