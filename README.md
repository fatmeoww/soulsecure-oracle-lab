# CloudBreach Range

A small, **genuinely real** cloud attack range — not a mock/simulation like
the SoulSecure course. Two real Compute instances on **Oracle Cloud
Infrastructure (OCI)**, a real instance-metadata misconfiguration, real
lateral movement between machines, and **two independent, unrelated
vulnerabilities** (not the same bug twice) so different people can each get
a genuinely different exercise. Built with Terraform so it's reproducible
and fully destroyable, and designed to sit on **OCI's Always Free tier —
genuinely $0/month, indefinitely**, not a 12-month trial.

**Chain A (Flag 1) — SSRF**: SSRF on a public web app → reach the real OCI
instance metadata service → find a careless "backup recovery" URL stashed
in that metadata → follow it to a presigned Object Storage link holding a
real SSH private key → use that key to pivot from the public machine into
a second, private-subnet-only machine.

**Chain B (Flag 2) — OS command injection**: a different internal tool on
the same site shells out to `whois` by string-formatting user input into a
`shell=True` call → real remote code execution, running as root → reach
the same metadata leak directly (no SSRF trick needed once you have a real
shell) → same pivot, same destination, completely different route in.

This is a **separate range from the SoulSecure course** — same spirit
(realistic misconfigurations, chained exploitation), but running on your own
real cloud account instead of hand-rolled mocks.

> **Why OCI and not AWS?** AWS has no tier that's free forever for two
> always-on instances (Free Tier is 12 months, and 750 free hours/month
> isn't enough for two machines running continuously anyway). OCI's Always
> Free tier genuinely never expires: 2 AMD Compute VMs, 10GB Object Storage,
> and 10TB/month egress, forever, on any account. The trade-off is OCI's
> IAM/instance-metadata mechanics differ from AWS's (see "Why this design"
> below) — the attack *shape* is the same, the specific APIs are OCI's own.

---

## ⚠️ Read this first: cost and account notes

| Resource | Cost | Notes |
|---|---|---|
| 2× `VM.Standard.E2.1.Micro` Compute | **$0, forever** | OCI Always Free explicitly includes exactly 2 of these per tenancy |
| Object Storage (the leaked SSH key) | **$0** | Well under the 10GB Always Free allowance |
| VCN, subnets, route tables, NSGs | **$0** | Always free |
| Outbound data transfer | **$0** | Well under the 10TB/month Always Free allowance |

Nothing in this design costs money at any point, as long as you stay on the
`VM.Standard.E2.1.Micro` shape (don't resize up) and don't add extra
services (a "Vault" for secrets, a Load Balancer, block volumes beyond the
two boot volumes, etc.) — the Terraform here doesn't create any of those.

**One honest caveat**: Oracle's Always Free resources are documented as not
expiring, but Oracle's fair-use terms allow reclaiming resources on
tenancies that go **fully idle** for an extended period. Log into the OCI
console occasionally and this won't be an issue for an actively-used
practice range.

**Scope discipline**: `allowed_cidr` (see Setup below) restricts both of
web-01's open ports to only your own IP — this range is not meant to sit
open to the whole internet. Widen it only if you deliberately want that.

---

## Why this design (OCI vs. the AWS version)

The original design (kept in git history) used AWS EC2 IMDS + IAM roles +
SSM Parameter Store. OCI's equivalents exist but work differently:

- **OCI's instance metadata service** lives at the same link-local address
  (`169.254.169.254`) as AWS's, but its "v2" endpoint requires a static
  `Authorization: Bearer Oracle` header on every request — a much weaker
  mitigation than AWS's IMDSv2 (which needs a session token from a prior PUT
  request), but it does mean a plain GET-based SSRF needs to be able to send
  a custom header. `web_app.py`'s `/preview` route supports an optional
  `headers=` JSON param specifically for this — a genuinely common real
  feature (many "link preview"/"webhook tester" tools let you customize
  headers), not an artificial lab shortcut.
- **OCI "Instance Principals"** (the rough equivalent of an AWS IAM
  instance role) authenticate via a request-signing certificate, not a
  simple bearer token — exploiting that properly off-instance requires
  request-signing machinery beyond what a read-only SSRF bug realistically
  gives an attacker. Rather than force that complexity into the lab, this
  range uses a **more common real-world mistake instead**: a presigned
  Object Storage URL (OCI's equivalent of an S3 presigned URL) stashed
  directly in instance metadata — something real ops teams genuinely do
  as a "convenience" and something SSRF-to-metadata leaks genuinely expose
  in the wild. It's a different specific mistake than the AWS version's,
  but the same class of mistake (credential material reachable from
  instance metadata) and the same attacker workflow (SSRF → metadata →
  credential → pivot).
- **OCI has no Always-Free secrets-manager equivalent** (OCI Vault is a
  paid service) — Object Storage doubles as the "vault" here, which is
  itself realistic (plenty of real breaches involve secrets sitting in a
  storage bucket rather than a proper secrets manager).

---

## Architecture

```
                         Internet
                            │
                      (allowed_cidr only)
                            │
                    ┌───────▼────────┐
                    │  Internet GW    │
                    └───────┬────────┘
                            │
                 ┌──────────▼───────────┐
                 │   Public subnet       │
                 │   10.0.1.0/24         │
                 │  ┌─────────────────┐  │
                 │  │  web-01          │  │   nginx (443, real TLS cert)
                 │  │  (public IP)     │  │   -> Flask app on 127.0.0.1:5000
                 │  │                  │  │   Flag 1: SSRF in /preview
                 │  │  instance meta:  │  │   Flag 2: cmd injection in
                 │  │  PAR leak        │  │     /tools/lookup (real root RCE)
                 │  │                  │  │   both reach "backup_recovery_url"
                 │  └────────┬────────┘  │   (presigned Object Storage link)
                 └───────────┼───────────┘
                              │ NSG-scoped SSH only
                 ┌────────────▼──────────┐
                 │   Private subnet       │
                 │   10.0.2.0/24          │
                 │   (no internet route)  │
                 │  ┌──────────────────┐  │
                 │  │  internal-01      │  │   No public IP
                 │  │  (no public IP)   │  │   SSH only from web-01's NSG
                 │  │  holds: flag.txt  │  │
                 │  └──────────────────┘  │
                 └────────────────────────┘

  Object Storage bucket "cloudbreach-secrets" holds internal-01's real SSH
  private key. A Pre-Authenticated Request (presigned URL) for that one
  object is what's leaked via web-01's instance metadata.
```

See [StudentGuide.md](StudentGuide.md) for the attacker path (without giving
away every exact command) and [InstructorKey.md](InstructorKey.md) for the
full ground truth, exact commands, and flag values.

---

## Setup

### Prerequisites

- An OCI account ([signup](https://signup.oraclecloud.com/) — a credit card
  is required for verification but Always Free resources never bill it)
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [OCI CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm),
  run `oci setup config` once to generate `~/.oci/config` and an API signing
  key pair (uploaded to your OCI user via the console when prompted) — the
  Terraform `oci` provider reads this same file automatically
- An SSH key pair on your own machine (`ssh-keygen -t ed25519` if you don't
  have one) — its **public** key goes into Terraform as
  `admin_ssh_public_key`; never paste a private key anywhere in this setup

### Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set region, compartment_ocid, allowed_cidr,
# admin_ssh_public_key

terraform init
terraform plan     # review what it's about to create
terraform apply
```

Before the first apply, register a free domain at [DuckDNS](https://www.duckdns.org)
(sign in, add a subdomain) and set it as `duckdns_domain` in
`terraform.tfvars` — used as the CN/SAN for both the fallback self-signed
cert and the real Let's Encrypt cert Certbot requests automatically on
every boot. Point its A record at the IP `terraform apply` prints as
`web01_public_ip` (a **reserved**, not ephemeral, IP — see below — so you
only need to do this once, ever).

Takes about 2–3 minutes. Terraform prints `web01_public_ip`, `web01_domain`
(your DuckDNS name), and `web01_app_url` when done.

> Don't want to register anything, even a free DuckDNS name? Leave
> `duckdns_domain` at anything and just use `https://<web01_public_ip>.nip.io`
> style access instead — [nip.io](https://nip.io) resolves any
> IP-embedded-in-the-hostname automatically, zero registration, though the
> IP ends up visible in the URL (DuckDNS gives you a clean name instead).
> Either way Certbot needs the domain to actually resolve to this IP to
> issue a real cert, so pick one before relying on HTTPS working without
> `-k`.

**This IP is stable across future `terraform apply` runs**, including ones
that force `web-01` to be destroyed and recreated (which any `user_data` /
app-code change does) — it's a **reserved**, not ephemeral, public IP
(`oci_core_public_ip.web01`), so it stays with your tenancy rather than
being re-randomized every time the instance underneath it changes. This
matters because the domain shows up as ground truth throughout
[InstructorKey.md](InstructorKey.md) — see that file's "Known limitations"
for the one-time migration story and why an ephemeral IP would have made
that documentation go stale on the next unrelated code change.

**Find your own IP for `allowed_cidr`:**
```bash
curl -s https://checkip.amazonaws.com
# use the result as "<that-ip>/32"
```

web-01 serves as SoulSecure Inc.'s own public site — Home, About, Team, and
a Work/portfolio page, styled and written like a real consultancy's site,
not a bare test page. The vulnerable "Report Link Preview" tool lives under
a low-key "Staff Tools" footer link, framed as an internal utility
consultants use to sanity-check outbound links before they go into a client
deliverable — see [StudentGuide.md](StudentGuide.md) for the attacker's way
in. HTTPS only (real Let's Encrypt certificate, reissued fresh on every
boot for `duckdns_domain`, self-signed as a fallback if that fails) —
plain HTTP on 80 redirects to 443, nothing meaningful is served over it.

### Verify it's up

```bash
curl -s https://<web01_domain>/health
# {"status": "ok"}
```

### Tear down (optional — this range is free to leave running)

```bash
cd terraform
terraform destroy
```

Since this sits on Always Free resources, there's no cost reason to destroy
it between sessions — leave it running so it's always ready. Destroy it if
you're rebuilding after an app-code change, or just want a clean slate.

---

## Keeping it game-ready: resetting between players

Leave both instances running permanently and let players get into
whatever state they get into (including breaking things via the
vulnerabilities on purpose) — the range resets itself back to a clean,
game-ready state automatically, every hour, with **no dependency on any
operator machine being on or reachable**.

### Automatic hourly reset (built into web-01, on by default)

`web-01` provisions itself, on every boot, with everything needed to reset
the whole range hourly with no outside help:

- `/opt/pristine/` — a clean copy of `app/web_app.py` and `flag2.txt`,
  captured at boot time.
- `/root/.ssh/internal01_key` — a real, root-only (600) copy of
  `internal-01`'s admin SSH key, baked in via Terraform (same key the
  intended vulnerability chain itself leaks — not a special backdoor).
- `/opt/reset-range.sh` — restores the pristine app files, restarts
  `cloudbreach-web`/`nginx`, then SSHes to `internal-01` over the same
  NSG-permitted path (`web01_ingress_ssh` → `internal01_ingress_ssh_from_web01`)
  to re-plant Flag 1 and the notes file.
- `/etc/cron.d/cloudbreach-reset` — `0 * * * * root /opt/reset-range.sh
  >> /var/log/cloudbreach-reset.log 2>&1`. Written as a plain
  `/etc/cron.d/` file rather than installed via the `crontab` command —
  the latter goes through PAM and was found to fail silently this early in
  a cloud-init boot (see InstructorKey.md's Known Limitations for the full
  story of how that was diagnosed).

Nothing to set up — it's live the moment `terraform apply` finishes.
Check on it any time:
```bash
ssh cloudbreach-web01 "sudo tail -20 /var/log/cloudbreach-reset.log"
ssh cloudbreach-web01 "cat /etc/cron.d/cloudbreach-reset"
```
Or trigger an off-cycle reset immediately, without waiting for the next
hourly firing:
```bash
ssh cloudbreach-web01 "sudo /opt/reset-range.sh"
```

An earlier design ran this same logic from the *operator's* machine
instead (a `soft-reset.sh` script + a Windows Scheduled Task calling it
hourly over SSH). It worked fine run by hand, but failed almost every
unattended run (`scp: Connection closed` right after auth — see
InstructorKey.md), and depended on that one machine being powered on and
reachable anyway. That approach was dropped in favor of the on-box cron
above. `terraform/soft-reset.sh` is still in the repo purely as a manual,
ad-hoc tool (e.g. force a reset from your own machine without SSHing in
yourself) — it is **not** wired to any scheduler anymore. If you want it
for that, the one-time setup is: extract `internal01_admin_ssh_key` via
`terraform output -raw internal01_admin_ssh_key > ~/.ssh/cloudbreach_internal01_admin`
(`chmod 600` it), and add `cloudbreach-web01`/`cloudbreach-internal01`
`Host` aliases to `~/.ssh/config` (`ProxyJump cloudbreach-web01` for the
internal one) — then just `bash terraform/soft-reset.sh` whenever.

### Hard reset (full instance replace — the nuclear option)

`terraform/reset.sh` — real `terraform apply -replace=...` against
`oci_core_instance.web01`/`internal01`. Use this only if a box is broken
badly enough that SSH itself stopped responding (the hourly cron reset
can't help there, since it also runs over SSH). Slower (~1 minute per
instance), and — as this range's own Known Limitations document — can
occasionally hit OCI's "Out of host capacity" error on Always Free shapes
in busy regions; retry if so. Also worth knowing: since this replaces the
instance, it requests a fresh Let's Encrypt cert every time — Let's
Encrypt's rate limit is 5 certs/week per domain, so don't lean on this for
routine resets (the hourly cron reset never touches the instance or its
cert at all, so it's unaffected).

```bash
bash terraform/reset.sh              # reset both instances
bash terraform/reset.sh web01        # just web-01
bash terraform/reset.sh internal01   # just internal-01
```

---

## Moving to a different account or region

This range has already been moved once for real — `ap-singapore-1` ran out
of Always Free host capacity ("Out of host capacity" on `LaunchInstance`)
for hours, so it was redeployed fresh in a second tenancy whose home
region is `ap-tokyo-1`. If you hit the same wall:

1. **A tenancy's subscribed-region list has a hard cap on Always Free
   accounts.** Trying to subscribe your *existing* tenancy to a second
   region (`oci iam region-subscription create`) will likely fail with
   `TenantCapacityExceeded` — that's not fixable via the API. The real
   fix is a **second, new OCI tenancy** with your target region set as
   its home region during signup.
2. Generate a new API signing key for that tenancy and add it as a
   **named profile** in the *same* `~/.oci/config` your original profile
   lives in (e.g. `[TOKYO]` alongside `[DEFAULT]`) — the Terraform `oci`
   provider only ever reads that one fixed file path, ignoring
   `$OCI_CLI_CONFIG_FILE` (unlike the `oci` CLI itself), so this is the
   only way to give Terraform a second identity to authenticate as.
3. Set `oci_config_profile = "<your profile name>"` in `terraform.tfvars`
   alongside the new `region` and a fresh `compartment_ocid` (the new
   tenancy's own root compartment).
4. **Back up, don't reuse, your old `terraform.tfstate`/`terraform.tfvars`**
   (e.g. rename with a `.old-account-backup` suffix) — state from one
   tenancy means nothing applied against a different one. Start fresh.
5. After a clean `terraform apply`: re-point your DuckDNS A record at the
   new `web01_public_ip`, re-extract `internal01_admin_ssh_key` (it's a
   brand new key), and update the two `HostName`s in your
   `~/.ssh/config` aliases. `soft-reset.sh` itself needs no changes — it
   was written to use those aliases rather than hardcoded IPs specifically
   so a migration like this wouldn't require touching it.
6. If a shape hits "Out of host capacity" in the *new* region too (it can
   — this happened moving to Tokyo as well, on `VM.Standard.A1.Flex`
   specifically, even though `VM.Standard.E2.1.Micro` launched fine
   seconds earlier), just switch `web01_instance_shape` to whichever
   shape just proved it had capacity. See InstructorKey.md's Known
   Limitations for the full blow-by-blow of this exact migration.

---

## Files

```
CloudBreach-Range/
├── README.md              # this file
├── StudentGuide.md         # attacker-path walkthrough (spoiler-light)
├── Walkthrough-TH.md       # full step-by-step playthrough (Thai)
├── InstructorKey.md        # ground truth: exact commands, flags, rubric
├── app/
│   └── web_app.py           # the vulnerable Flask app (SSRF + command injection)
└── terraform/
    ├── versions.tf
    ├── variables.tf
    ├── network.tf             # VCN, subnets, NSGs
    ├── storage.tf              # Object Storage bucket + presigned URL
    ├── compute.tf               # the two Compute instances
    ├── outputs.tf
    ├── terraform.tfvars.example
    ├── reset.sh                 # hard reset: full instance replace
    ├── soft-reset.sh             # manual/ad-hoc reset via SSH (auto reset is on-box cron now)
    └── user_data/
        ├── web01.sh.tpl         # installs + starts the Flask app
        └── internal01.sh.tpl    # plants the flag
```
