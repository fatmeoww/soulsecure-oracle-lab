# CloudBreach Range

A small, **genuinely real** cloud attack range — not a mock/simulation like
the SoulSecure course. Two real Compute instances on **Oracle Cloud
Infrastructure (OCI)**, a real instance-metadata misconfiguration, a real
SSRF vulnerability, and real lateral movement between machines. Built with
Terraform so it's reproducible and fully destroyable, and designed to sit
on **OCI's Always Free tier — genuinely $0/month, indefinitely**, not a
12-month trial.

**Kill chain**: SSRF on a public web app → reach the real OCI instance
metadata service → find a careless "backup recovery" URL stashed in that
metadata → follow it to a presigned Object Storage link holding a real SSH
private key → use that key to pivot from the public machine into a second,
private-subnet-only machine.

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
                 │  │  web-01          │  │   nginx (443, self-signed cert)
                 │  │  (public IP)     │  │   -> Flask app on 127.0.0.1:5000
                 │  │                  │  │   SSRF vuln in /preview
                 │  │  instance meta:  │  │   "backup_recovery_url" ->
                 │  │  PAR leak        │  │   presigned Object Storage link
                 │  └────────┬────────┘  │
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

## Files

```
CloudBreach-Range/
├── README.md              # this file
├── StudentGuide.md         # attacker-path walkthrough (spoiler-light)
├── InstructorKey.md        # ground truth: exact commands, flags, rubric
├── app/
│   └── web_app.py           # the vulnerable Flask app (real SSRF bug)
└── terraform/
    ├── versions.tf
    ├── variables.tf
    ├── network.tf             # VCN, subnets, NSGs
    ├── storage.tf              # Object Storage bucket + presigned URL
    ├── compute.tf               # the two Compute instances
    ├── outputs.tf
    ├── terraform.tfvars.example
    └── user_data/
        ├── web01.sh.tpl         # installs + starts the Flask app
        └── internal01.sh.tpl    # plants the flag
```
