# CloudBreach Range — Attacker Guide

**Target**: Meridian Freight Co.'s internal ops portal, a real internet-facing
web app on a real OCI Compute instance. Everything in this range is genuinely
running — no mocked responses, no simulated APIs. Standard rules apply: only
attack infrastructure you deployed yourself (see `../terraform/`).

**Goal**: get a shell on `internal-01`, a second machine that has **no public
IP and no direct internet exposure** — you can only reach it by pivoting
through the first machine you compromise.

---

## Stage 0: Recon

You have one target: `web01_domain` from `terraform output` (a free nip.io
DNS name that resolves straight to web-01's public IP — `web01_public_ip`
also works directly if you'd rather use the raw IP). Start there.

```bash
nmap -sV -p- <web01_domain>
curl -s https://<web01_domain>/
```

What does the app do? What features does it expose that touch the network on
the server's behalf?

## Stage 1: Initial access — reach the metadata service

The "link preview" feature fetches a URL **server-side** and shows you the
response, and it lets you supply custom headers too (`headers=` as a JSON
object) — think about why a "preview" tool would need that, and what else
it's useful for.

Every cloud instance can reach a metadata service at a fixed link-local
address. Try reaching it through the app:

```bash
curl "https://<web01_domain>/preview?url=http://169.254.169.254/opc/v2/instance/"
```

If that comes back with an authentication complaint, look at what header
value the error is asking for — it's not a secret, it's a fixed, publicly
documented string. Pass it through the app's `headers=` param and try again.

## Stage 2: Enumerate what's stashed in instance metadata

Once you're past the header requirement, look at what's under
`/opc/v2/instance/metadata/` — instance metadata isn't just standard fields
like hostname/region, it can hold arbitrary key/value pairs an operator set
at launch time. Ops teams sometimes stash things there for their own
convenience scripts. Enumerate what keys exist, and read each one.

## Stage 3: Follow the leak

One of those keys should look like a URL, with a name suggesting it's
related to some kind of recovery/backup process for another host. Pull on
that thread — where does it point, and what does a plain (unauthenticated)
request to it return?

> 💡 If it looks like a long, opaque, pre-signed-style URL pointing at an
> object storage path, that's exactly what it is — a presigned link that
> grants read access to one specific file without needing any further cloud
> authentication at all.

## Stage 4: Turn the leak into access

What you retrieve in Stage 3 should be directly usable material for
authenticating to another machine. Where would you point it?

## Stage 5: Lateral movement

`internal-01` has no public IP. The only network path to it is *through*
`web-01`. Figure out its private IP (a few different ways depending on what
you've already got — recon what OCI resources you can discover, or think
about what's a reasonable subnet/addressing guess given `web-01`'s own
address), then route an SSH connection through your foothold on `web-01`
using the credential material from Stage 4.

## Stage 6: Proof

Once you're in, there's a flag waiting for you. There's also a short note in
`/opt/meridian-internal/` — read it, it's part of telling a complete story
in your findings.

---

## Deliverable

Same expectation as any real engagement: document the chain end to end —
what you found, why it worked, what you'd tell Meridian Freight Co. to fix,
and in what priority order. See [InstructorKey.md](InstructorKey.md) if
you're stuck or grading someone else's run — full ground truth and exact
commands are there, so don't open it if you want to solve this yourself
first.
