# CloudBreach Range — Attacker Guide

**Target**: Meridian Freight Co.'s internal ops portal, a real internet-facing
web app on a real OCI Compute instance. Everything in this range is genuinely
running — no mocked responses, no simulated APIs. Standard rules apply: only
attack infrastructure you deployed yourself (see `../terraform/`).

**Goal**: get a shell on `internal-01`, a second machine that has **no public
IP and no direct internet exposure** — you can only reach it by pivoting
through the first machine you compromise.

There are **two independent vulnerabilities** here, on two different
internal tools, each leading to that same goal by a genuinely different
route — not two labs, and not the same bug twice. Chain A (below) starts
from an SSRF. Chain B (further down) starts from something else entirely —
try to find it yourself before reading that section's hint.

---

## Chain A

### Stage 0: Recon

You have one target: `web01_domain` from `terraform output` (your DuckDNS
domain — `web01_public_ip` also works directly if you'd rather use the raw
IP). Start there.

```bash
nmap -sV -p- <web01_domain>
curl -s https://<web01_domain>/
```

What does the app do? What features does it expose that touch the network on
the server's behalf?

### Stage 1: Initial access — reach the metadata service

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

### Stage 2: Enumerate what's stashed in instance metadata

Once you're past the header requirement, look at what's under
`/opc/v2/instance/metadata/` — instance metadata isn't just standard fields
like hostname/region, it can hold arbitrary key/value pairs an operator set
at launch time. Ops teams sometimes stash things there for their own
convenience scripts. Enumerate what keys exist, and read each one.

### Stage 3: Follow the leak

One of those keys should look like a URL, with a name suggesting it's
related to some kind of recovery/backup process for another host. Pull on
that thread — where does it point, and what does a plain (unauthenticated)
request to it return?

> 💡 If it looks like a long, opaque, pre-signed-style URL pointing at an
> object storage path, that's exactly what it is — a presigned link that
> grants read access to one specific file without needing any further cloud
> authentication at all.

### Stage 4: Turn the leak into access

What you retrieve in Stage 3 should be directly usable material for
authenticating to another machine. Where would you point it?

### Stage 5: Lateral movement

`internal-01` has no public IP. The only network path to it is *through*
`web-01`. Figure out its private IP (a few different ways depending on what
you've already got — recon what OCI resources you can discover, or think
about what's a reasonable subnet/addressing guess given `web-01`'s own
address), then route an SSH connection through your foothold on `web-01`
using the credential material from Stage 4.

### Stage 6: Proof

Once you're in, there's a flag waiting for you. There's also a short note in
`/opt/meridian-internal/` — read it, it's part of telling a complete story
in your findings.

---

## Chain B

Different starting point than Chain A — same destination. There's a second
internal tool listed on the same "Staff Tools" page. It's a small utility
for looking up a domain during the recon phase of an engagement, and it
shells out to a real system command to do it.

### Stage 0: Find it and think about how it's built

If a web feature runs a real command-line tool (not calling an API, an
actual subprocess) on input you control, ask: is that input landing inside
a shell string, or being passed as a proper argument? Those aren't the same
thing, and only one of them is safe. Try passing a value that includes a
shell metacharacter (`;`, `|`, `&&`, or a backtick) alongside the input the
tool is expecting, and see if you get *more* output than just what you
asked for.

### Stage 1: Confirm it's real command execution, not a fluke

Once you can inject a second command, prove to yourself it's genuinely
running with whatever privileges the web app itself has — not some
sandboxed/limited context.

### Stage 2: Proof

There's a flag sitting in a plain file on this machine, not gated behind
anything except being able to run `cat` on it at all.

### Stage 3: Get to the same place Chain A ends up

You don't have a read-only "fetch a URL" primitive here — you have a real
shell. Think about what that means for reaching the same cloud metadata
service Chain A used, and what's different about doing it this way (hint:
one annoying part of Chain A's Stage 1 stops being necessary once you can
just run `curl` yourself).

---

## Deliverable

Same expectation as any real engagement: document whichever chain you ran
(or both) end to end — what you found, why it worked, what you'd tell
SoulSecure Inc. to fix, and in what priority order. See
[InstructorKey.md](InstructorKey.md) if you're stuck or grading someone
else's run — full ground truth and exact commands are there, so don't open
it if you want to solve this yourself first.
