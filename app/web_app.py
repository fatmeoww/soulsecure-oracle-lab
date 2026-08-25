#!/usr/bin/env python3
"""
CloudBreach Range -- web-01, the public site of "SoulSecure Inc."

A deliberately vulnerable Flask app for a real-cloud (OCI) pentest range.
This is NOT a mock -- it is a genuine SSRF vulnerability that, running on a
real OCI Compute instance, lets an attacker reach the real instance metadata
service (169.254.169.254, same link-local address OCI and AWS both use) and
pull real instance metadata -- including whatever an operator carelessly
stashed there (see InstructorKey.md).

In-fiction: SoulSecure Inc. is the same cybersecurity consultancy behind the
mocked SoulSecure training course -- this range is presented as SoulSecure's
own public site, carrying a real internal tool (the "Report Link Preview"
staff utility) that consultants use to sanity-check outbound links before
they go into a client deliverable. That tool is where the SSRF lives.

Vulnerability: /preview fetches an attacker-supplied URL server-side with no
allow-list, no scheme restriction, no block on the 169.254.169.254
link-local metadata range, and (realistically -- plenty of real "link
checker" tools do this) lets the caller pass custom headers through
untouched, which happens to be exactly what's needed to satisfy OCI IMDS
v2's `Authorization: Bearer Oracle` requirement.

Do not deploy this anywhere reachable by anyone other than intended lab
students. See ../README.md for network/IAM scoping that makes this safe to
run as a real internet-facing service for a training range.
"""
import json
from urllib.parse import urlparse

import requests
from flask import Flask, request, Response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Shared chrome: one CSS block, one layout() wrapper, every route uses it.
# Design: a bright, rounded "trust and capability" consultancy look -- a
# navy-to-teal gradient banner carries the services section, soft-shadowed
# white cards throughout, one geometric display face (Prompt) doing double
# duty for headings and body so the page reads as one confident voice.
# ---------------------------------------------------------------------------

BASE_CSS = """
:root {
  --bg: #F3F7FC;
  --surface: #FFFFFF;
  --surface-2: #EAF1F8;
  --border: #DCE6F0;
  --ink: #142338;
  --muted: #5C6C84;
  --primary: #0B4F8A;
  --primary-2: #12A8C4;
  --accent: #0F8FB0;
  --on-primary: #FFFFFF;
  --shadow: 0 12px 28px -18px rgba(20, 35, 56, 0.35);
  --shadow-sm: 0 6px 16px -12px rgba(20, 35, 56, 0.3);
  --display: "Prompt", "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0B1420;
    --surface: #121C2B;
    --surface-2: #182437;
    --border: #22314A;
    --ink: #E7EEF7;
    --muted: #93A3BC;
    --primary: #1B6FB0;
    --primary-2: #1FC2E0;
    --accent: #38C7E6;
    --on-primary: #08131F;
    --shadow: 0 14px 30px -16px rgba(0, 0, 0, 0.55);
    --shadow-sm: 0 8px 18px -12px rgba(0, 0, 0, 0.5);
  }
}
* { box-sizing: border-box; }
html { text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--display);
  font-weight: 400;
  font-size: 16px;
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; }
a:focus-visible, button:focus-visible, input:focus-visible {
  outline: 2px solid var(--primary-2);
  outline-offset: 2px;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 28px; }

/* --- Masthead --- */
header.masthead {
  background: var(--surface);
  box-shadow: var(--shadow-sm);
  position: relative;
  z-index: 5;
}
.masthead-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 20px 28px;
}
.wordmark {
  font-weight: 700;
  font-size: 1.4rem;
  letter-spacing: -0.01em;
  text-decoration: none;
  color: var(--primary);
}
.wordmark .dot { color: var(--primary-2); }
nav.primary { display: flex; gap: 30px; }
nav.primary a {
  font-size: 0.92rem;
  font-weight: 500;
  text-decoration: none;
  color: var(--muted);
  padding-bottom: 3px;
  border-bottom: 2px solid transparent;
  transition: color 0.15s ease, border-color 0.15s ease;
}
nav.primary a:hover { color: var(--primary); }
nav.primary a.active { color: var(--primary); border-bottom-color: var(--primary-2); }

/* --- Hero --- */
.hero { padding: 68px 0 48px; }
.eyebrow {
  display: inline-block;
  font-size: 0.78rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--primary);
  background: var(--surface-2);
  border-radius: 999px;
  padding: 6px 16px;
  margin: 0 0 20px;
}
h1 {
  font-weight: 700;
  font-size: clamp(2.1rem, 4.2vw, 3rem);
  line-height: 1.16;
  margin: 0 0 20px;
  max-width: 17ch;
  text-wrap: balance;
  color: var(--ink);
}
.lede {
  font-size: 1.12rem;
  color: var(--muted);
  max-width: 58ch;
  margin: 0 0 32px;
}
.cta-row { display: flex; gap: 14px; flex-wrap: wrap; }
.btn {
  font-size: 0.92rem;
  font-weight: 600;
  text-decoration: none;
  padding: 13px 26px;
  border-radius: 10px;
  border: 1px solid var(--border);
  display: inline-block;
  transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}
.btn.primary {
  background: linear-gradient(135deg, var(--primary), var(--primary-2));
  color: var(--on-primary);
  border-color: transparent;
  box-shadow: var(--shadow-sm);
}
.btn.primary:hover { transform: translateY(-1px); box-shadow: var(--shadow); }
.btn.ghost { color: var(--primary); background: var(--surface); }
.btn.ghost:hover { border-color: var(--primary-2); }

/* --- Sections --- */
section.block { padding: 44px 0; }
.block-head { margin: 0 0 32px; max-width: 62ch; }
h2 {
  font-weight: 700;
  font-size: 1.6rem;
  margin: 0 0 8px;
  text-wrap: balance;
}
.block-sub { color: var(--muted); margin: 0; }

/* --- Stats strip --- */
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
.stat {
  background: var(--surface);
  border-radius: 14px;
  box-shadow: var(--shadow-sm);
  padding: 22px 20px;
}
.stat .n { font-size: 1.9rem; font-weight: 700; color: var(--primary); }
.stat .l { font-size: 0.78rem; font-weight: 500; color: var(--muted); margin-top: 4px; }

/* --- Gradient services banner (homepage) --- */
.banner {
  background: linear-gradient(135deg, var(--primary), var(--primary-2));
  border-radius: 26px;
  padding: 44px 40px;
  color: #fff;
  box-shadow: var(--shadow);
}
.banner-head { max-width: 60ch; margin: 0 0 32px; }
.banner-head h2 { color: #fff; margin-bottom: 10px; }
.banner-head p { color: rgba(255, 255, 255, 0.86); margin: 0; }
.icon-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 18px;
}
.icon-card {
  background: var(--surface);
  border-radius: 18px;
  padding: 28px 22px;
  text-align: center;
  box-shadow: var(--shadow-sm);
}
.icon-badge {
  width: 56px;
  height: 56px;
  margin: 0 auto 16px;
  border-radius: 50%;
  background: var(--surface-2);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--primary);
}
.icon-badge svg { width: 28px; height: 28px; }
.icon-card h3 { font-size: 1rem; font-weight: 700; margin: 0 0 8px; color: var(--ink); }
.icon-card p { color: var(--muted); font-size: 0.9rem; margin: 0; line-height: 1.55; }

/* --- Generic rounded card grid (about / values) --- */
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.rcard {
  background: var(--surface);
  border-radius: 16px;
  box-shadow: var(--shadow-sm);
  padding: 26px 24px;
}
.rcard h3 { font-weight: 700; font-size: 1.02rem; margin: 0 0 10px; }
.rcard p { color: var(--muted); font-size: 0.92rem; margin: 0; }
.rcard .tag {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--primary);
  background: var(--surface-2);
  border-radius: 999px;
  padding: 4px 12px;
  margin-bottom: 12px;
}

/* --- Team --- */
.team-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 16px; }
.person {
  background: var(--surface);
  border-radius: 16px;
  box-shadow: var(--shadow-sm);
  padding: 24px;
}
.person .badge {
  font-family: var(--mono);
  font-size: 0.68rem;
  color: var(--muted);
  letter-spacing: 0.04em;
  margin-bottom: 14px;
  display: flex;
  justify-content: space-between;
}
.person h3 { font-size: 1.1rem; font-weight: 700; margin: 0 0 2px; }
.person .role { font-size: 0.82rem; color: var(--accent); font-weight: 600; margin-bottom: 12px; }
.person p { color: var(--muted); font-size: 0.9rem; margin: 0; }

/* --- Case list (portfolio) --- */
.case {
  display: grid;
  grid-template-columns: 170px 1fr;
  gap: 24px;
  padding: 24px;
  background: var(--surface);
  border-radius: 16px;
  box-shadow: var(--shadow-sm);
  margin-bottom: 14px;
}
.case .meta { font-size: 0.76rem; color: var(--muted); font-weight: 500; }
.case .meta .kind {
  display: inline-block;
  color: var(--primary);
  font-weight: 600;
  background: var(--surface-2);
  border-radius: 999px;
  padding: 4px 12px;
  margin-bottom: 8px;
}
.case h3 { font-size: 1.05rem; font-weight: 700; margin: 0 0 8px; }
.case p { color: var(--muted); margin: 0; font-size: 0.94rem; }

/* --- Timeline (about) --- */
.timeline { display: flex; flex-direction: column; gap: 14px; }
.tl-row {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 24px;
  padding: 22px 24px;
  background: var(--surface);
  border-radius: 16px;
  box-shadow: var(--shadow-sm);
}
.tl-row .yr { font-weight: 700; color: var(--primary); font-size: 0.95rem; padding-top: 2px; }
.tl-row p { margin: 0; color: var(--muted); }
.tl-row strong { color: var(--ink); }

/* --- Prose (staff tool pages) --- */
.prose { max-width: 68ch; }
.prose p { color: var(--muted); }
.prose code {
  font-family: var(--mono);
  background: var(--surface-2);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.86em;
}

/* --- Forms (preview tool) --- */
.tool-panel { background: var(--surface); border-radius: 18px; box-shadow: var(--shadow-sm); padding: 30px; }
label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--muted); margin-bottom: 8px; }
input[type=text] {
  width: 100%;
  font-family: var(--mono);
  font-size: 0.92rem;
  padding: 12px 14px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 10px;
  color: var(--ink);
  margin-bottom: 18px;
}
.result {
  margin-top: 24px;
  background: var(--bg);
  border-radius: 12px;
  border: 1px solid var(--border);
  padding: 18px;
  font-family: var(--mono);
  font-size: 0.84rem;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
}
.result .status { color: var(--muted); margin-bottom: 10px; display: block; }

footer { padding: 40px 0 32px; }
.footer-inner { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.footer-inner p { margin: 0; color: var(--muted); font-size: 0.84rem; }
.footer-links { display: flex; gap: 20px; }
.footer-links a { font-size: 0.82rem; color: var(--muted); text-decoration: none; font-weight: 500; }
.footer-links a:hover { color: var(--primary); }

@media (max-width: 860px) {
  .icon-grid { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 720px) {
  .grid-3, .stats { grid-template-columns: 1fr; }
  .icon-grid { grid-template-columns: 1fr; }
  .case, .tl-row { grid-template-columns: 1fr; gap: 8px; }
  .banner { padding: 32px 22px; border-radius: 20px; }
  nav.primary { display: none; }
}
"""

NAV_ITEMS = [
    ("/", "Home"),
    ("/about", "About"),
    ("/team", "Team"),
    ("/portfolio", "Work"),
]

# Small original line-icon set (hand-authored, single-color stroke paths --
# not sourced from anywhere) used in the homepage services banner.
ICONS = {
    "cloud": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18a4 4 0 0 1-.6-7.96A5 5 0 0 1 16 8a4.5 4.5 0 0 1 1 8.9"/><path d="M9 15l2 2 4-4"/></svg>',
    "target": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="0.6" fill="currentColor"/></svg>',
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/></svg>',
    "pulse": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2 6 4-12 2 6h6"/></svg>',
}


def layout(title, body, active="", head_extra=""):
    nav_links = []
    for href, label in NAV_ITEMS:
        cls = ' class="active"' if href == active else ""
        nav_links.append(f'<a href="{href}"{cls}>{label}</a>')
    nav_html = "".join(nav_links)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SoulSecure Inc. — {title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Prompt:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{BASE_CSS}</style>
{head_extra}
</head>
<body>
<header class="masthead">
  <div class="wrap masthead-inner">
    <a href="/" class="wordmark">SoulSecure<span class="dot">.</span></a>
    <nav class="primary">{nav_html}</nav>
  </div>
</header>
{body}
<footer>
  <div class="wrap footer-inner">
    <p>&copy; SoulSecure Inc. — Offensive security, done honestly.</p>
    <div class="footer-links">
      <a href="/staff">Staff Tools</a>
      <a href="/health">Status</a>
    </div>
  </div>
</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    services = [
        ("cloud", "Cloud Security Review", "IAM misconfigurations, exposed metadata services, over-broad trust policies — tested against your real environment, not a checklist."),
        ("target", "Red Team", "Goal-oriented operations scoped against your actual detection and response capability, not a generic playbook."),
        ("shield", "Blue Team", "Detection engineering and response readiness — we tell you what would have caught us, specifically."),
        ("pulse", "Incident Response", "On-call before the incident happens, not after — retainer engagements with someone who already knows your environment."),
    ]
    cards = "".join(
        f"""<div class="icon-card">
          <div class="icon-badge">{ICONS[icon]}</div>
          <h3>{title}</h3>
          <p>{desc}</p>
        </div>"""
        for icon, title, desc in services
    )
    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Cloud &amp; Infrastructure Security</p>
    <h1>We break in first, so someone else doesn't.</h1>
    <p class="lede">SoulSecure Inc. runs offensive security engagements for teams
    who'd rather find their own gaps than read about them in a breach
    disclosure. Cloud assessments, red team operations, and the kind of
    reporting your engineers will actually read.</p>
    <div class="cta-row">
      <a href="/portfolio" class="btn primary">See our work</a>
      <a href="/about" class="btn ghost">Our story</a>
    </div>
  </section>

  <section class="block">
    <div class="stats">
      <div class="stat"><div class="n">2019</div><div class="l">Founded</div></div>
      <div class="stat"><div class="n">140+</div><div class="l">Engagements delivered</div></div>
      <div class="stat"><div class="n">6</div><div class="l">Practice areas</div></div>
      <div class="stat"><div class="n">0</div><div class="l">Findings we've ever softened</div></div>
    </div>
  </section>

  <section class="block">
    <div class="banner">
      <div class="banner-head">
        <h2>Full-service, matched to what you actually need</h2>
        <p>SoulSecure covers the full lifecycle of a security program — offense,
        defense, process, and the people who have to run it day to day.</p>
      </div>
      <div class="icon-grid">{cards}</div>
    </div>
  </section>
</div>
"""
    return layout("Home", body, active="/")


@app.route("/about")
def about():
    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">About</p>
    <h1>Founded on one complaint.</h1>
    <p class="lede">SoulSecure started because too many audit reports read
    like they were written for a compliance checkbox instead of the person
    who'd actually have to fix anything. We set out to build the kind of
    firm we'd have wanted to hire.</p>
  </section>

  <section class="block">
    <div class="block-head">
      <h2>How we got here</h2>
    </div>
    <div class="timeline">
      <div class="tl-row">
        <div class="yr">2019</div>
        <p><strong>Two consultants, one shared office.</strong> SoulSecure
        opens with a single focus: cloud environments, because that's where
        every client's real exposure had quietly moved while their security
        program was still budgeted for the data center.</p>
      </div>
      <div class="tl-row">
        <div class="yr">2021</div>
        <p><strong>Red team practice stood up.</strong> Assessment work kept
        surfacing the same question from clients: "okay, but could someone
        actually use that?" We built a dedicated operations team to answer
        it properly instead of guessing.</p>
      </div>
      <div class="tl-row">
        <div class="yr">2023</div>
        <p><strong>The training range.</strong> Hiring by resume stopped
        working — too many candidates who could recite OWASP categories and
        couldn't chain three real findings together. We built a hands-on
        assessment course internally so candidates (and now clients' own
        teams) could show us, not tell us. Some of what you're looking at
        right now is part of it.</p>
      </div>
      <div class="tl-row">
        <div class="yr">Today</div>
        <p><strong>Six practice areas, one standard.</strong> Every
        engagement is still reviewed by someone who didn't run it, before it
        goes to a client — the same rule we started with.</p>
      </div>
    </div>
  </section>

  <section class="block">
    <div class="block-head">
      <h2>What we won't do</h2>
      <p class="block-sub">A short list, held for six years running.</p>
    </div>
    <div class="grid-3">
      <div class="rcard">
        <h3>Pad the finding count</h3>
        <p>A report with forty low-severity items and no critical path
        isn't more thorough. It's harder to act on.</p>
      </div>
      <div class="rcard">
        <h3>Skip the retest</h3>
        <p>A fix nobody verified is a finding with extra steps.</p>
      </div>
      <div class="rcard">
        <h3>Sell what we didn't do</h3>
        <p>If it wasn't in scope, it's not in the report as a finding.</p>
      </div>
    </div>
  </section>
</div>
"""
    return layout("About", body, active="/about")


@app.route("/team")
def team():
    people = [
        ("Renata Cole", "Founder & CEO", "01",
         "Started SoulSecure with two laptops and a conviction that a pentest "
         "report should change what a client does on Monday morning."),
        ("James Ops", "Director of Infrastructure", "02",
         "Keeps every environment we run — training and production — patched, "
         "logged, and boring, the way infrastructure is supposed to be. "
         "(Yes, that's really the handle on his commits.)"),
        ("Priya Desai", "Head of Cloud Security", "03",
         "Spent four years on the other side, building the IAM policies "
         "she now gets paid to find gaps in."),
        ("Marcus Webb", "Principal Red Team Consultant", "04",
         "Prefers a quiet foothold over a loud exploit. Has never once used "
         "a finding's CVSS score in casual conversation."),
        ("Dawn Sirichai", "Detection & Response Lead", "05",
         "Reads every red team report from the defender's side first, "
         "before anyone else on the team sees it."),
        ("Théo Lindqvist", "Senior Consultant, Cloud Practice", "06",
         "Wrote the internal training range's first capstone chain over one "
         "long weekend, then made everyone re-solve it before shipping."),
    ]
    cards = "".join(
        f"""<div class="person">
          <div class="badge"><span>{num}</span><span>SOULSECURE.LAB</span></div>
          <h3>{name}</h3>
          <div class="role">{role}</div>
          <p>{bio}</p>
        </div>"""
        for name, role, num, bio in people
    )
    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Team</p>
    <h1>Six people, one standard for a finding.</h1>
    <p class="lede">Small enough that everyone reviews everyone else's
    work before it reaches a client.</p>
  </section>
  <section class="block">
    <div class="team-grid">{cards}</div>
  </section>
</div>
"""
    return layout("Team", body, active="/team")


@app.route("/portfolio")
def portfolio():
    cases = [
        ("Cloud Security Assessment", "Global freight &amp; logistics operator",
         "Traced a public-facing operations tool's link-preview feature "
         "through to full instance-metadata exposure — the kind of chain "
         "that starts as a low-severity SSRF and ends as a lateral-movement "
         "finding once the credentials underneath it get pulled on a thread."),
        ("Red Team Engagement", "Regional fintech, 40-day operation",
         "Goal: reach a specific internal ledger service without tripping "
         "the client's SOC. Delivered a full kill-chain writeup instead of "
         "a tool list — including the two detections that did fire, and why."),
        ("Incident Response Retainer", "Healthcare SaaS platform",
         "On-call engagement following a credential-stuffing incident; "
         "post-incident hardening review closed out three related findings "
         "the original alert never surfaced."),
        ("Cloud Migration Review", "Manufacturing conglomerate",
         "Pre-migration security review of a lift-and-shift plan — caught an "
         "inherited trust-policy misconfiguration before it ever reached "
         "production."),
    ]
    rows = "".join(
        f"""<div class="case">
          <div class="meta"><span class="kind">{kind}</span></div>
          <div><h3>{client}</h3><p>{desc}</p></div>
        </div>"""
        for kind, client, desc in cases
    )
    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Selected work</p>
    <h1>A few engagements we can talk about.</h1>
    <p class="lede">Client names are withheld per standard engagement terms
    — the findings and the shape of each chain are real.</p>
  </section>
  <section class="block">
    {rows}
  </section>
</div>
"""
    return layout("Selected Work", body, active="/portfolio")


@app.route("/staff")
def staff():
    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Internal — Staff Tools</p>
    <h1>Report Link Preview</h1>
    <p class="lede">Consultants use this before a link goes into a client
    deliverable — paste it in, confirm it resolves to what you think it
    does, catch a typo'd domain before a client does.</p>
  </section>
  <section class="block prose">
    <p>Open the tool: <a href="/preview?url=https://example.com">/preview</a></p>
    <p>Pass <code>url=</code> with the link to check. Some legacy partner
    integrations occasionally need a custom header forwarded through — the
    tool accepts an optional <code>headers=</code> parameter as a JSON
    object for that case.</p>
  </section>
</div>
"""
    return layout("Staff Tools", body, active="")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/preview")
def preview():
    """
    "Report Link Preview" -- internal tool: fetches a URL server-side and
    returns a snippet of the response, so consultants can sanity-check a
    link before it goes into a client deliverable. Real feature pattern
    (Slack/Discord/many internal tools do exactly this) -- the bug is the
    complete lack of validation on *what* URL/host the server is allowed to
    fetch, plus an optional "custom headers" convenience (also a genuinely
    common real feature, e.g. for previewing links behind partner auth)
    that happens to make bypassing cloud metadata-service header checks
    trivial.
    """
    url = request.args.get("url", "").strip()

    extra_headers = {}
    raw_headers = request.args.get("headers")
    headers_error = None
    if raw_headers:
        try:
            extra_headers = json.loads(raw_headers)
            if not isinstance(extra_headers, dict):
                raise ValueError
        except Exception:
            headers_error = 'headers= must be a JSON object, e.g. {"Authorization":"Bearer Oracle"}'

    result_html = ""
    if not url:
        pass
    elif headers_error:
        result_html = f'<div class="result"><span class="status">Error</span>{headers_error}</div>'
    else:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError("Only http/https URLs are supported.")
            headers = {"User-Agent": "SoulSecureReportPreview/1.0", **extra_headers}
            r = requests.get(url, timeout=4, headers=headers)
            body_text = r.text[:4000]
            result_html = (
                f'<div class="result"><span class="status">Fetched {url} '
                f"-- HTTP {r.status_code}</span>{body_text}</div>"
            )
        except Exception as e:
            result_html = f'<div class="result"><span class="status">Preview failed</span>{e}</div>'

    body = f"""
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Internal — Staff Tools</p>
    <h1>Report Link Preview</h1>
    <p class="lede">Paste a link below to fetch and preview it server-side,
    exactly the way it will resolve when a client clicks it.</p>
  </section>
  <section class="block">
    <div class="tool-panel">
      <form method="get" action="/preview">
        <label for="url">Link to preview</label>
        <input type="text" id="url" name="url" value="{url}" placeholder="https://partner-domain.example/report/q3">
        <label for="headers">Custom headers (optional, JSON)</label>
        <input type="text" id="headers" name="headers" value="{raw_headers or ''}" placeholder='{{"Authorization":"Bearer ..."}}'>
        <button type="submit" class="btn primary" style="border:none;cursor:pointer;">Preview link</button>
      </form>
      {result_html}
    </div>
  </section>
</div>
"""
    return layout("Report Link Preview", body, active="")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
