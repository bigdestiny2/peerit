import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const sourceDir = path.dirname(fileURLToPath(import.meta.url))
const docsDir = path.resolve(sourceDir, "..")

const sharedCss = `
:root {
  --bg: #081019;
  --surface: #0d1824;
  --surface-2: #111f2d;
  --border: #243344;
  --border-strong: #385069;
  --text: #f1f4f5;
  --muted: #9dabb9;
  --faint: #6f8090;
  --accent: #ffae2b;
  --accent-soft: #ffe0a1;
  --accent-rgb: 255,174,43;
  --good: #61d6a4;
  --warn: #ffb66e;
  --page: min(1180px, calc(100vw - 40px));
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-width: 320px;
  color: var(--text);
  background: var(--bg);
  font-family: var(--sans);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  z-index: -1;
  pointer-events: none;
  opacity: .18;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='72' height='72' viewBox='0 0 72 72'%3E%3Cpath d='M0 71.5h72M71.5 0v72' fill='none' stroke='%237d91a6' stroke-opacity='.16'/%3E%3Ccircle cx='12' cy='12' r='1' fill='%237d91a6' fill-opacity='.22'/%3E%3C/svg%3E");
}
a { color: inherit; }
button { color: inherit; font: inherit; }
svg { display: block; }
code, .mono { font-family: var(--mono); }
::selection { color: var(--bg); background: var(--accent); }
.skip-link {
  position: fixed; z-index: 100; top: 10px; left: 10px; transform: translateY(-160%);
  padding: 9px 13px; border-radius: 7px; color: var(--bg); background: var(--text);
  font-weight: 800; transition: transform .15s ease;
}
.skip-link:focus { transform: translateY(0); }
.site-header {
  position: sticky; z-index: 50; top: 0; border-bottom: 1px solid rgba(56,80,105,.62);
  background: rgba(8,16,25,.94); backdrop-filter: blur(16px);
}
.header-inner {
  width: var(--page); min-height: 64px; margin: 0 auto; display: flex;
  align-items: center; justify-content: space-between; gap: 22px;
}
.brand { display: inline-flex; align-items: center; gap: 10px; text-decoration: none; font-weight: 850; letter-spacing: -.025em; }
.brand-mark {
  width: 32px; height: 32px; display: grid; place-items: center; border: 1px solid var(--accent);
  border-radius: 9px; color: var(--accent); font: 850 15px var(--mono); background: rgba(var(--accent-rgb),.08);
}
.nav-list { display: flex; align-items: center; gap: clamp(12px,2.4vw,30px); margin: 0; padding: 0; list-style: none; }
.nav-list a { color: var(--muted); font-size: 13px; font-weight: 700; text-decoration: none; white-space: nowrap; }
.nav-list a:hover, .nav-list a:focus-visible { color: var(--accent); }
main { overflow: hidden; }
.hero, .section { width: var(--page); margin: 0 auto; scroll-margin-top: 64px; }
.hero {
  min-height: calc(100vh - 64px); padding: clamp(70px,8vw,112px) 0 84px;
  display: grid; grid-template-columns: minmax(0,.86fr) minmax(500px,1.14fr);
  align-items: center; gap: clamp(48px,6vw,88px);
}
.eyebrow { margin: 0 0 18px; color: var(--accent); font: 760 12px var(--mono); letter-spacing: .12em; text-transform: uppercase; }
h1,h2,h3,p { margin-top: 0; }
h1,h2,h3 { text-wrap: balance; }
h1 { max-width: 650px; margin-bottom: 23px; font-size: clamp(50px,6.4vw,82px); line-height: 1; letter-spacing: -.058em; }
h2 { margin-bottom: 14px; font-size: clamp(32px,4vw,50px); line-height: 1.08; letter-spacing: -.043em; }
h3 { margin-bottom: 10px; font-size: 20px; line-height: 1.28; letter-spacing: -.02em; }
.hero-copy > p:not(.eyebrow) { max-width: 590px; margin-bottom: 28px; color: var(--muted); font-size: clamp(19px,2vw,24px); line-height: 1.52; }
.actions { display: flex; align-items: center; gap: 14px 22px; flex-wrap: wrap; }
.button {
  min-height: 47px; display: inline-flex; align-items: center; justify-content: center; gap: 9px;
  padding: 10px 19px; border: 1px solid var(--accent); border-radius: 9px;
  color: var(--bg); background: var(--accent); text-decoration: none; font-weight: 800;
  transition: transform .15s ease, box-shadow .15s ease;
}
.button:hover { transform: translateY(-2px); box-shadow: 0 10px 28px rgba(var(--accent-rgb),.16); }
.text-link { color: var(--accent); text-decoration: none; font-weight: 760; }
.text-link:hover { text-decoration: underline; text-underline-offset: 4px; }
.hero-map { min-width: 0; }
.map-frame {
  position: relative; min-height: 470px; display: grid; grid-template-columns: 1fr 1.08fr 1fr;
  align-items: center; gap: 26px; padding: 28px; border: 1px solid var(--border-strong);
  background: rgba(13,24,36,.74);
}
.map-frame::before, .map-frame::after {
  content: ""; position: absolute; top: 50%; width: 10%; height: 1px; background: var(--accent);
}
.map-frame::before { left: 28%; }
.map-frame::after { right: 28%; }
.map-column { position: relative; z-index: 1; display: grid; gap: 12px; }
.map-label { color: var(--faint); font: 720 11px var(--mono); letter-spacing: .08em; text-transform: uppercase; }
.map-node {
  min-height: 88px; display: grid; align-content: center; gap: 5px; padding: 15px;
  border: 1px solid var(--border); border-radius: 10px; background: var(--surface);
}
.map-node strong { font-size: 14px; }
.map-node span { color: var(--muted); font-size: 12px; line-height: 1.4; }
.map-node.core { min-height: 160px; border-color: var(--accent); text-align: center; background: rgba(var(--accent-rgb),.06); }
.map-node.core .core-mark {
  width: 58px; height: 58px; margin: 0 auto 10px; display: grid; place-items: center;
  border: 1px solid var(--accent); border-radius: 50%; color: var(--accent); font: 850 22px var(--mono);
}
.map-tags { margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap; }
.tag { padding: 6px 9px; border: 1px solid var(--border); border-radius: 999px; color: var(--muted); background: var(--surface); font: 700 11px var(--mono); }
.section { padding: clamp(82px,9vw,128px) 0; }
.section + .section { border-top: 1px solid rgba(56,80,105,.45); }
.section-head { max-width: 790px; margin-bottom: 46px; }
.lead { color: var(--muted); font-size: clamp(17px,1.8vw,21px); }
.journey-tabs {
  display: grid; grid-template-columns: repeat(var(--step-count),1fr); gap: 0;
  border: 1px solid var(--border-strong); background: var(--surface);
}
.journey-tab {
  min-width: 0; min-height: 104px; padding: 17px 14px; border: 0; border-right: 1px solid var(--border);
  color: var(--muted); background: transparent; text-align: left; cursor: pointer;
}
.journey-tab:last-child { border-right: 0; }
.journey-tab:hover { color: var(--text); background: rgba(var(--accent-rgb),.04); }
.journey-tab[aria-selected="true"] { color: var(--text); background: rgba(var(--accent-rgb),.11); box-shadow: inset 0 3px 0 var(--accent); }
.tab-number { display: block; margin-bottom: 7px; color: var(--accent); font: 800 12px var(--mono); }
.journey-tab strong { display: block; font-size: 14px; line-height: 1.3; }
.journey-panel {
  min-height: 280px; display: grid; grid-template-columns: .84fr 1.16fr; gap: 44px; align-items: center;
  padding: clamp(26px,4vw,48px); border: 1px solid var(--border-strong); border-top: 0; background: rgba(13,24,36,.74);
}
.journey-panel[hidden], .atlas-panel[hidden] { display: none; }
.stage-kicker { margin-bottom: 7px; color: var(--accent); font: 750 12px var(--mono); letter-spacing: .08em; text-transform: uppercase; }
.stage-copy p { color: var(--muted); }
.stage-note { padding: 13px 15px; border-left: 2px solid var(--accent); background: rgba(var(--accent-rgb),.06); color: var(--accent-soft) !important; font-size: 13px; }
.stage-visual { min-height: 180px; display: grid; grid-template-columns: repeat(3,1fr); align-items: center; gap: 16px; }
.stage-box { min-height: 112px; display: grid; place-items: center; padding: 13px; border: 1px solid var(--border); border-radius: 9px; text-align: center; background: var(--surface-2); }
.stage-box:nth-child(2) { border-color: var(--accent); color: var(--accent); }
.stage-box strong { font-size: 13px; }
.atlas-shell { border: 1px solid var(--border-strong); background: rgba(13,24,36,.72); }
.atlas-tabs { display: flex; overflow-x: auto; border-bottom: 1px solid var(--border-strong); scrollbar-width: thin; }
.atlas-tab {
  min-height: 54px; flex: 1 0 auto; padding: 10px 18px; border: 0; border-right: 1px solid var(--border);
  color: var(--muted); background: transparent; font-weight: 760; cursor: pointer;
}
.atlas-tab:last-child { border-right: 0; }
.atlas-tab:hover { color: var(--text); }
.atlas-tab[aria-selected="true"] { color: var(--bg); background: var(--accent); }
.atlas-panel { min-height: 370px; padding: clamp(26px,4vw,46px); }
.atlas-grid { display: grid; grid-template-columns: .86fr 1.14fr; gap: 46px; }
.atlas-summary p { color: var(--muted); }
.status-line { display: inline-flex; gap: 8px; align-items: center; color: var(--accent-soft); font: 700 12px var(--mono); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); }
.feature-list { margin: 0; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; list-style: none; }
.feature-list li { min-height: 74px; padding: 13px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); font-size: 13px; line-height: 1.45; }
.feature-list li::before { content: "✓"; margin-right: 8px; color: var(--accent); font-weight: 900; }
.cap-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 14px; }
.cap-card { min-height: 190px; padding: 21px; border: 1px solid var(--border); background: rgba(13,24,36,.74); }
.cap-top { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 26px; }
.cap-index { color: var(--accent); font: 800 12px var(--mono); }
.status-badge { padding: 4px 7px; border: 1px solid var(--border-strong); border-radius: 999px; color: var(--muted); font: 680 10px var(--mono); white-space: nowrap; }
.status-badge.live { border-color: rgba(97,214,164,.45); color: var(--good); }
.status-badge.warn { border-color: rgba(255,182,110,.5); color: var(--warn); }
.cap-card p { margin-bottom: 0; color: var(--muted); font-size: 13px; line-height: 1.55; }
.truth-grid { display: grid; grid-template-columns: repeat(4,1fr); border: 1px solid var(--border-strong); }
.truth-card { min-height: 220px; padding: 24px 20px; border-right: 1px solid var(--border); background: rgba(13,24,36,.72); }
.truth-card:last-child { border-right: 0; }
.truth-symbol { width: 38px; height: 38px; margin-bottom: 32px; display: grid; place-items: center; border: 1px solid var(--accent); border-radius: 50%; color: var(--accent); font: 800 14px var(--mono); }
.truth-card p { color: var(--muted); font-size: 13px; }
.glossary { display: grid; grid-template-columns: repeat(2,1fr); gap: 12px; }
.glossary details { border: 1px solid var(--border); background: rgba(13,24,36,.72); }
.glossary summary { padding: 17px 19px; cursor: pointer; font-weight: 760; list-style: none; }
.glossary summary::-webkit-details-marker { display: none; }
.glossary summary::after { content: "+"; float: right; color: var(--accent); font-family: var(--mono); }
.glossary details[open] summary::after { content: "−"; }
.glossary p { margin: 0; padding: 0 19px 18px; color: var(--muted); font-size: 14px; }
.collection { display: flex; gap: 9px; flex-wrap: wrap; margin-top: 42px; }
.collection a { padding: 7px 10px; border: 1px solid var(--border); border-radius: 999px; color: var(--muted); text-decoration: none; font: 680 11px var(--mono); }
.collection a[aria-current="page"], .collection a:hover { border-color: var(--accent); color: var(--accent); }
.footer { border-top: 1px solid var(--border); }
.footer-inner { width: var(--page); margin: 0 auto; padding: 34px 0 44px; display: flex; justify-content: space-between; gap: 24px; color: var(--faint); font-size: 12px; }
.source-note { max-width: 740px; }
.reveal { opacity: 1; transform: none; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
@media (max-width: 980px) {
  .hero { min-height: auto; grid-template-columns: 1fr; }
  .hero-copy { max-width: 760px; }
  .hero-map { max-width: 720px; }
  .cap-grid { grid-template-columns: repeat(2,1fr); }
  .truth-grid { grid-template-columns: repeat(2,1fr); }
  .truth-card:nth-child(2) { border-right: 0; }
  .truth-card:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
}
@media (max-width: 720px) {
  :root { --page: min(100% - 28px, 1180px); }
  .header-inner { min-height: 58px; }
  .nav-list li:nth-child(-n+2) { display: none; }
  .hero { padding-top: 58px; }
  h1 { font-size: clamp(43px,14vw,64px); }
  .map-frame { min-height: 0; grid-template-columns: 1fr; padding: 18px; gap: 14px; }
  .map-frame::before, .map-frame::after { display: none; }
  .map-node.core { min-height: 130px; }
  .journey-tabs { grid-template-columns: 1fr 1fr; }
  .journey-tab { min-height: 86px; border-bottom: 1px solid var(--border); }
  .journey-panel, .atlas-grid { grid-template-columns: 1fr; }
  .stage-visual { grid-template-columns: 1fr; }
  .feature-list, .cap-grid, .glossary { grid-template-columns: 1fr; }
  .truth-grid { grid-template-columns: 1fr; }
  .truth-card { border-right: 0; border-bottom: 1px solid var(--border); }
  .truth-card:last-child { border-bottom: 0; }
  .footer-inner { flex-direction: column; }
}
@media (max-width: 520px) {
  .nav-list { display: none; }
  .brand { font-size: 15px; }
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after { animation: none !important; transition: none !important; }
  .reveal { opacity: 1; transform: none; }
}
@media print {
  :root { --bg:#fff; --surface:#fff; --surface-2:#fff; --text:#111827; --muted:#46505d; --faint:#64748b; --border:#cbd5e1; --border-strong:#94a3b8; }
  body::before, .site-header, .actions, .collection { display:none; }
  .hero { min-height: auto; }
  .section { padding: 46px 0; break-inside: avoid; }
  .reveal { opacity:1; transform:none; }
}
`

const collection = [
  ["Peerit", "HOW-PEERIT-WORKS.html"],
  ["HiveRelay", "HOW-HIVERELAY-WORKS.html"],
  ["Blind substrate", "HOW-HIVERELAY-BLIND-SUBSTRATE-WORKS.html"],
  ["PearBrowser", "HOW-PEARBROWSER-WORKS.html"],
  ["Agent Harbour", "HOW-AGENT-HARBOUR-WORKS.html"]
]

const pages = [
  {
    file: "HOW-HIVERELAY-WORKS.html",
    title: "How HiveRelay works",
    description: "A plain-language visual explainer of HiveRelay availability, ingress, verification, services, operations, and distribution.",
    brand: "HiveRelay",
    mark: "HR",
    eyebrow: "How HiveRelay works",
    accent: "#ffae2b",
    accentSoft: "#ffe0a1",
    accentRgb: "255,174,43",
    headline: "The always-on layer for Pear apps.",
    subhead: "HiveRelay keeps apps available, reachable, repairable, and verifiable — even when the publisher goes offline.",
    core: ["Relay kernel", "Stores, serves, measures, repairs"],
    left: [["Publisher", "Publishes a signed Hyperdrive"], ["App policy", "Declares what the relay may accept"]],
    right: [["Pear readers", "Fetch and verify app content"], ["Browser & mobile", "Use bounded HTTP or WebSocket ingress"]],
    tags: ["Hyperdrive", "Hyperswarm DHT", "HTTP Range", "WebSocket", "AutoHeal"],
    journeyTitle: "From one publisher to always-on.",
    journeyIntro: "A relay does not replace the P2P network. It joins it, keeps a verified copy warm, and gives clients more ways to reach the same addressed content.",
    steps: [
      ["Publish", "The app publisher shares a Hyperdrive key and a signed request or operator-approved seed policy.", "The content stays addressed by its cryptographic key.", ["Drive key", "Manifest", "Seed policy"]],
      ["Discover", "HiveRelay joins Hyperswarm and advertises or catalogs the app so other peers can find it.", "Catalogs help humans browse; the DHT helps peers connect.", ["DHT", "Catalog", "Relay record"]],
      ["Replicate", "The kernel copies both drive cores, tracks measured bytes, and keeps the content available after the source leaves.", "Public app availability is the persistent plane.", ["Hypercore", "Hyperdrive", "Accounting"]],
      ["Serve", "Readers fetch over direct P2P, streaming HTTP with Range support, Hypercore-over-WS, or a circuit fallback.", "Different clients can choose the transport they can actually use.", ["P2P", "HTTP", "WebSocket"]],
      ["Verify & repair", "Clients verify signed content. Anchor proofs and AutoHeal can recruit diverse relays and repair missing public-app blocks.", "Repair applies to archive-tier drives; blind-cell repair is not live.", ["Proofs", "AutoHeal", "Diversity"]]
    ],
    atlasTitle: "The full feature set, grouped by job.",
    atlasIntro: "HiveRelay is a kernel plus optional layers. Choose a family to see what it adds and where the current evidence boundary sits.",
    atlas: [
      ["Availability", "Keep public Pear apps reachable", "Current kernel", "Seed Hyperdrives and bare Hypercores", "Eagerly replicate both drive cores", "Signed and delta-updated catalogs", "Durable pinning and time-bounded leases", "Superseded-version reclaim", "Measured stored and served bytes"],
      ["Ingress", "Reach browsers, phones, and constrained peers", "Current; several routes opt-in", "Streaming HTTP gateway with Range", "Hypercore replication over WebSocket", "Optional DHT lookup over WebSocket", "Circuit fallback for NAT-constrained peers", "Signed catalogBeeKey discovery", "Optional indexRoom query sidecar", "Opt-in app-origin HTTPS gateway", "Tor transport with separate live-evidence gates"],
      ["Verification", "Prove the relay really has what it claims", "Current; privacy-gated", "Full verifySeeded replication check", "Sampled proof-of-retrievability", "Ed25519 anchor proofs", "Nonce freshness and relay attribution", "Blind/private drives hide possession", "Diverse-relay AutoHeal selection"],
      ["Services", "Add utility protocols without changing the kernel", "Opt-in; maturity and enablement vary", "Identity, storage, and schema helpers", "Production-ready VRF primitives", "AI, ZK, SLA, and arbitration experiments", "Storage-proof and signed-directory providers", "Poker/SignedLog substrate", "Notify and OutboxLog utility providers", "Shard-store, witnesslog, and repair-ticket set", "Wildcard rejection and subscription caps"],
      ["Economics", "Meter use without making it the trust root", "Optional; several paths need live evidence", "Time-bounded paid pin leases", "Direct proofs and bearer vouchers", "Cashu NUT-00/01/02 blind tokens", "Signed storage and served-byte receipts", "Poker usage receipts", "Wallet/subsidy destination controls", "Public reputation and fork-proof reads", "Active leases protected from reclaim"],
      ["Client SDK", "Give apps one bounded integration surface", "Implemented; feature-qualify relay versions", "Content create, open, get, put, list", "Seed, unseed, waitForDurable", "Reader mirrors and community replicas", "Custody and PVSS recovery helpers", "Capability-based quorum selection", "Cross-relay comparison reads", "Identity export, pairing, and revocation", "Verification and accounting helpers"],
      ["Operations", "Run the relay as bounded infrastructure", "Implemented; live proof is release-gated", "Blindspark setup and service manager", "Capacity profiles and finite storage pools", "Eviction, purge, tombstones, reconcile", "Redacted health and metrics views", "Hardened management API", "Restart, rollback, and persistence feedback"],
      ["Distribution", "Ship the same stack across environments", "Mixed publication evidence", "Node CLI and npm packages", "GHCR multi-architecture image path", "Raw systemd fleet with health gates", "Umbrel Blindspark package", "StartOS package source and verification", "Release-evidence sidecars and handoff gates"]
    ],
    capsTitle: "One stack, six surfaces.",
    caps: [
      ["Relay kernel", "implemented", "Seeds, serves, accounts, evicts, and coordinates availability."],
      ["Catalog & discovery", "implemented", "HTTP catalog, signed Hyperbee option, DHT relay records, and deltas."],
      ["Browser ingress", "implemented", "Streaming gateway, Range requests, and WebSocket replication."],
      ["Blind custody", "implemented", "Ciphertext-only custody state machines and blind cells; opt-in providers apply."],
      ["AutoHeal", "implemented", "Verifies archive replicas and repairs missing public-app blocks peer-to-peer."],
      ["Blindspark", "implemented", "Home-server dashboard, setup, wallet destination, services, and live status."],
      ["Paid pin leases", "opt-in", "Quotes and time-bounded leases; direct proofs, vouchers, and Cashu paths."],
      ["Tor transport", "qualified carefully", "Substantial code exists; packaging and live reachability evidence are separate."],
      ["Utility services", "mixed maturity", "Core helpers plus production-ready, opt-in, and experimental providers."],
      ["Bounded storage", "implemented baseline", "Measured caps, pressure recovery, profiles, and planned multi-pool evolution."],
      ["Release automation", "implemented", "Build, smoke, digest, rollout, and store-handoff evidence gates."],
      ["Operator ecosystem", "externally gated", "Official Umbrel/StartOS inclusion depends on upstream review and device proof."]
    ],
    truthTitle: "What is live — and what is not the same thing.",
    truthIntro: "The repository deliberately separates source version, stable channel, image proof, and store availability.",
    truth: [
      ["RC", "Source line", "The monorepo package reports v1.0.0-rc.1. That is a release-candidate source state, not a blanket fleet claim."],
      ["ST", "Stable channel", "The current README records the published application-aware legacy fleet as v0.24.3 while the v1 blind-relay line still requires explicit rollout evidence."],
      ["IMG", "Published image proof", "The TrueNAS community package pins the published multi-architecture GHCR image v0.25.0-rc.9; source, package, appliance, and fleet versions remain separate evidence surfaces."],
      ["EXT", "External distribution", "Official Umbrel and StartOS listings still depend on upstream review, registry proof, and real-device evidence."]
    ],
    glossary: [
      ["Hyperdrive", "A versioned peer-to-peer filesystem built on signed Hypercores."],
      ["DHT", "A distributed address book peers use to find one another without a central directory."],
      ["Seed", "Keep a verified copy of a core or drive available for other peers."],
      ["Anchor proof", "A signed proof used to decide whether a relay really counts toward archive durability."],
      ["AutoHeal", "The repair coordinator for verified public-app replicas. It is not blind-cell repair."],
      ["Blindspark", "HiveRelay packaged as a home-server appliance for Umbrel or StartOS."]
    ],
    source: "Repository-grounded snapshot: HiveRelay README, architecture, blind-custody, capacity, and v0.25 capability-audit documents; reviewed 6 August 2026."
  },
  {
    file: "HOW-HIVERELAY-BLIND-SUBSTRATE-WORKS.html",
    title: "How HiveRelay blind substrate works",
    description: "A plain-language visual explainer of HiveRelay atomic blind custody, PVSS bundles, blind cells, proofs, reconstruction, and honest limits.",
    brand: "HiveRelay blind substrate",
    mark: "BC",
    eyebrow: "How the blind substrate works",
    accent: "#b889ff",
    accentSoft: "#e5d0ff",
    accentRgb: "184,137,255",
    headline: "Relays can hold it without knowing it.",
    subhead: "Your app encrypts and splits the secret. HiveRelay stores verifiable blind cells. A reader who gathers the threshold rebuilds the key locally.",
    core: ["Blind cells", "Opaque, addressed, independently placed"],
    left: [["Publisher edge", "Encrypts before the network"], ["Signed intent", "Binds each cell to one relay"]],
    right: [["Independent relays", "Each holds one opaque cell"], ["Reader edge", "Verifies and reconstructs locally"]],
    tags: ["Ciphertext only", "PVSS", "k-of-n", "Custody receipts", "Expiry witnesses"],
    journeyTitle: "The secret never crosses the relay boundary.",
    journeyIntro: "This illustrative 3-of-5 flow shows the shape. HiveRelay's simulation-recommended production profile is 16 cells with a 10-cell reconstruction threshold.",
    steps: [
      ["Encrypt", "The app creates a random data key and encrypts the content on the publisher's own device.", "Relays never receive the plaintext or data key.", ["Plaintext local", "Ciphertext out", "Random key"]],
      ["Split", "PVSS turns the key into n opaque shares. Any k can reconstruct; fewer than k cannot.", "Public proofs let anyone check that shares are well formed.", ["n shares", "k threshold", "DLEQ proofs"]],
      ["Publish intent", "A signed custody intent names the roster, cell hashes, threshold, commitments, and retention window.", "Every relay must see the intent before any cell upload.", ["Roster", "Manifest", "Retain until"]],
      ["Place", "Exactly one content-addressed cell is uploaded to each assigned relay with a signed pin.", "An orphan or roster mismatch is rejected.", ["One cell", "One relay", "Hash-bound"]],
      ["Prove & expire", "Relays sign receipts and possession proofs. After retention, they stop serving and sign non-serving proofs; witnesses can sign tombstones.", "This proves observed protocol state, not physical disk erasure.", ["Receipt", "Proof", "Tombstone"]],
      ["Rebuild", "A reader fetches cells, re-hashes and verifies every proof, then reconstructs the key and decrypts locally.", "Below the threshold, reconstruction fails closed.", ["Fetch k", "Verify", "Decrypt local"]]
    ],
    atlasTitle: "Three generations, one custody state machine.",
    atlasIntro: "The blind substrate grew in layers. They coexist, but what the relay stores changes.",
    atlas: [
      ["Atomic custody", "Encrypted content handoff", "Shipped since v0.8.0", "Signed intent, receipts, commit", "Logical source-authority retirement", "Ciphertext possession challenges", "Post-expiry non-serving proofs", "Independent witness tombstones", "Append-only custody registry"],
      ["PVSS bundles", "Threshold custody of key shares", "Shipped v0.9.x line", "Publicly verifiable encrypted shares", "Whole bundle stored in a Hypercore", "Relays verify without decrypting", "Threshold reconstruction client-side", "Feldman commitments and DLEQ", "Social-recovery-grade primitive"],
      ["Blind cells", "One independently placeable shard blob", "Shipped v0.22–0.24.x line", "Content address per cell", "Exactly one assigned relay per cell", "4 MiB maximum per cell", "Pin authorization bound to roster", "Deduplicated blob storage", "Client-side recovery helpers"],
      ["Expiry & burn", "Stop serving at the protocol boundary", "Implemented with explicit limits", "60-second custody expiry monitor", "Unseed and non-serving proof", "Immediate burn after source-retired", "Independent witness attestation", "Disk-pressure shedding policy", "No claim of physical deletion"]
    ],
    capsTitle: "What the relay sees — and never sees.",
    caps: [
      ["Opaque cell bytes", "sees", "A content-addressed blob that is meaningless on its own."],
      ["Hashes & commitments", "sees", "Enough public material to verify shape and possession."],
      ["Roster & timing", "sees", "Relay pubkeys, cell index, size, retention, and operational metadata."],
      ["Signed lifecycle", "sees", "Intent, receipt, commit, proof, and witnessed expiry events."],
      ["Plaintext", "never sees", "The application encrypts content before it reaches a relay."],
      ["Data key", "never sees", "Key-material field names are rejected at the schema boundary."],
      ["Share scalars", "never sees", "PVSS verification works without revealing the underlying scalar."],
      ["Complete threshold", "by design", "Independent placement is meant to keep one relay below reconstruction power."],
      ["Decrypted reads", "never sees", "Readers reconstruct and decrypt at their own edge."],
      ["Authorisation truth", "limited", "A valid pin proves assignment; it does not prove the publisher was honest."],
      ["Physical deletion", "cannot prove", "Commodity cryptography cannot prove a remote disk forgot every copy."],
      ["Operator independence", "needs evidence", "Different relay keys do not by themselves prove different owners."]
    ],
    truthTitle: "Honest limits are part of the protocol.",
    truthIntro: "Blind means no plaintext or key material at the relay. It does not mean no metadata, magical deletion, or automatic repair of every cell.",
    truth: [
      ["META", "Metadata still exists", "Cell hashes, public keys, timing, sizes, retention, and access patterns can be visible."],
      ["DEL", "Deletion is observed", "Non-serving proofs and witnesses make continued serving detectable; they do not prove forensic erasure."],
      ["REP", "Cell repair is not live", "Client recovery helpers ship, but relay-side DHT announce and AutoHeal integration for cells remain spec-only."],
      ["COL", "Collusion matters", "A malicious dealer knows the secret, and colluding witnesses or a threshold of cell holders weaken the intended privacy boundary."]
    ],
    glossary: [
      ["Blind cell", "Team shorthand for one content-addressed blind-shard blob. The code uses shard terminology."],
      ["PVSS", "Publicly verifiable secret sharing: shares can be checked without revealing the secret."],
      ["k-of-n", "Any k shares out of n can reconstruct; fewer than k cannot."],
      ["Custody receipt", "A relay's signature saying it accepted the exact encrypted item named by the intent."],
      ["Source retirement", "A signed lifecycle checkpoint that retires future authority; it is not proof the source erased local bytes."],
      ["Tombstone", "A witness-signed observation that a relay was not serving the item after expiry."]
    ],
    source: "Repository-grounded snapshot: HiveRelay BLIND-CELLS, ATOMIC-BLIND-CUSTODY, dealer-contract, crypto-guarantees, and v0.25 capability-audit documents; reviewed 6 August 2026."
  },
  {
    file: "HOW-PEARBROWSER-WORKS.html",
    title: "How PearBrowser works",
    description: "A plain-language visual explainer of PearBrowser Desktop: tabs, hyper:// browsing, app catalogues, publishing, search, identity, local AI, plugins, direct peers, HiveRelay, and native delivery.",
    brand: "PearBrowser",
    mark: "PB",
    eyebrow: "How PearBrowser works",
    accent: "#35cfff",
    accentSoft: "#b9efff",
    accentRgb: "53,207,255",
    headline: "The P2P web, in a real desktop browser.",
    subhead: "Open hyper:// sites, discover verified apps, publish, search, and connect directly to peers — with your data kept local.",
    mapLeftLabel: "Desktop edge",
    mapCoreLabel: "Core (local)",
    mapRightLabel: "Network & apps",
    core: ["Bare backend", "Hyperdrive, Hyperbee, Hyperswarm"],
    left: [["Browser chrome", "Tabs, address bar, history, permissions"], ["Local identity", "Backup, profile, app grants"]],
    right: [["Direct peers", "P2P discovery, fetch, sync"], ["HiveRelay", "Optional fast and availability path"]],
    tags: ["hyper://", "Content Shield", "Pear Plugins", "Local QVAC", "Pear v3 packages"],
    journeyTitle: "One address, two network routes.",
    journeyIntro: "PearBrowser resolves the address locally, prefers direct P2P, and can race an optional HiveRelay route. The same cryptographic content identity is checked either way.",
    steps: [
      ["Enter or discover", "Type a hyper:// key or pearname, reopen history, or choose an entry from one of the browser's catalogues.", "A catalogue helps discovery; it does not become authority over the content key.", ["Address bar", "pearname", "Catalogue"]],
      ["Resolve & trust", "The backend normalizes the target, resolves local names and catalogue records, and keeps verification provenance.", "Unsafe rows are dropped. Native execution is never inferred from an arbitrary remote link.", ["Normalize", "Resolve", "Provenance"]],
      ["Fetch best route", "PearBrowser discovers Hyperdrive peers through Hyperswarm and can race a HiveRelay gateway for reach or speed.", "Direct P2P stays first-class; the relay is an optional route to the same addressed content.", ["Hyperswarm", "HiveRelay", "Hyperdrive"]],
      ["Run isolated", "The browser-owned proxy loads the page into its tab and injects only the bridge surface allowed for that drive.", "Drive-scoped loopback origins are on by default, with CSP-safe injection and scoped tokens.", ["Tab", "Origin", "Content Shield"]],
      ["Grant capabilities", "A page can request login, identity, local-first sync, contacts, or swarm channels through explicit host policy and consent.", "The renderer does not own raw swarm sockets or long-lived keys; the Bare backend does.", ["Consent", "Grant", "window.pear"]],
      ["Keep or publish", "Bookmarks, history, settings, and app state stay local. The block editor can publish a new Hyperdrive and wait for durable HiveRelay pinning.", "Published means durability was confirmed, not merely requested.", ["Hyperbee", "Publish", "Durable"]]
    ],
    atlasTitle: "The complete desktop surface, grouped by job.",
    atlasIntro: "The desktop app is a browser, app store, publisher, search and naming layer, identity host, P2P API broker, local AI surface, and native delivery path.",
    atlas: [
      ["Browse", "Use a familiar multi-tab browser for the P2P web", "Current desktop surface", "hyper:// address bar with hex and z-base-32 keys", "Tabs, back/forward, reload, restore, and keyboard shortcuts", "Autocomplete from local bookmarks and history", "About this site with key formats and copy actions", "Direct Hyperdrive loading through the local proxy", "Page sandbox and browser-owned bridge shims"],
      ["Apps", "Discover content and install executable apps safely", "Current; Pear v3 install is an explicit host-confirmed action", "Hyperdrive, signed Hyperbee, Autobee, sheets, and index-room sources", "Curated, community, read-only, and writable personal catalogues", "Pear v3 listings bind canonical link, version, product name, and platforms", "Signed submission receipts keep review and approval exact", "hyper:// content opens in a tab", "Native packages pass identity, target, destination, upgrade, and GUI-artifact checks"],
      ["Publish", "Build a site and make it durably available", "Current; durability is confirmed", "Heading, text, image, link, list, quote, code, and divider blocks", "Raw HTML, CSS, and JavaScript blocks for advanced pages", "One-click Hyperdrive publish", "Shareable drive keys", "Automatic HiveRelay pin request", "waitForDurable before success is reported", "Signed unseed revocation"],
      ["Library", "Keep your browser state local and useful", "Current; local-first", "Hyperbee bookmarks and history", "Fast address-bar autocomplete", "Session and per-tab navigation restore", "Local storage usage and cache controls", "Device Sync for tabs, bookmarks, and settings", "Reset paths preserve signed unseed semantics"],
      ["Search & names", "Find local knowledge first, then ask trusted peers", "Current; network federation is opt-in", "Immediate personal-index first paint", "Bounded trusted-peer federation", "Digest checks, provenance, and stale-query suppression", "pearname:// local petnames and owned records", "Trusted-contact and curated name layers", "Unicode and homograph guardrails", "Trusted-contact Nostr event feed stored locally"],
      ["Identity & APIs", "Give each app the smallest useful capability", "Current; consent and grants apply", "12-word BIP39 backup and restore", "Per-app public keys and domain-separated signatures", "Connected-app review and revocation", "window.pear.login profile consent", "window.pear.sync local-first state", "window.pear.swarm.v1 direct peer channels", "Topic tiers, rate limits, and short-lived bridge tokens"],
      ["Shield & plugins", "Block unwanted traffic and extend the browser", "Current in v0.8.0", "Browser-owned ad and tracker blocking", "Requests blocked before they reach peers or relays", "Cosmetic hiding and CSP-safe scriptlets", "Per-drive allow, balanced, and strict modes", "P2P filter-list drives with SHA-256 verification", "Pear Plugins installed from Hyperdrives", "Capability changes auto-disable pending re-approval"],
      ["Local AI", "Ask about a page without sending it to a cloud model", "Experimental desktop MVP", "Ask Browser side panel for the active tab", "Browser-owned QVAC or approved local Qwen models", "On-device streaming, cancellation, and follow-ups", "Visible source provenance and bounded page context", "Blank-tab quick ask never captures page context", "Pages cannot access browser-chrome AI commands", "Page text is treated as untrusted evidence"],
      ["Desktop delivery", "Ship the browser and compatible native apps", "v0.8.0 is published; public trust is separately gated", "Embedded Pear v3 host migration", "macOS, Windows, and Linux package targets", "SHA-256 sidecars and package manifests", "macOS app zip package workflow", "Windows MSIX package workflow", "Linux AppImage with desktop metadata", "Package-proof and public-trust modes stay distinct"]
    ],
    capsTitle: "The desktop product, in plain language.",
    caps: [
      ["Desktop chrome", "implemented", "Tabs, address bar, shortcuts, history, bookmarks, restore, and site information."],
      ["P2P browsing", "implemented", "Load Hyperdrive sites directly, with HiveRelay available as an optional parallel route."],
      ["App catalogues", "implemented", "Aggregate many decentralized sources through one safety-normalized model."],
      ["Verified installs", "explicit action", "Keep in-tab hyper content separate from host-confirmed Pear v3 native package installation."],
      ["Publisher", "implemented", "Compose a site, publish its Hyperdrive, pin it, confirm durability, and revoke seeding."],
      ["Local library", "device owned", "Keep bookmarks, history, tab state, settings, and personal search data on the machine."],
      ["Search & naming", "local first", "Return local results immediately and federate only when the user asks trusted peers."],
      ["Identity host", "consent", "Back up one identity while issuing per-app keys, signatures, profile fields, and revocable grants."],
      ["P2P page APIs", "consent tiers", "Offer sync and direct swarm channels without giving pages raw backend keys or sockets."],
      ["Content Shield", "implemented", "Block requests in the proxy and apply per-drive cosmetic rules before content renders."],
      ["Pear Plugins", "implemented", "Install capability-declared Hyperdrive extensions and re-approve permission escalation."],
      ["Ask Browser", "experimental", "Stream a local model answer about the active page through a browser-owned private channel."]
    ],
    truthTitle: "What the desktop release actually claims.",
    truthIntro: "The product is broad, but its trust and distribution boundaries stay explicit.",
    truth: [
      ["LIVE", "v0.8.0 is published", "The live release makes Pear v3 delivery an explicit catalogue contract and includes the embedded v3 host, private-search home, reconnect-safe RPC, shield, plugins, local AI, search, naming, Nostr, and publishing work."],
      ["ISO", "Per-drive origins by default", "Each Hyperdrive page gets a drive-scoped loopback origin. Tokens, CSP, grants, and browser-owned RPC keep page powers bounded."],
      ["APP", "Browsing is not execution", "A hyper:// site can open in a tab. A native application needs a compatible, verified Pear v3 package and an explicit host-confirmed install action."],
      ["TRUST", "Signing is a separate gate", "Package-proof artifacts are not public-trust proof. macOS notarization and Windows signing remain required for announcement-ready native assets."]
    ],
    glossary: [
      ["Bare backend", "The separate local process that owns P2P networking, storage, identity, and browser services behind the renderer."],
      ["hyper://", "An address for content inside a Hyperdrive rather than on a traditional web server."],
      ["Hyperdrive", "A signed P2P filesystem whose key gives content a stable cryptographic address."],
      ["Hyperbee", "An ordered key-value database stored on Hypercore; PearBrowser uses it for local browser data and signed catalogues."],
      ["Hyperswarm", "The peer discovery and encrypted connection layer used to find and talk directly to other peers."],
      ["HiveRelay", "Optional always-on infrastructure that can seed content and provide another gateway route without becoming the content authority."],
      ["Pear Plugin", "A Hyperdrive extension that declares the browser capabilities it contributes and must be re-approved if those capabilities grow."],
      ["Pear v3 release", "A catalogue contract for a released native app and its verified OS package. Installation stays separate from content opened in a browser tab."]
    ],
    source: "Repository-grounded desktop snapshot: published PearBrowser Desktop v0.8.0 release, Architecture and Capabilities, Security Boundary Alignment, Ask Browser, Content Shield / Plugins, and native delivery documents; reviewed 6 August 2026."
  },
  {
    file: "HOW-AGENT-HARBOUR-WORKS.html",
    title: "How Agent Harbour works",
    description: "A plain-language visual explainer of Agent Harbour passports, encrypted memory, direct and outbox routes, local QVAC, governed tools, receipts, and evidence gates.",
    brand: "Agent Harbour",
    mark: "AH",
    eyebrow: "How Agent Harbour works",
    accent: "#65dca8",
    accentSoft: "#c6f5df",
    accentRgb: "101,220,168",
    headline: "An agent that stays yours.",
    subhead: "Harbour keeps identity, encrypted memory, permissions, work, and receipts under the owner's control — even when the chat surface or model changes.",
    core: ["Harbour worker", "Plans, enforces policy, routes work"],
    left: [["Workspace edge", "Buzz, Hivemind, or another requester"], ["Owner vault", "Passport, workspace keys, peer routes"]],
    right: [["Local paths", "Canonical memory, Blind Core, QVAC"], ["External paths", "Direct peers, blind Outbox, governed tools"]],
    tags: ["Passport", "Encrypted state", "Approvals", "QVAC", "Signed receipts"],
    journeyTitle: "From a request to a receipt.",
    journeyIntro: "The collaboration surface can ask for work. Harbour remains the trust root and decides which identity, memory, permission, route, model, and tool may be used.",
    steps: [
      ["Request", "A workspace sends a bounded job. It does not receive the Passport, vault keys, or root authority.", "Buzz or Hivemind is an edge, not the agent's owner.", ["Job", "Context", "Requester"]],
      ["Plan", "The worker loads only relevant encrypted state, evaluates policy, and builds an infer, act, delegate, wait, or gate plan.", "Child agents receive sliced context, never coordinator vault keys.", ["Policy", "Task DAG", "Context slice"]],
      ["Ask approval", "Sensitive or irreversible actions become exact prepared actions for the owner to approve, deny, or narrow.", "Narrowing can never widen the signed request.", ["Typed grant", "One-shot", "Owner decision"]],
      ["Act", "Harbour chooses a direct session, blind Outbox, local QVAC subprocess, same-device specialist, or reviewed tool provider.", "There is no silent privacy downgrade or implicit external fallback.", ["Route", "Lease", "Execution"]],
      ["Receipt", "Results, acknowledgements, spend entries, and evidence retain the exact semantic stage they proved.", "Queued is not delivered; relay admission is not recipient delivery.", ["Signed ACK", "Result", "Audit trail"]]
    ],
    atlasTitle: "Choose a route; the policy stays in charge.",
    atlasIntro: "Different work needs different paths. Harbour makes the boundary visible and refuses to turn one kind of evidence into another.",
    atlas: [
      ["Direct", "Live owner-to-peer interaction", "Implemented, explicit opt-in", "Hyperswarm dormant until enabled", "Authenticated transport session", "Signed ACK required for delivery", "Encrypted replay state", "Fallback only when policy allows", "Two-device live gate still pending"],
      ["Outbox", "Sleeping and offline continuity", "Implemented; live gate pending", "Opaque directional lane tags", "Qualified HiveRelay namespaces", "Multi-relay durable admission", "CAS and idempotent commit", "Stable job-ID deduplication", "Reverse-lane signed receipt"],
      ["Local QVAC", "Private owner-device inference", "Component-exercised", "Separate Bare OS subprocess", "Lazy model load and streaming", "Bounded request and cancellation", "Prompt stays on owner device", "Character and evaluator integration", "Packet-capture and soak still pending"],
      ["Governed tools", "Reviewed external capabilities", "Implemented, disabled by default", "Trusted host-installed providers only", "No renderer code execution", "Job claim, lease, grant, policy", "Exact approval for irreversible effects", "Web fetch/search first-party providers", "Wallet/x402 beta paths, no autonomy"],
      ["Memory & exit", "Carry the agent across surfaces", "Implemented locally", "Argon2id/XChaCha owner vault", "Encrypted Hyperbee canonical state", "Chained Blind Core checkpoints", "Rotatable runtime/transport keys", "Versioned encrypted exit archive", "Fresh-device remote proof pending"],
      ["Crews", "Delegate without sharing the vault", "Implemented foundation", "Same-device registered specialists", "Sliced and redacted child context", "ACK separate from signed result", "Depth threshold approval", "Read-only brain status GUI", "Task plans not yet persisted"]
    ],
    capsTitle: "What Harbour owns and guards.",
    caps: [
      ["Passport", "implemented", "Stable owner-controlled identity with rotatable runtime and transport bindings."],
      ["Owner vault", "implemented", "Encrypted keys, routes, settings, and recovery commitments; lock tears down services."],
      ["Canonical memory", "implemented", "Encrypted Hyperbee owns memory, jobs, grants, approvals, receipts, and settings."],
      ["Blind Core", "local implemented", "Encrypted chained checkpoints; remote durability and independence remain separate facts."],
      ["Agent Cards", "implemented", "Dual-signed public presentation with no root, runtime, or tool authority."],
      ["Contact tickets", "implemented", "Private subject-bound route admission, bearer-sensitive until expiry."],
      ["Authority gateway", "implemented", "Typed grants, runtime leases, claims, fencing, and exact approval binding."],
      ["Brain layer", "implemented", "Character, semantic memory, evaluators, task DAG vocabulary, plugins, and learn loop."],
      ["Wallet & x402", "disabled by default", "Every irreversible spend requires exact one-shot owner approval; no autonomous spending."],
      ["Spending ledger", "implemented", "Signed hash-chain of approved spend execution; not a blockchain balance proof."],
      ["Privacy SDK", "contract implemented", "Fail-closed local, private, and resilient profiles against real inventory."],
      ["Pear Deploy profile", "integration seam", "Describes a future deploy contract; this package does not publish or deploy."]
    ],
    truthTitle: "What Harbour refuses to pretend.",
    truthIntro: "The product's claim discipline is a feature: every status says exactly what has been observed.",
    truth: [
      ["ACK", "Admission is not delivery", "A relay can durably accept encrypted work without proving the recipient fetched it. Delivery needs the reverse receipt."],
      ["IND", "Keys are not operators", "Different relay public keys do not prove different owners, regions, or independent custody."],
      ["AI", "Process isolation is not a new privacy party", "Local QVAC runs separately, but it still sees plaintext on the same owner-controlled device."],
      ["REL", "Development is not release", "Live relay/device gates, fresh-device recovery, target-hardware soak, notarisation, and a Pear v3 native release record remain pending."]
    ],
    glossary: [
      ["Passport", "The stable identity root an agent keeps when runtimes, transports, models, or workspaces change."],
      ["Canonical state", "The authoritative encrypted record. Network transports carry copies and messages but do not become the source of truth."],
      ["Blind Core", "A signed Hypercore of encrypted, predecessor-chained checkpoints used for continuity and restore."],
      ["Outbox", "Opaque store-and-forward lanes for work sent while a recipient is offline."],
      ["QVAC", "The local model route Harbour runs in a separate Bare OS subprocess on the owner's device."],
      ["Evidence gate", "A test or live exercise required before a capability can be promoted to a stronger maturity claim."]
    ],
    source: "Repository-grounded snapshot: Agent Harbour README, Implementation Status, Architecture, SDK, provider, and QVAC/Pear roadmap documents; reviewed 6 August 2026."
  }
]

function esc(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;")
}

function mapNodes(items) {
  return items.map((item) => '<div class="map-node"><strong>' + esc(item[0]) + '</strong><span>' + esc(item[1]) + '</span></div>').join("")
}

function journey(page) {
  const tabs = page.steps.map((step, index) => '<button class="journey-tab" type="button" role="tab" id="journey-tab-' + index + '" aria-selected="' + (index === 0 ? "true" : "false") + '" aria-controls="journey-panel-' + index + '" tabindex="' + (index === 0 ? "0" : "-1") + '"><span class="tab-number">0' + (index + 1) + '</span><strong>' + esc(step[0]) + '</strong></button>').join("")
  const panels = page.steps.map((step, index) => '<div class="journey-panel" role="tabpanel" id="journey-panel-' + index + '" aria-labelledby="journey-tab-' + index + '"' + (index === 0 ? "" : " hidden") + '><div class="stage-copy"><p class="stage-kicker">Step ' + (index + 1) + '</p><h3>' + esc(step[0]) + '</h3><p>' + esc(step[1]) + '</p><p class="stage-note">' + esc(step[2]) + '</p></div><div class="stage-visual"><div class="stage-box"><strong>' + esc(step[3][0]) + '</strong></div><div class="stage-box"><strong>' + esc(step[3][1]) + '</strong></div><div class="stage-box"><strong>' + esc(step[3][2]) + '</strong></div></div></div>').join("")
  return '<div class="journey-tabs reveal" role="tablist" aria-label="Journey steps" style="--step-count:' + page.steps.length + '">' + tabs + '</div>' + panels
}

function atlas(page) {
  const tabs = page.atlas.map((item, index) => '<button class="atlas-tab" type="button" role="tab" id="atlas-tab-' + index + '" aria-selected="' + (index === 0 ? "true" : "false") + '" aria-controls="atlas-panel-' + index + '" tabindex="' + (index === 0 ? "0" : "-1") + '">' + esc(item[0]) + '</button>').join("")
  const panels = page.atlas.map((item, index) => {
    const features = item.slice(3).map((feature) => "<li>" + esc(feature) + "</li>").join("")
    return '<div class="atlas-panel" role="tabpanel" id="atlas-panel-' + index + '" aria-labelledby="atlas-tab-' + index + '"' + (index === 0 ? "" : " hidden") + '><div class="atlas-grid"><div class="atlas-summary"><p class="stage-kicker">' + esc(item[0]) + '</p><h3>' + esc(item[1]) + '</h3><p>Explore the concrete capabilities in this family. The status line describes the current evidence boundary, not a marketing tier.</p><span class="status-line"><span class="status-dot"></span>' + esc(item[2]) + '</span></div><ul class="feature-list">' + features + '</ul></div></div>'
  }).join("")
  return '<div class="atlas-shell reveal"><div class="atlas-tabs" role="tablist" aria-label="Capability families">' + tabs + '</div>' + panels + '</div>'
}

function badgeClass(status) {
  const value = status.toLowerCase()
  if (value.includes("pending") || value.includes("cannot") || value.includes("never") || value.includes("mixed") || value.includes("external")) return " warn"
  if (value.includes("implemented") || value.includes("live") || value.includes("sees")) return " live"
  return ""
}

function caps(page) {
  return page.caps.map((item, index) => '<article class="cap-card reveal"><div class="cap-top"><span class="cap-index">' + String(index + 1).padStart(2, "0") + '</span><span class="status-badge' + badgeClass(item[1]) + '">' + esc(item[1]) + '</span></div><h3>' + esc(item[0]) + '</h3><p>' + esc(item[2]) + '</p></article>').join("")
}

function truths(page) {
  return page.truth.map((item) => '<article class="truth-card"><div class="truth-symbol">' + esc(item[0]) + '</div><h3>' + esc(item[1]) + '</h3><p>' + esc(item[2]) + '</p></article>').join("")
}

function glossary(page) {
  return page.glossary.map((item) => '<details><summary>' + esc(item[0]) + '</summary><p>' + esc(item[1]) + '</p></details>').join("")
}

function collectionLinks(page) {
  return collection.map((item) => '<a href="' + item[1] + '"' + (item[1] === page.file ? ' aria-current="page"' : "") + '>' + esc(item[0]) + '</a>').join("")
}

function render(page) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="' + esc(page.description) + '"><meta name="color-scheme" content="dark"><title>' + esc(page.title) + '</title><style>' + sharedCss + ':root{--accent:' + page.accent + ';--accent-soft:' + page.accentSoft + ';--accent-rgb:' + page.accentRgb + '}</style></head><body><a class="skip-link" href="#main">Skip to explainer</a><header class="site-header"><div class="header-inner"><a class="brand" href="#top"><span class="brand-mark">' + esc(page.mark) + '</span>' + esc(page.brand) + '</a><nav aria-label="Page sections"><ul class="nav-list"><li><a href="#journey">Journey</a></li><li><a href="#atlas">Features</a></li><li><a href="#truth">Status</a></li></ul></nav></div></header><main id="main"><section class="hero" id="top"><div class="hero-copy reveal"><p class="eyebrow">' + esc(page.eyebrow) + '</p><h1>' + esc(page.headline) + '</h1><p>' + esc(page.subhead) + '</p><div class="actions"><a class="button" href="#journey">Explore the system →</a><a class="text-link" href="#glossary">Plain-English glossary</a></div></div><div class="hero-map reveal"><div class="map-frame"><div class="map-column"><span class="map-label">' + esc(page.mapLeftLabel || "Input & owner edge") + '</span>' + mapNodes(page.left) + '</div><div class="map-column"><span class="map-label">' + esc(page.mapCoreLabel || "Core") + '</span><div class="map-node core"><span class="core-mark">' + esc(page.mark) + '</span><strong>' + esc(page.core[0]) + '</strong><span>' + esc(page.core[1]) + '</span></div></div><div class="map-column"><span class="map-label">' + esc(page.mapRightLabel || "Routes & readers") + '</span>' + mapNodes(page.right) + '</div></div><div class="map-tags">' + page.tags.map((tag) => '<span class="tag">' + esc(tag) + '</span>').join("") + '</div></div></section><section class="section" id="journey"><div class="section-head reveal"><p class="eyebrow">The journey</p><h2>' + esc(page.journeyTitle) + '</h2><p class="lead">' + esc(page.journeyIntro) + '</p></div>' + journey(page) + '</section><section class="section" id="atlas"><div class="section-head reveal"><p class="eyebrow">Feature atlas</p><h2>' + esc(page.atlasTitle) + '</h2><p class="lead">' + esc(page.atlasIntro) + '</p></div>' + atlas(page) + '</section><section class="section" id="capabilities"><div class="section-head reveal"><p class="eyebrow">Capability map</p><h2>' + esc(page.capsTitle) + '</h2></div><div class="cap-grid">' + caps(page) + '</div></section><section class="section" id="truth"><div class="section-head reveal"><p class="eyebrow">Evidence boundary</p><h2>' + esc(page.truthTitle) + '</h2><p class="lead">' + esc(page.truthIntro) + '</p></div><div class="truth-grid reveal">' + truths(page) + '</div></section><section class="section" id="glossary"><div class="section-head reveal"><p class="eyebrow">Glossary</p><h2>Words that carry the system.</h2><p class="lead">Open a term for the short version.</p></div><div class="glossary reveal">' + glossary(page) + '</div><nav class="collection" aria-label="Explainer collection">' + collectionLinks(page) + '</nav></section></main><footer class="footer"><div class="footer-inner"><span class="source-note">' + esc(page.source) + '</span><span>Self-contained HTML · no network required</span></div></footer><script>' + clientScript + '</script></body></html>'
}

const clientScript = `
(function () {
  function wire(groupSelector, tabSelector, panelPrefix) {
    document.querySelectorAll(groupSelector).forEach(function (group) {
      var tabs = Array.from(group.querySelectorAll(tabSelector))
      function select(index, focus) {
        tabs.forEach(function (tab, i) {
          var active = i === index
          tab.setAttribute("aria-selected", active ? "true" : "false")
          tab.tabIndex = active ? 0 : -1
          var panel = document.getElementById(panelPrefix + i)
          if (panel) panel.hidden = !active
        })
        if (focus) tabs[index].focus()
      }
      tabs.forEach(function (tab, index) {
        tab.addEventListener("click", function () { select(index, false) })
        tab.addEventListener("keydown", function (event) {
          var next = index
          if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % tabs.length
          else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + tabs.length) % tabs.length
          else if (event.key === "Home") next = 0
          else if (event.key === "End") next = tabs.length - 1
          else return
          event.preventDefault()
          select(next, true)
        })
      })
    })
  }
  wire(".journey-tabs", ".journey-tab", "journey-panel-")
  wire(".atlas-tabs", ".atlas-tab", "atlas-panel-")
})()
`

for (const page of pages) {
  await fs.writeFile(path.join(docsDir, page.file), render(page))
}

console.log("Built " + pages.length + " explainers:")
for (const page of pages) console.log(" - docs/" + page.file)
