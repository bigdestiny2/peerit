# Peerit Growth and Automation Spec

Date: 2026-06-27

This spec combines the launch strategy, the second-agent advice, and the current
Peerit/PearBrowser/HiveRelay architecture into an executable roadmap.

The goal is not to buy anonymous traffic. The goal is to create a small number
of living, defensible communities, prove the P2P UX in PearBrowser, and only
then spend into channels that produce activated posters.

## Core Thesis

Peerit should launch as:

> A proof-of-work gated, no-account, peer-to-peer Reddit that reads on the web
> and writes in PearBrowser.

That means three things must be true before paid traffic:

1. Spam must stop being free.
2. New users must not land in a ghost town.
3. The first click must show value before asking users to install PearBrowser.

It also means HiveRelay node adoption is part of distribution, not just
infrastructure. Every useful node can become a public proof surface, referral
surface, and local advertising surface for Peerit and PearBrowser.

## Non-Negotiable Preflight Gates

### Gate 1: Proof-of-Work Before Traffic

Peerit identities are cheap Ed25519 keypairs. That is good for no-account UX, but
bad for Sybil/spam resistance. Paid traffic must not begin until new posts,
comments, and community creation are proof-of-work gated.

Implementation should port the proven `p2pbuilders` design:

- Source pattern: `02-apps/p2pbuilders/js/pow.js`.
- Gossip hook pattern: `02-apps/p2pbuilders/js/gossip.js` `validate(type, val)`.
- Domain signing pattern: `02-apps/p2pbuilders/js/data.js` `_powSign()`.

Recommended initial difficulty:

| Action | Bits | Notes |
| --- | ---: | --- |
| Vote | 0 | Exempt; ranking should be reputation-weighted. |
| Profile edit | 0 | Exempt; rate-limit in UI if needed. |
| Comment | 14 | Cheap for humans, costly for floods. |
| Post | 16 | Should feel like a short "minting" moment. |
| Community create | 18-20 | Prevents name squatting and board spam. |
| New identity burst | +2 to +4 | Optional adaptive gate after repeated actions. |
| Trusted/aged identity | -1 to -2 | Optional later; avoid premature complexity. |

Acceptance criteria:

- Unsigned records are rejected in secure mode.
- Signed records without valid PoW are rejected before entering outbox cache.
- PoW is bound to immutable record identity, not mutable text body.
- Edits/deletes reuse the original PoW and require a fresh signature.
- Tampering with `cid`, author, community, created time, or PoW invalidates the
  record.
- Tests cover no-PoW rejection, tamper rejection, valid ingest, edit reuse, and
  community-create difficulty.
- UI shows a short progress state while minting.

### Gate 2: Seed the First Living Communities

Ads into empty boards will convert poorly. Before paid traffic, seed 8-15 boards
with founders, starter posts, norms, and moderation overlays.

Initial board list:

| Board | Audience | Launch Role |
| --- | --- | --- |
| `p2pbuilders` | Pear, Holepunch, P2P builders | Technical flagship. |
| `nostr` | Nostr users/builders | Best ideological fit. |
| `selfhosted` | Homelab and self-hosting users | Practical infrastructure crowd. |
| `privacy` | PrivacyGuides, degoogle, Brave users | No-account/no-server pitch. |
| `linux` | Linux/FOSS users | High technical overlap. |
| `localfirst` | Local-first software people | Product philosophy match. |
| `ai_local` | Local AI and GPU users | Bridge to HiveCompute later. |
| `fediverse` | Lemmy/Mastodon/Mbin users | "No servers at all" narrative. |
| `cypherpunk` | Bitcoin/Lightning/privacy builders | Censorship-resistance audience. |
| `redditalternatives` | Users seeking community exits | High-intent switchers. |
| `hiverelay` | Relay operators and node-curious users | Infrastructure-as-growth channel. |
| `homelab` | Operators and seeders | Future relay/operator channel. |
| `showcase` | Launch demos and user projects | Keeps the first screen alive. |

Acceptance criteria:

- Each board has an owner/moderator identity.
- Each board has 10-20 starter posts, at least 3 discussion prompts, and a pinned
  norms post.
- At least 20 founding posters exist across the network.
- The front page has fresh posts every day for the first 14 days.
- Moderation overlay is exercised before launch.

### Gate 3: Kill Install Friction

The launch funnel should be:

```text
Ad/post/link -> read-only web/gateway page -> open live P2P thread in PearBrowser
```

PearBrowser remains the write/runtime gateway, but first-contact users should be
able to read a real thread before installation.

Acceptance criteria:

- Every board and post has a gateway-readable URL.
- Gateway pages show live-ish public content, proof labels, and the PearBrowser
  open action.
- The CTA explains the exchange clearly: read on the gateway, post through
  PearBrowser.
- Gateway pages do not pretend to be the canonical database. They are previews
  over P2P content.

## Product Implementation Spec

### P0: Spam and Trust

Files likely to change:

- `js/pow.js`: new Peerit PoW module, adapted from `p2pbuilders`.
- `js/gossip.js`: add optional `validate(type, val)` path.
- `js/data.js`: mint PoW before signing posts/comments/communities.
- `js/app.js`: minting progress UI and copy.
- `test/gossip.mjs`: no-PoW, tamper, and ingest tests.
- `test/smoke.mjs`: UI/domain smoke for normal creation paths.

Add reputation-weighted ranking after PoW:

- Keep raw vote counts visible as social feedback.
- Use weighted vote scores for ranking.
- Weight should start small for fresh keys and grow with age plus received
  upvotes.
- Keep formula simple and auditable.

### P1: Read-Only Gateway

Implement a gateway reader that can render:

- front page;
- board page;
- post page with comments;
- profile page;
- proof/about page.

Suggested approach:

- Build a relay-side or static-export reader from known outboxes.
- Generate immutable/static pages on a schedule while the full app remains P2P.
- Include signed metadata/proof snippets so technical users can inspect how the
  page was derived.
- Add UTM-aware open links into PearBrowser.

Gateway non-goals:

- Do not allow writing from the gateway in v1.
- Do not centralize moderation decisions server-side.
- Do not require accounts, email, or hosted identity.

### P1.5: HiveRelay Operator Growth Loop

HiveRelay nodes should be treated as a growth channel with verifiable work at the
center. A node operator is not just a server host; they are a local ambassador
with public evidence that they help keep Peerit and Pear apps online.

The loop:

```text
run a node -> earn for useful work -> publish proof/referral page -> recruit
users/operators -> increase app demand -> increase useful node work
```

Useful node work:

| Work | Growth Value | Reward Basis |
| --- | --- | --- |
| Peerit app drive seeding | Keeps the app loadable. | Fresh-reader and gateway proof. |
| Peerit outbox seeding | Prevents public records from vanishing when authors go offline. | Outbox availability proof and byte/accounting caps. |
| Gateway serving | Gives first-click users a fast read-only preview. | Gateway reads served, latency, and region. |
| Regional relay coverage | Makes decentralization visible. | Region diversity and uptime. |
| Release/storage proofing | Builds trust in the launch. | Signed proof freshness. |
| Operator referrals | Turns nodes into acquisition surfaces. | Activated posters and retained operators, not raw clicks. |

Operator-facing surfaces:

- Public node identity page: region, uptime, bytes served, apps seeded, proof
  age, and referral link.
- Operator leaderboard: useful work, not vanity impressions.
- Regional node map: "Peerit served by HiveRelay nodes in these regions."
- Founder-node badge: early operators get social status.
- Operator launch kit: copy, banners, proof-page links, and referral UTM links.
- Proof dashboard: app availability, outbox availability, gateway health, and
  release proof state.

Reward rules:

- Pay for verifiable infrastructure work first.
- Pay marketing bonuses only for activated/retained users or recruited
  operators.
- Do not pay for raw clicks, impressions, spam posts, or low-quality signups.
- Cap any one operator's referral rewards until moderation quality and retention
  are known.
- Keep all reward criteria public and reproducible enough to audit.

### P2: Launch Content System

Create a structured launch directory:

```text
launch/
  communities.json
  seed-posts/
    p2pbuilders.md
    nostr.md
    selfhosted.md
  creators.csv
  channels.json
  ads/
    creative-matrix.json
    utm-links.csv
  reports/
```

Recommended automation:

- `npm run launch:readiness`
  - verifies PoW tests, manifest, gateway URLs, seed boards, and landing pages.
- `npm run launch:seed-plan`
  - reads `launch/communities.json` and outputs moderator briefs, starter post
    checklists, and a 14-day editorial calendar.
- `npm run launch:utm`
  - generates tagged links by channel, creative, board, and campaign.
- `npm run launch:briefs`
  - creates sponsor/KOL briefs from approved templates.
- `npm run launch:report`
  - aggregates manually exported ad data plus gateway/PearBrowser event counts.

Automation boundary:

- Scripts may prepare copy, briefs, links, and reports.
- Scripts must not auto-post into Reddit, 4chan, Nostr, Fediverse, or other
  third-party communities without explicit operator action and platform-permitted
  API use.
- Scripts must not evade platform rate limits, bans, anti-spam systems, or ad
  review policies.

## Paid Launch Budget

Use `$20,000` in sequence, not all at once.

| Bucket | Budget | Purpose |
| --- | ---: | --- |
| Product hardening | `$2,500` | PoW, gateway, proof page, launch readiness. |
| Founding boards | `$5,000` | 10-15 founding moderators/posters and quality posts. |
| KOL/sponsorships | `$5,000` | Nostr, privacy, FOSS, crypto, self-hosting micro-creators. |
| Reddit/community ads | `$2,500` | Privacy, self-hosted, FOSS, Reddit-alternative audiences. |
| Alt-network ads | `$2,000` | Brave, 4chan `/g/` and `/biz/`, crypto/privacy networks. |
| HiveRelay operator growth | `$1,500` | Operator launch kits, node proof pages, referral bounties. |
| Prizes/bounties | `$1,000` | Best board, importer, bot, moderation tool. |
| Reserve | `$500` | Double down only after activation data. |

Kill rules:

- Stop any channel above `$40` per activated poster after 3 creative tests.
- Stop any source where more than 20% of first-week content requires moderation.
- Stop any channel that attracts illegal-content positioning or brand capture.
- Double down on channels with real posts, not clicks.

## Channel Strategy

Ranked by launch fit:

1. Nostr.
2. Lemmy/Fediverse/Mbin.
3. Privacy and degoogle communities.
4. Self-hosting, homelab, Linux, FOSS.
5. HiveRelay operators and node-curious homelab users.
6. Bitcoin/Lightning/cypherpunk.
7. Reddit alternatives and deplatformed-but-lawful communities.
8. Hacker News, Lobsters, Tildes, and `/g/` as technical proof channels.
9. 4chan `/biz/` only as a small crypto-native experiment.

Explicit exclusions:

- Do not advertise into darknet-market communities.
- Do not position Peerit as a place for illegal content.
- Do not target hate, harassment, doxxing, exploitation, or violent-extremism
  communities.

4chan guidance:

- Use only paid banner inventory.
- Target `/g/` first, `/biz/` second.
- Do not seed regular posts as ads.
- Keep copy technical: "P2P Reddit", "PoW-gated", "no accounts", "runs in
  PearBrowser".

## Launch Narrative

Primary line:

> Peerit is a proof-of-work gated P2P Reddit. Read on the gateway, post through
> PearBrowser. No accounts. No central server. Communities are signed records
> you can seed.

Supporting lines:

- "Spam is not free: posts and comments mint small browser PoW."
- "Moderation is a signed overlay, not a hidden admin panel."
- "Your identity lives in PearBrowser, not on our server."
- "Relays make it fast; they do not own the community."
- "Run a HiveRelay node and make the network visibly stronger."
- "Node operators can prove what they served instead of asking users to trust a
  dashboard."

Avoid:

- "Anything goes."
- "Darknet Reddit."
- "No moderation."
- "Untraceable."
- "Use this to evade bans."

## Metrics

Primary:

- Activated posters: users who create at least one valid PoW-gated post/comment.
- D7 returning posters.
- Boards with 10+ distinct contributors.
- Cost per activated poster.

Secondary:

- Gateway read-to-PearBrowser-open rate.
- PearBrowser open-to-first-post rate.
- First post PoW completion rate.
- Moderation rate by source.
- Spam rejection count.
- Relay/gateway cold-load latency.
- Active HiveRelay operators.
- Node referral-to-activated-poster rate.
- Outbox availability proofs and proof age.
- Regional gateway latency and coverage.

Launch success target for `$20k`:

- 500-1,000 activated posters.
- 20-40 boards that feel alive.
- 5-10 boards with durable weekly activity.
- Under `$40` blended cost per activated poster.
- No major illegal-content or spam capture incident.

## Reporting Model

Use event names that preserve privacy and avoid content surveillance:

| Event | Where | Notes |
| --- | --- | --- |
| `gateway_view` | Gateway | Board/post path, campaign tag, no user identity. |
| `open_pearbrowser_click` | Gateway | Campaign tag and target link. |
| `app_loaded` | Peerit | Local aggregate only unless opted into release telemetry. |
| `pow_started` | Peerit | Type only: post/comment/community. |
| `pow_completed` | Peerit | Type and duration bucket. |
| `record_appended` | Peerit | Type only, no body. |
| `spam_rejected` | Peerit/merge | Type and reason bucket. |
| `node_proof_seen` | Operator page | Node id, region, proof type, no user identity. |
| `node_referral_open` | Gateway/operator page | Campaign tag and node referral id. |
| `operator_signup_intent` | Operator kit | Region and node type only. |

Any public dashboard should show aggregates only.

## Milestones

### Week 1: Launch Safety

- Port PoW.
- Add reputation-weighted ranking or at least ranking hook.
- Add tests.
- Add launch readiness script stub.

### Week 2: Gateway and Seed Boards

- Build gateway preview path.
- Create `launch/communities.json`.
- Generate starter posts and moderator briefs.
- Recruit first founding board owners.
- Draft the HiveRelay operator kit and proof-page template.

### Week 3: Organic Soft Launch

- Publish Show HN/Lobsters/Tildes-ready copy.
- Publish Nostr thread.
- Publish Fediverse/Lemmy launch posts.
- Invite founding moderators.
- Invite first HiveRelay operators to publish proof/referral pages.
- Track organic conversion.

### Week 4-5: Paid Tests

- Test Reddit/community ads, KOLs, Brave, 4chan `/g/`, and crypto/privacy ad
  networks with small budgets.
- Test HiveRelay operator referrals and node proof pages as a channel.
- Kill weak channels.
- Double down on activated-poster sources.

### Week 6: Scale or Stop

- If D7 and moderation quality hold, increase spend.
- If ghost-town indicators remain, spend on board founders and content, not ads.
- If spam pressure rises, increase PoW/adaptive gates before buying more traffic.

## Immediate Next Implementation Order

1. Port PoW from `p2pbuilders` into `peerit`.
2. Add `launch:readiness` to prevent accidental paid launch without PoW.
3. Create `launch/communities.json` and `launch:seed-plan`.
4. Add HiveRelay operator-kit generation to the rollout automation repo.
5. Build read-only gateway previews.
6. Create launch copy and KOL/ad brief generator.
