# Community moderation and pluggable feeds

**Status:** research, architecture, and implemented v1 baseline  
**Date:** 2026-07-18  
**Scope:** community flagging, reversible burial, user-selectable moderation, and interchangeable open-source feed algorithms for Peerit

## Implementation update

The first deployable baseline described by this paper is now implemented in the Peerit client:

- `report` is a signed protocol-v3 record with one LWW `bury` or `keep` slot per community, target, and author.
- Reports require target-bound content references and proof-of-work. In Opaque-Log v2, community, target, verdict, reason, and note are sealed; a blind substrate relay sees a generic `v2!<okey>` cell.
- Withdrawals are signed tombstones in the same slot.
- The local materialized index aggregates reports without asking a relay to understand the record type.
- Visibility progresses through `visible`, `downranked`, `collapsed`, and `buried`; every state is reversible and the underlying content record remains intact.
- Readers can independently choose **Community**, **Consensus only**, or **Open / unmoderated**. Open retains signature/protocol admission and author deletion while treating community/moderator visibility decisions as labels.
- Moderation authority does not use the backdateable global reputation score. V1 trust roots are the founder and current moderators; another non-banned signed member becomes eligible only after publishing community content and receiving a direct positive vote from one of those roots. Raw vote trust deliberately does not recurse.
- Built-in `Hot`, `New`, `Top`, `Rising`, and `Controversial` algorithms now have stable ids, versions, MIT-license metadata, source-module disclosure, and a common registry/window interface. Moderation remains host-enforced and orthogonal to the selected ranker.
- The representative outbox availability proof now carries profile, community, post, comment, vote, and report data entirely through sealed opaque cells and verifies fresh-reader recovery after the author is offline.

This is a built-in algorithm interface, not yet a safe arbitrary-code plugin system. Content-addressed third-party bundles, constrained Worker/Wasm execution, cluster-diversity checks, witnessed pre-incident membership, reason-specific dispositions, appeals, and shadow metrics remain follow-on hardening. The v1 thresholds are explicit client-policy constants rather than protocol truth.

## Executive decision

Peerit should separate a feed into three independently selected components:

1. **Candidate source** — which signed posts are considered (`all`, joined communities, followed authors, or one community).
2. **Moderation policy** — which valid candidates are visible, warned, collapsed, or buried.
3. **Ranking algorithm** — how the remaining candidates are ordered.

The first user-facing presets should be:

- **Community consensus** — applies signed community reports through a Sybil-aware, reversible policy and buries content only after a conservative quorum.
- **Open** — ignores community and moderator visibility decisions, while still enforcing protocol validity, author deletion, the user's own blocks/mutes/hides, and any non-optional transport or legal safety boundary.

The ranking selector is orthogonal to that choice. A user could select `Community consensus + Hot`, `Community consensus + New`, `Open + New`, or a third-party ranker. Calling the second preset “Open” is more accurate than “unmoderated”: forged records are never content, personal filters still apply, and no client can display bytes that its transport is legally or technically unable to provide.

Reports must not delete source records. They produce explainable, reversible visibility states:

`visible -> downranked -> collapsed -> buried`

The majority policy should initially be described in the UI as **community consensus**, not literal democracy. Peerit identities are free to create, so a count of public keys is not a count of people. The long-term design should combine a minimum independent-reporter quorum, community-local trust, counter-signals (“keep” or “vouch”), and disagreement-cluster diversity. Exact thresholds should be calibrated in a shadow deployment and adversarial simulation before they affect visibility.

The algorithm system should start with audited built-in modules behind a stable interface. Installing arbitrary remote JavaScript is not safe merely because its source is public. Third-party algorithms should eventually be content-addressed, signed, reproducibly built, capability-free, and executed in a constrained worker with deterministic inputs and resource limits.

## What Peerit already has

Peerit is unusually well-positioned for this design:

- Every community, post, comment, vote, profile, social edge, and moderator action is signed and locally verified.
- Protocol-v3 content references bind actions to an author, type, nonce, and CID, preventing ambiguous target attacks.
- The current moderation system is already a client-honored overlay rather than destructive deletion.
- Proof-of-work provides an admission cost for posts and comments.
- Votes preserve raw totals for display while using a reputation-weighted total for ranking.
- Follow and membership edges provide the beginning of a community-local trust graph.
- Feed ranking already lives in a pure module, [`js/ranking.js`](../js/ranking.js), and feed windowing already has deterministic tests.

There are also important gaps:

- There is no signed report, label, appeal, or vouch record.
- Moderator actions and ranking are wired into the view flow rather than composed as explicit policies.
- The current reputation weight is global, not community-local.
- Received upvotes can themselves come from Sybil identities.
- Account age is derived from the earliest self-timestamped post or comment. The test in [`test/reputation.mjs`](../test/reputation.mjs) deliberately establishes an old identity by changing `Date.now()` and backdating a post. An attacker can do the same. This input must not grant moderation authority.
- There is no algorithm manifest, stable ABI, sandbox, artifact hash, or audit receipt.

The account-age issue is not a minor implementation bug. In a permissionless network there is no trustworthy wall clock merely because an author signed a timestamp.

## Lessons from existing systems

### Hacker News: graduated burial plus a counter-signal

Hacker News does not treat a flag as an immediate deletion. Its FAQ says flags affect rank; sufficient flags can mark a post as flagged and then dead. Dead content remains available to users who enable `showdead`, and sufficiently trusted users can vouch to restore it. Flagging itself has a small karma threshold. This is close to the interaction Peerit needs: progressive friction, continued auditability, and a recovery path rather than a binary erase button. The ranking also combines votes with flags, anti-abuse systems, discussion-temperature penalties, and moderator action rather than pretending one number is ground truth. [Hacker News FAQ](https://news.ycombinator.com/newsfaq.html)

### Stack Overflow: graduated privilege, reason codes, quotas, and reliability feedback

Stack Overflow grants flagging after a small reputation threshold, uses standard reason codes, allows pending flags to be retracted, and gives additional daily flags for a strong history. Too many declined flags temporarily suspend flagging. Severe spam or abusive flags can trigger automatic action, but much community moderation enters review queues and higher-impact actions require more reputation. The transferable lesson is not its exact threshold; it is that flag power, rate, reason, and past accuracy are distinct inputs. [Flag-post privilege](https://stackoverflow.com/help/privileges/flag-posts), [declined flags](https://stackoverflow.com/help/declined-flags)

### Reddit: use community-local trust, not just global account state

Reddit's Crowd Control can collapse or filter contributions based on negative community karma, new-account status, and non-membership. It is designed specifically for viral influxes and bad-faith participation. Reddit also explicitly prohibits coordinated voting, multiple-account manipulation, and abuse of reporting channels. This supports two Peerit design choices: moderation influence should be community-local, and sudden outside participation is an attack signal. It does not solve Peerit's decentralized identity problem because Reddit can observe and enforce accounts centrally. [Crowd Control](https://support.reddithelp.com/hc/en-us/articles/15484545006996-Crowd-Control), [Disrupting Communities](https://support.reddithelp.com/hc/en-us/articles/360043066412-Disrupting-Communities)

### Bluesky: separate feed generators from labelers

Bluesky's architecture separates custom feed generators from moderation labelers. A feed generator returns a skeleton of record identifiers that another service hydrates. Moderation labels come from stackable services selected by the application or user, and label definitions map to actions such as hide, warn, or ignore. This is the strongest existing precedent for making ranking and moderation independently composable. Peerit can implement the same separation locally rather than requiring a hosted AppView. [Custom feed protocol](https://docs.bsky.app/docs/starter-templates/custom-feeds), [labels and moderation](https://docs.bsky.app/docs/advanced-guides/moderation), [AT Protocol label specification](https://atproto.com/specs/label)

The useful abstraction is a signed assertion about a target, not a destructive mutation of the target. Bluesky also distinguishes labels from takedowns; that distinction should remain explicit in Peerit.

### Nostr: reports are subjective signals and clients choose how to use them

NIP-56 defines signed reports with reason types and explicitly says that objectionability is subjective: users, apps, and relays may act on reports as they see fit. It suggests that clients could blur an account after reports from several friends, while warning relays not to auto-moderate raw reports because they are easily gamed. NIP-32 generalizes signed labels, NIP-51 provides mute lists, and NIP-85 lets users choose signed trust/ranking assertion providers. This closely matches Peerit's local-first trust model. [NIP-56 reporting](https://github.com/nostr-protocol/nips/blob/master/56.md), [NIP-32 labeling](https://github.com/nostr-protocol/nips/blob/master/32.md), [NIP-51 lists](https://github.com/nostr-protocol/nips/blob/master/51.md), [NIP-85 trusted assertions](https://github.com/nostr-protocol/nips/blob/master/85.md)

NIP-72 is also instructive: anyone may express approval for a community post and clients decide which approvals to honor, but the specification is now marked unrecommended. The durable idea is client choice; Peerit should not copy that protocol wholesale. [NIP-72 moderated communities](https://github.com/nostr-protocol/nips/blob/master/72.md)

### Community Notes: require cross-group agreement, not just a larger pile

X's Community Notes uses an open-source “bridging” model: a note needs support from contributors who have historically disagreed, rather than support from only one aligned cluster. This is more resistant to a cohesive faction than a simple majority. It is not a complete moderation system, and its requirement for cross-group agreement can delay or omit decisions on polarized harms. Peerit should adopt the diversity principle and expose uncertainty, not copy the model as a universal bury switch. [Algorithm and source](https://github.com/twitter/communitynotes), [ranking explanation](https://communitynotes.x.com/guide/en/under-the-hood/ranking-notes), [known challenges](https://communitynotes.x.com/guide/en/about/challenges)

### Mastodon: “limit” is a useful reversible state

Mastodon's `limit` action reduces discovery without deleting underlying content, and users separately retain their own filters, mutes, blocks, and server blocks. Peerit's burial should behave more like a reversible visibility limit than deletion. [Mastodon moderation actions](https://docs.joinmastodon.org/admin/moderation/), [user filters and blocks](https://docs.joinmastodon.org/user/moderating/)

### The hard limit: identities are not people

Douceur's Sybil result shows that without a trusted identity authority, a peer-to-peer system cannot generally prove one physical entity corresponds to one identity. Sybil-resistant content-voting systems therefore add scarce resources or root trust in an existing social graph. Peerit must make its trust assumption explicit instead of marketing raw-key consensus as a human majority. [The Sybil Attack](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/), [Sybil-Resilient Online Content Voting](https://www.usenix.org/conference/nsdi-09/sybil-resilient-online-content-voting)

## The model: validation, moderation, and ranking are different

The processing pipeline should be:

```text
replicated bytes
  -> protocol admission and signature verification
  -> candidate-source selection
  -> personal controls
  -> selected moderation-policy stack
  -> selected ranking algorithm
  -> hydration and rendering
```

These layers have different meanings:

| Layer | Question | User-selectable? |
|---|---|---|
| Protocol admission | Is this an authentic, well-formed Peerit record with required work and a valid target binding? | No |
| Candidate source | Which communities/authors/network slice does this feed cover? | Yes |
| Personal controls | Has this user hidden, muted, or blocked it? | Yes, always authoritative for that user |
| Moderation policy | Do the selected communities, moderators, or label providers warn, collapse, or bury it? | Yes |
| Ranking | In what order should eligible records appear? | Yes |

An invalid signature is not “moderated content”; it is not a record. A downvote is a relevance or quality signal; it is not a policy report. An author deletion is not a community moderation opinion. Keeping these semantics separate prevents later algorithms from silently changing the meaning of old actions.

## Signed report and verdict schema

Add a new `report` record family using the same one-record-per-identity pattern as votes:

```text
report!<community>!<targetCid>!<reporterPubkey>
```

The logical cleartext form should be equivalent to:

```js
{
  id,
  protocol: 3,
  community,
  targetType: 'post' | 'comment',
  targetCid,
  targetRef: { type, author, contentNonce, cid },
  author: reporterPubkey,
  verdict: 'bury' | 'keep',
  reason: 'spam' | 'off-topic' | 'low-quality' | 'harassment' | 'hate' |
          'sexual' | 'graphic' | 'personal-info' | 'impersonation' |
          'malware' | 'illegal' | 'misleading' | 'duplicate' | 'other',
  note: '',
  ts,
  deleted: false
}
```

Important rules:

- `targetRef` must pass the same protocol-v3 recomputation used by votes and moderator actions.
- The record owner is `author`, which must equal the signing key.
- One reporter has one current verdict per target. A later rewrite changes the reason or verdict; `deleted:true` withdraws it.
- A report never edits the target record.
- A `keep` verdict is the counter-signal corresponding to Hacker News vouching. It should become prominent after content is downranked or collapsed, rather than encouraging every fan to pre-vouch for every post.
- A structured reason is required. Free text should be short and optional.
- Detailed evidence should not be published in plaintext by default. A public P2P report permanently links the reporter to the target and can expose victims to retaliation. A later encrypted moderator-evidence record can carry sensitive details.
- Report target and community fields must be included in the V2 sealing/key rules so a relay cannot enumerate the report graph from semantic keys.

The taxonomy must map to different presentation actions. It is unsafe to treat every majority opinion as a truth or deletion decision:

| Reason class | Default consensus effect |
|---|---|
| Spam, off-topic, duplicate, low quality | Downrank, then bury from listings |
| Harassment, hate, personal information | Warn/collapse; bury after stronger consensus |
| Sexual or graphic media | Blur media and warn; user age/safety preferences decide reveal |
| Misleading | Add context/warning; do not equate majority opinion with factual truth |
| Malware or credible illegality | Quarantine and escalate to the non-optional safety/operator path; do not wait for popularity |

The initial code can use one `report` family, but the API should speak in terms of a general **label signal** so automated or specialist label providers can be added without changing feed ranking.

## Consensus policy

### Do not use raw key count

A safe policy needs all of these dimensions:

- **Eligibility:** is this identity allowed to affect community-wide visibility?
- **Influence:** how much can one eligible identity contribute?
- **Quorum:** is there enough independent participation to act?
- **Agreement:** what share supports `bury` rather than `keep`?
- **Diversity:** do signals cross trust/disagreement clusters?
- **Disposition:** does the reason call for downranking, warning, blurring, or burial?

No one scalar reputation score answers all six.

### Community-local eligibility

For a conservative first release, an impactful reporter should need:

- a signed community membership record that existed before the incident window;
- positive participation in that community;
- no active community ban;
- a bounded report rate;
- no evidence that all supporting identities are a single newly arrived cluster.

However, a self-authored timestamp cannot prove that membership “existed before” anything. The first implementation should therefore use such rules only as heuristics and explicitly cap their authority. Stronger tenure requires a witness:

- inclusion in an earlier community checkpoint signed by a diverse committee;
- inclusion in several independently observed signed outbox-head snapshots; or
- viewer-rooted web-of-trust distance from established community members.

Each choice introduces a trust root. That is acceptable if visible and replaceable; pretending no trust root exists is not.

### Weight and quorum

The current global ranking weight may remain a ranking experiment, but it should not be reused as moderation authority. Its age input is backdateable and its received-upvote input is recursively Sybil-inflatable.

A v0 community policy can use a capped community-local weight `w_i` in `[0, 1]`, where ineligible reporters have zero weight. For a target:

```text
B = sum of weights for bury verdicts
K = sum of weights for keep verdicts
support = B / (B + K)
```

Action must require both weighted support and a minimum number of distinct eligible reporters. Weighted mass without identity diversity lets one high-reputation participant censor alone; raw diversity without trust lets a Sybil swarm win.

The following are **shadow-mode starting points, not protocol constants**:

| State | Conservative pilot trigger |
|---|---|
| Downranked | at least 3 eligible reporters, meaningful report weight, and at least 60% `bury` support |
| Collapsed | at least 5 eligible reporters from at least 2 trust clusters and at least two-thirds `bury` support |
| Buried | at least 7 eligible reporters from at least 2 trust clusters, a stronger weight floor, and at least 75% `bury` support |

Small communities that cannot reach the minimum should not auto-bury. They can show warnings, use the existing moderator policy, or let users install a different policy. Lowering the quorum to one or two makes targeted censorship easier precisely where each voice matters most.

Thresholds should be reason-specific. For example, an image may be immediately blurred locally after a lower-confidence sexual/graphic signal because reveal is reversible; removing a political claim from listings should require materially stronger evidence.

### Diversity and bridging

After basic reporting works, compute a coarse disagreement or trust-cluster signal from signed community activity and follow relationships. Cap the contribution of any single dense cluster and require support across clusters for the strongest visibility action. This imports the best property of Community Notes without forcing its factual-note model onto all moderation.

Cluster membership must not be displayed as a claim about ideology. It is only an anti-capture feature, and users need an explanation such as “reports came from two otherwise distinct participation groups.”

### Jury model as the stronger long-term option

Self-selected reporters are a motivated sample, not the community majority. A stronger second-generation design is:

1. Reports nominate a target for review.
2. The content CID plus a frozen community-membership checkpoint deterministically selects a small jury.
3. Jurors return signed `bury` or `keep` verdicts with reasons.
4. A supermajority and minimum response quorum determine the label.

This reduces the ability of a coordinated reporting faction to define both the case and the verdict. It still depends on Sybil-resistant membership snapshots and will have availability problems when selected jurors do not respond. It should therefore be evaluated after, not before, the direct-report model is observable in shadow mode.

### Reversibility and appeals

- The target author can publish a signed appeal referring to the target and current consensus receipt.
- Eligible members can change `bury` to `keep` or withdraw a report.
- The client recomputes the state from the current signed set; the source record never needs restoration.
- The UI shows the aggregate reason mix, current state, selected policy, algorithm version, and how to reveal the item.
- A moderator or specialist provider can add an independent label, but must not silently rewrite community consensus.
- Reporters who repeatedly support outcomes reversed after broad review can lose report rate or influence. This must be based on independent review or later cross-group agreement, not circularly on the same threshold they helped create.

## Moderation presets and existing moderator actions

Moderator authority should become one selectable policy layer, not be fused into every feed forever.

Recommended presets:

| Preset | Personal controls | Community consensus | Existing moderator overlay |
|---|---:|---:|---:|
| Community | Yes | Yes | Yes |
| Majority | Yes | Yes | Labels only; visibility actions ignored |
| Open | Yes | No | Labels only; visibility actions ignored |

The first public UI can show only **Community consensus** and **Open**, with an advanced setting for the moderator layer. Lock and ban actions that govern participation are separate from visibility selection: a client may choose to display removed content while still recognizing that a community has locked a thread or does not accept a user's new submissions.

Every non-default view should make its policy visible near the feed title. A user should never have to infer whether a missing post was absent, invalid, personally hidden, moderator-removed, consensus-buried, or excluded by the ranker.

## Pluggable open-source feed algorithms

### Two interfaces, not one

Define separate interfaces for policy and ranking:

```js
// Core has already verified records before either function runs.
moderate(context, candidates, signals) -> {
  decisions: [{ cid, visibility, reasonCodes, explanation }]
}

rank(context, eligibleCandidates, signals) -> {
  items: [{ cid, score, explanation }]
}
```

`visibility` is one of `visible`, `downranked`, `collapsed`, or `buried`. The renderer, not the algorithm, owns HTML. Rankers cannot delete records or manufacture hydrated content. Policies cannot reorder content except through a declared downrank penalty.

A feed selection is a small, shareable descriptor:

```json
{
  "source": { "kind": "community", "value": "p2p" },
  "policy": "peerit:policy/community-consensus@1#<artifact-hash>",
  "ranker": "peerit:rank/hot@1#<artifact-hash>",
  "parameters": { "timeWindow": "week" }
}
```

### Manifest

Every installable policy or ranker should have a signed manifest similar to:

```json
{
  "schema": "peerit.feed-algorithm/v1",
  "kind": "ranker",
  "id": "hot",
  "name": "Hot",
  "version": "1.0.0",
  "inputSchema": 1,
  "artifact": {
    "cid": "<content-address>",
    "sha256": "<digest>"
  },
  "source": {
    "repository": "https://example.org/algo.git",
    "commit": "<full-commit>",
    "license": "MIT"
  },
  "deterministic": true,
  "permissions": [],
  "limits": {
    "maxCandidates": 20000,
    "cpuMs": 100,
    "memoryMiB": 32
  }
}
```

“Open source” should mean more than a homepage link:

- exact source commit;
- SPDX license;
- content hash of the executable artifact;
- reproducible build instructions;
- conformance tests and golden vectors;
- signed publisher identity;
- declared input schema and parameters;
- changelog and immutable version identifier.

Algorithm upgrades create a new immutable artifact. A feed descriptor never changes meaning underneath a user.

### Determinism and audit receipts

Local clients need the same result from the same complete input:

- no ambient `Date.now()`; the core supplies a rounded evaluation time;
- no network, DOM, storage, identity, randomness, or signing access;
- canonical candidate order before invocation;
- CID as the final deterministic tie-breaker;
- bounded output containing only input CIDs;
- explicit behavior for missing optional fields;
- canonical parameter validation.

For each rendered page the client can produce a local receipt:

```text
candidate-root
policy artifact hash + parameters
ranker artifact hash + parameters
result CID list
```

This makes “why is this post here?” locally auditable. It does not prove the client received every network record; Peerit's signed-head and relay-audit mechanisms remain responsible for detecting withholding.

### Safe execution

Do not `import()` arbitrary network URLs into the main application.

Roll out in two stages:

1. **Built-in registry:** extract current `hot`, `new`, `top`, `rising`, and `controversial` sorts behind the interface. They remain normal audited modules shipped with Peerit.
2. **Third-party artifacts:** execute a content-addressed bundle in a dedicated worker or constrained WebAssembly runtime with no capabilities, a hard timeout, input/output size bounds, and termination on violation.

A worker alone is not a complete sandbox: workers can ordinarily use `fetch`, IndexedDB, Web Crypto, WebSockets, and other APIs, and accepting an arbitrary worker URL is itself an injection risk. The host must expose only a structured message interface and apply browser security controls appropriate to the runtime. WebAssembly provides fault isolation, but a module can still reach whatever host functions the embedder imports, so the import surface must also be capability-minimal. Algorithms that require a hosted service should be identified as **remote providers**, with their availability and privacy implications shown separately from locally reproducible algorithms. [APIs available to workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Functions_and_classes_available_to_workers), [worker security considerations](https://developer.mozilla.org/en-US/docs/Web/API/Worker/Worker), [WebAssembly security model](https://webassembly.org/docs/security/)

## Threat model

| Attack | Required defense |
|---|---|
| Cheap Sybil reporters | Eligibility gates, community-local/rooted trust, absolute quorum, cluster caps |
| Backdated “old” accounts | Do not trust author timestamps for authority; use witnessed checkpoints or graph trust |
| Sybils upvoting one another into reputation | Do not recursively treat raw received votes as moderation trust |
| Join-and-flag brigade | Freeze eligibility to a witnessed pre-incident membership snapshot; flag burst detection |
| Established faction capture | Counter-verdicts, cross-cluster support, user-selectable Open view |
| Retaliatory reports | Structured reasons, report quotas, reliability history, sensitive-detail encryption |
| One trusted account compromised | Per-identity influence cap and minimum independent reporters |
| False positive burial | Progressive states, reveal control, vouch/keep, appeal, transparent reasons |
| Content-ID collision or wrong target | Mandatory protocol-v3 `targetRef` validation |
| Relay withholds reports or vouches | Signed outbox heads/audits; show incomplete-view status rather than false certainty |
| Malicious algorithm exfiltrates keys/data | Capability-free worker/Wasm; never expose identity or storage APIs |
| Malicious algorithm loops or allocates heavily | CPU, memory, candidate, and output limits; terminate and fall back |
| Algorithm publisher changes code in place | Content-addressed immutable artifacts and pinned manifests |
| Non-deterministic rankings | Canonical inputs, supplied time, no randomness, golden conformance vectors |
| Open-source algorithm is gamed because rules are known | Rely on costly signals and bounded influence, not secrecy; simulate adaptive attacks |

Open algorithms make attacks easier to study and reproduce. They also let attackers optimize against the rules. Transparency is therefore a governance and audit advantage, not a substitute for Sybil resistance.

## UX recommendation

At the top of every feed:

```text
View: [ Community consensus v ]    Rank: [ Hot v ]
```

The view menu explains:

- **Community consensus:** “Uses signed reports from established community participants. Reported items may be downranked, collapsed, or buried. You can reveal and audit them.”
- **Open:** “Shows all available valid records except your own hides, mutes, and blocks. Community and moderator removals are shown as labels only.”

A downranked or buried item page should show:

- state and reason categories;
- bury/keep totals and weighted totals;
- number of distinct eligible reporters and represented trust clusters;
- selected policy name, version, and source;
- “show anyway,” “keep/vouch,” and “appeal” actions as applicable;
- whether the local network view may be incomplete.

Do not expose reporter identities in the default interface even if signed records are auditable. Aggregation reduces retaliation and pile-ons. A dedicated audit view can expose public evidence with a warning.

## Implementation sequence

### Phase 1 — signals without automatic visibility changes

- Add `TYPE.REPORT`, key derivation, V2 sealing rules, ownership rules, materialized indexes, and protocol-v3 target validation.
- Add report, withdraw, keep/vouch, list, and aggregate data APIs.
- Add report UI and an aggregate explanation panel.
- Run policy decisions in **shadow mode**. Log what would have been downranked/collapsed/buried, but do not change feeds.
- Add permutation/convergence tests and target-binding tests.

### Phase 2 — built-in community consensus policy

- Introduce the four visibility states and reason-specific dispositions.
- Add Community consensus/Open selection to per-identity preferences.
- Make moderator overlay an explicit policy layer.
- Add reveal, vouch, withdrawal, and appeal flows.
- Enable only conservative downranking first; graduate collapse and burial after measured false-positive review.

### Phase 3 — policy/ranker interface

- Extract current sorts from the hard-coded view path into a built-in registry.
- Canonicalize algorithm inputs and outputs.
- Add manifests, parameter schemas, deterministic tie-breaking, explanations, and local receipts.
- Preserve the current feed-window performance boundary and 20k-candidate tests.

### Phase 4 — trust hardening

- Replace timestamp-derived authority with witnessed community checkpoints or explicit viewer-rooted trust.
- Add disagreement/trust-cluster diversity and per-cluster influence caps.
- Evaluate deterministic juries for strong burial decisions.
- Add report-quality feedback only where outcomes have an independent review signal.

### Phase 5 — third-party algorithms

- Add content-addressed signed artifacts and a source/build metadata registry.
- Add constrained worker/Wasm execution, termination, and safe fallback.
- Add install/update warnings, publisher trust, and algorithm sharing.
- Consider remote feed/label providers only as a visibly different privacy and availability mode.

## Required tests and experiments

### Deterministic protocol tests

- report create/change/withdraw is one LWW record per target and reporter;
- wrong-community, wrong-author, legacy-CID, and malformed `targetRef` reports fail admission;
- every permutation of the same signed input converges on the same aggregate state;
- partial replicas show uncertainty and converge after missing records arrive;
- appeals and keep verdicts reverse visibility without source-record restoration;
- Open mode shows consensus- and moderator-buried valid content with labels;
- author-deleted and invalid records do not reappear in Open mode.

### Adversarial simulations

- 1, 10, 100, and 1,000 fresh Sybils;
- backdated Sybils with fabricated old activity;
- Sybils mutually upvoting before reporting;
- a join-and-flag burst from one trust cluster;
- compromised high-trust account;
- two polarized honest clusters;
- slow organic reports versus a synchronized brigade;
- report withdrawal and coordinated vouching;
- small, medium, and large community quorum behavior.

### Algorithm safety tests

- infinite loop and deliberate timeout;
- oversized candidate/result arrays;
- output CID not present in input;
- attempts to use network, storage, DOM, randomness, or signing APIs;
- output changes across browsers or candidate input permutations;
- artifact/source hash mismatch;
- unavailable or crashed algorithm falls back to a known built-in ranker without losing the selected moderation policy.

### Product metrics

- false-positive rate from shadow review;
- time from first report to each visibility state;
- appeal and vouch reversal rate;
- share of actions supported by more than one trust cluster;
- concentration of impactful reports by identity and cluster;
- rate of users revealing buried items;
- Open versus Community-consensus selection and switching;
- reproducibility rate for local algorithm receipts;
- moderation computation time and feed-render regression.

Do not optimize solely for “bad content removed.” A system can maximize that number by suppressing legitimate minority speech. Track reversals, concentration, disagreement, and reveal behavior alongside coverage.

## Decisions that need product ownership

1. Is **Community** (moderator overlay plus consensus) or **Majority** (consensus only) the default moderated view?
2. Which source of scarce trust is acceptable: witnessed checkpoints, viewer-rooted social trust, optional external credentials, proof-of-work/resource cost, or a documented hybrid?
3. Which report reasons may bury content, which only warn/blur, and which enter a non-optional operator safety path?
4. Are public reporter identities an acceptable audit trade-off, or must sensitive reports be encrypted to a selected review group?
5. Can third-party algorithms execute locally, or should v1 restrict choice to audited algorithms shipped with Peerit?
6. Should algorithm and moderation choices sync as signed user preferences or remain device-local for privacy?

## Recommended deployment next step

The implementation now goes beyond the original Phase 1 recommendation because the product direction called for a working selectable moderated feed. Before broad promotion, run the Community policy against representative relay traffic, review the items it would downrank/collapse/bury from the Open view, and calibrate reversals and reveal behavior. Do not lower the 3/5/7 quorum floors for small communities.

The next security increment should add witnessed membership/checkpoint history and cross-cluster support before treating `buried` as a mature majority judgment. The current direct-root endorsement rule is intentionally conservative and avoids the known backdated-age and recursively Sybil-inflated reputation inputs.
