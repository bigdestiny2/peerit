# What is peerit?

**peerit is a peer-to-peer Reddit.** Communities, posts, threaded comments,
up/down votes, moderation, karma — everything you'd expect — but with **no
servers, no company, and no central database** that can be seized, sold, or
censored. The whole thing is a folder of HTML and JavaScript; the "backend" is
the people using it.

On ordinary Reddit, one company owns the servers, the data, and the rules. It
can delete a community, ban an account, hand data to whoever asks, or simply be
shut down. peerit has no such single point. There is no server to seize, no
master database to subpoena, and no account you didn't create yourself that
anyone can suspend. Content is trusted because it's **cryptographically signed**,
not because a server vouches for it.

---

## How it works, in four ideas

![How peerit assembles your feed: each user writes a signed outbox; your device verifies every signature and merges them into your feed; forged records are dropped.](docs/how-peerit-works.svg)

### 1. Everyone writes only their own "outbox"
When you create a community, post, comment, or vote, peerit writes a **signed
record** to *your own* append-only log — your outbox. You never write to anyone
else's. Your outbox is yours alone, secured by your private key.

### 2. Peers copy each other's outboxes
Your device pulls copies of other people's outboxes over a peer-to-peer network.
Nobody's outbox is "the database" — there are just lots of personal outboxes
replicating across the network. (How a post stays reachable when its author is
offline is covered under [Durability](#under-the-hood-for-the-curious) below.)

### 3. Your device merges them into the feed you see
peerit combines everyone's outboxes — on your device — into one view: the list
of communities, the posts in each, the comment threads, the vote tallies. The
feed you read is assembled locally from many signed sources. There's no server
deciding what you see; your client does the merge.

The merge is **deterministic**, so everyone converges on the same result: when a
post is edited, the newest version wins; a deleted post stays deleted even if an
older copy resurfaces; and a community name belongs permanently to whoever
validly created it first, so an established community can't be hijacked.

### 4. Signatures are the only authority
Every record carries an **Ed25519 digital signature**. Before showing anything,
your client checks it. A forged or tampered record fails the check and is thrown
away. So it doesn't matter *who handed you* a record — only whether its signature
is valid.

> This is the whole trick. Because authenticity is math, not permission, **no
> server needs to be trusted.** Anyone can relay data; nobody can fake it.

A record is only accepted if all three hold:
1. it's filed exactly where its own contents say it belongs — a post's place is
   fixed by its community and ID, so no one can relabel another person's record to
   pass it off as yours,
2. the key it was signed with matches the author it claims to be from (you can't
   sign as someone else), and
3. the Ed25519 signature actually verifies.

---

## What that gets you

- **Nothing central to seize or censor.** Take down any one machine and the
  network is unaffected.
- **No impersonation.** Only you hold your key, so only you can post as you.
- **No silent edits.** Change a record and its signature breaks; peers drop it.
- **Verifiable moderation.** A moderator's actions (remove, lock, ban, …) are
  *themselves* signed records, honored only when they come from a current
  moderator of that community (the founder is always one, and can delegate to
  others). Authority is checked cryptographically at the merge, so a fake "ban"
  from a non-moderator is simply ignored. You see the effects (e.g. *[removed by
  moderators]*) and the moderator list; the underlying records can be audited.
- **Spam costs something.** Each post carries a small **proof-of-work** — a brief
  computation done when it's created — and every peer re-checks it at the merge,
  so a post without valid work never reaches anyone's feed. No central filter
  needed.

---

## What's actually in it

Communities · text / link / image posts · unlimited-depth threaded comments ·
Hot / New / Top / Rising / Controversial ranking (and a Wilson-score "Best" sort
for comments) · one vote per identity · Ed25519 identities with profiles and
karma · per-community moderation (remove, approve, lock, sticky, ban, add-mod,
with a founder→mod chain) · search · saved / hidden posts · community
subscriptions. All of it runs as plain ES modules — no build step.

---

## Three ways to run it

peerit's security model is the same everywhere; only the transport changes.

| | how peers are reached | trust |
|---|---|---|
| **PearBrowser** (strongest) | direct on the Hyperswarm DHT — true peer-to-peer, no middleman | fully trustless |
| **A normal browser (peerit.site)** | through an **untrusted relay** that shuttles data | relay can withhold, never forge |
| **A normal browser, no relay** | nothing — a local-only sandbox on one device | not networked |

**PearBrowser** loads peerit as a content-addressed `hyper://` site and gives it
real peer-to-peer access. This is the fully trustless mode.

**peerit.site** exists because a normal web page *can't* join a peer-to-peer
network directly. So it connects through a relay. The key design choice: **your
keys never leave your browser, and your client still verifies every record** — so
the relay can pass messages along but can never forge, tamper, or impersonate. It
can be blocked (an availability risk), but it can't be made to lie (integrity is
preserved). Honest caveat: a website hands you its JavaScript on every visit, so
whoever runs the site could in principle ship modified code. For the highest
assurance, use PearBrowser; the web build says as much in its own banner.

---

## Under the hood (for the curious)

Each record is a value stored at a structured key in a per-user
[Hyperbee](https://github.com/holepunchto/hyperbee) log — for example
`post!<community>!<id>`, `vote!<targetId>!<author>`, or `community!<slug>`. The
merge is **deterministic and order-independent**: edits resolve last-write-wins
by timestamp, a delete (tombstone) always wins a tie so content can't be
resurrected, and a community name is **sticky** — the first valid creator keeps
it, so an established community can't be hijacked. Identities sign with Ed25519
via the browser's WebCrypto; the relay (when used) implements a small token-gated
HTTP/streaming contract and holds no keys.

When you're offline, your posts still live on your own device and on any peer that
has replicated your outbox. For always-on availability there's a separate,
opt-in tool — the **peerit-seeder** — that anyone can run on a cheap always-up
box to replicate and pin outboxes so content survives the author logging off.
Without a seeder, a post's reach depends on other peers staying online.

---

## The honest limits

peerit is built to be honest about what cryptography can and can't do:

- **Sybil resistance.** Identities are free to mint, so votes are *advisory* —
  they signal, they don't guarantee one-human-one-vote.
- **Genesis name-squatting.** This is a deliberate tradeoff. With no central
  authority to decide who "owns" a name, peerit makes names permanently sticky so
  established communities can't be hijacked — the price is that the first person
  to claim a brand-new name keeps it (the classic Zooko's-triangle bind: names
  can't be human-readable, decentralized, and squat-proof all at once).
- **The web trusts the origin's code.** As above, peerit.site keeps your records
  unforgeable but can't prove the JavaScript you ran is the audited JavaScript.
  PearBrowser, which you pin by content key, doesn't have this gap.
- **Privacy on the web.** A normal-browser visit reveals your IP address to the
  relay (and WebRTC can leak local-network IPs); PearBrowser's Hyperswarm layer
  doesn't expose you the same way. For privacy-sensitive use, prefer PearBrowser
  or front the web build with Tor.

None of these break the core promise: **your content is yours, signed by you, and
no server can forge it, silently change it, or make it disappear from everyone at
once.**

---

## Learn more

- **Run it fully trustless:** install [PearBrowser](https://pears.com/) and open
  peerit's `hyper://` drive.
- **Put it on a normal website:** see [`docs/WEB-DEPLOYMENT.md`](docs/WEB-DEPLOYMENT.md).
- **Prove it's really P2P:** see [`docs/BRIDGE_VERIFICATION.md`](docs/BRIDGE_VERIFICATION.md).
- **The untrusted relay:** [github.com/bigdestiny2/peerit-relay](https://github.com/bigdestiny2/peerit-relay).
