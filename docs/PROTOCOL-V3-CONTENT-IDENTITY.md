# Protocol v3 content identity cutover

Peerit's pre-v3 post/comment `cid` was caller-selected. Opaque v2 storage keys
already included the author, but the decrypted read model reconstructed
`post!<community>!<cid>` and `comment!<community>!<postCid>!<cid>`. Two authors
choosing the same CID could therefore collapse onto one logical post/comment,
and a CID-only vote or reply could be displayed against the wrong author.

Protocol v3 closes new collisions:

```
cid = SHA-256("peerit.content-id.v3" || NUL || JSON([type, author, contentNonce]))
```

New post/comment records carry signed `protocol: 3` and `contentNonce` fields.
Normal writes generate a random nonce. Deterministic publishers pass an explicit
`nonce` or `seed`; they never pass a result CID. Edits and tombstones retain the
original protocol, nonce, and CID and re-run the identity check before signing.

Admission does not infer a cutover from timestamps. A post/comment must either:

1. explicitly be protocol 3 and reproduce its CID, or
2. have an exact signature in the frozen pre-cutover production inventory.

The second case is read compatibility only. Re-signing an old record changes its
signature, so historical posts/comments cannot be edited or deleted. New votes,
comments, nested replies, and content-moderation actions also refuse historical
targets because their old CID-only references may already be ambiguous. This is
enforced twice: the Data API refuses to construct the write, and
`makeValidator()` rejects a custom client's signed record at admission.

## Signed target references

A protocol-v3 target reference has one exact shape:

```json
{
  "type": "post",
  "author": "<64 lowercase hex>",
  "contentNonce": "<1-128 printable characters>",
  "cid": "<64 lowercase hex>"
}
```

No extra fields are accepted. Admission recomputes `cid` with the content-ID
formula above and requires the scalar `targetCid`/`targetType` fields to equal
the signed ref. A ref therefore cannot be redirected by whichever legacy
CID-only record happened to win a local merge.

New records carry the following bindings:

- A comment carries `targetRef` for its post. A nested reply additionally carries
  `parentRef` for its parent comment; a top-level comment carries `parentRef:null`.
- A vote carries `protocol:3` and `targetRef`, with matching `targetCid` and
  `targetType`.
- A content moderation action (`remove`, `approve`, `lock`, `unlock`, `sticky`,
  `unsticky`) carries `protocol:3`, `targetRef`, `targetCid`, and `targetType`.
  Lock/sticky actions are post-only; remove/approve may target a post or comment.
- A user moderation action (`ban`, `unban`, `addmod`, `removemod`) carries one
  canonical lowercase public-key target and no content target. Unknown or mixed
  action shapes are rejected.

Opaque-v2 records seal these fields. The validator decrypts the logical fields
before applying the same checks; absence at the wire top level is never treated
as a compatibility exception. Moderator authorization remains a deterministic
read-model decision (`resolveMods`/`modOverlay`); the admission gate closes the
record shape and target identity independently of arrival order.

## Frozen compatibility inventory

Legacy action compatibility is signature-only. The frozen production boundary
contains exactly 2 comments, 11 votes, and 0 moderation actions in
`js/legacy-action-allowlist.js`. It also pins the 20 distinct historical CIDs
observed in the signed seed snapshot and read-only live inventory. None currently
looks like a v3 hash, but the deny-set closes the case where a pre-cutover custom
client deliberately selected a v3-looking CID.

Run the non-mutating release audit while writes are blocked:

```sh
npm run audit:live-legacy-actions
```

The audit issues an ephemeral read token and performs only directory/range reads.
It fails on an unpinned legacy action, a missing frozen action, an unexplained
legacy CID, or a historical row that no longer passes signature, ownership,
key-binding, PoW, and application admission.

## Honest compatibility boundary

- Existing inventoried records and their old hash routes remain readable.
- Existing cross-author legacy collisions are **not repaired**. Where two frozen
  records already share a CID, the current CID-only read architecture can still
  select one logical winner.
- Protocol v3 prevents a newly signed record from creating or exploiting such a
  collision. Two authors using the same nonce produce unrelated 256-bit CIDs.
- Re-publishing deterministic seed content as v3 creates new author-bound URLs.
  If preserving old seed permalinks matters, migration needs an explicit signed
  redirect/alias design rather than treating an old CID as a new v3 CID.

## UI boundary

Historical posts/comments remain visible with a read-only label. Their vote,
reply, edit, delete, and content-moderation affordances are hidden. New comment
moderation passes the enclosing post CID so the Data layer resolves its target
with one direct lookup instead of a global comment scan.

Routes do not otherwise need a new shape: v3 CIDs are URL-safe 64-character
lowercase hex strings and continue to occupy the existing CID route segment.

## Deployment constraint

Keep public writes closed until the signed v3 client is the active release. The
relay is intentionally content-blind and does not enforce this application-level
schema; an old tab/client can still transmit a newly signed legacy-shaped row,
but v3 readers will reject it. Preventing that user-visible lost-write case for
stale clients requires the release/capability gate to refuse pre-v3 writers when
writes are enabled.
