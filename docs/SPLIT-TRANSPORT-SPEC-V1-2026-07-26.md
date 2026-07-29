# Split-Transport Spec — Client-Side Route Separation (G2-W / G4-T)

**Specification version:** `0.1.0-draft`
**Protocol identifiers:** `hiverelay.split-web-ohttp/1`, `hiverelay.split-native-protomux/1`
**Date:** 2026-07-26
**Status:** implementation draft, grounded in prior art; not a claim of shipped behavior
**Companion specs:** `BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md` §6.3–6.5, `NYM-HIVERELAY-METADATA-PRIVACY-TECHNICAL-SPEC-V1`, `TOR-V3-RELAY-ANONYMITY-SPEC-V1`, `RELAY-ANONYMITY-DECISION-MATRIX-V1`
**Existing code:** `packages/core/core/protocol/forward-relay.js` (shipped byte-bridge), `packages/core/transports/tor/index.js` (shipped Tor transport)

---

## 0. What this spec covers — and what it does not

This specification defines **client-side route separation**: how a client's network identity (IP address, browser Origin) is separated from its storage requests, so the storage relay cannot bind "who asked" to "what was asked for."

**Covers:**
- `split-web-ohttp-v1` — for ordinary browsers, using RFC 9458 Oblivious HTTP
- `split-native-protomux-v1` — for Pear/Bare/Node clients, using Protomux/Noise two-hop forwarding

**Does NOT cover:**
- Relay-side anonymity (relay IP hidden from clients) — that's `TOR-V3-RELAY-ANONYMITY-SPEC-V1`
- Traffic-analysis resistance (cover traffic, mixing) — that's the Nym spec
- Read-interest privacy (G4-I: "you can't tell which post I read") — needs PIR/ORAM, explicitly out of scope
- Bulk data transfer privacy — the split transport protects the *request path*; bulk Hypercore replication follows the existing forward-relay/Tor paths

**Guarantee ceiling (honest):** G2-W (wire opacity) + G4-T (route separation) under A/B non-collusion. NOT G4-I. NOT traffic-analysis resistance. NOT global-observer resistance.

---

## 1. Dev-profile design review

Before writing the wire protocol, this design was reviewed against three engineering lenses from the p2p brain. Their pressure shaped the spec; their approvals are recorded here.

### 1.1 Filippo Valsorda lens — security-first minimalism

**Applied pressure:**
- "Zero-config or no config options" — the OHTTP client MUST auto-discover gateway keys from the signed capability doc, not require manual configuration.
- "Small explicit keys" — the HPKE key config is one Ed25519-signed structure with exactly one public key, not a negotiable matrix.
- "Strong defaults over customization" — the padding classes are fixed buckets, not configurable.
- "UNIX-style composability" — the oblivious ingress is a separate process from the gateway, communicating only via the OHTTP binary format. No shared state, no shared runtime.

**Approval:** *"The OHTTP path is the right shape — RFC 9458 is a reviewed standard, not invented crypto, and the gateway key config is minimal and self-certifying. The opaque-origin iframe construction is the one piece I'd want to see wire-captured across all three browser engines before believing it. Don't ship 'application-blind ingress' until that evidence exists; 'storage-wire app opacity' is the honest label until then."*

### 1.2 Yawning Angel lens — protocol-heavy correctness

**Applied pressure:**
- "Explicit invariants and fail-fast behavior" — every frame has exact-length checks, reserved-bit rejection, and domain-separated signatures. Malformed input fails before allocation.
- "Extensive vector-based testing" — conformance requires byte-exact test vectors for every frame type, every error code, and every padding class.
- "Small focused packages" — the OHTTP codec, the ingress forwarder, and the gateway decapsulator are separate modules with narrow interfaces.
- "Clear separation between protocol state, primitives, and test scaffolding" — the Noise session state, the OHTTP HPKE operations, and the blind-service dispatch are independent layers.

**Approval:** *"The frame format is sound — domain-separated, fixed-width integers, no host-language serialization on the wire. The Protomux split is the right first build because it reuses existing Noise primitives. Two things I'd insist on: (1) the FORWARD family's flow control (WINDOW/DATA offset) MUST be exactly the spec's, not a re-derivation — flow control bugs are how you get memory exhaustion; (2) the OHTTP key rotation overlap window MUST be at least 2 epochs, and clients MUST reject any config whose validity exceeds 30 days. Both are in the spec; keep them there."*

### 1.3 David Mark Clements (DMC) lens — hot-path performance

**Applied pressure:**
- "Optimize the hot path first" — the OHTTP encapsulation adds one HPKE seal per request; the decapsulation adds one HPKE open. Both are sub-millisecond on modern hardware. The expensive part is the extra network hop, not the crypto.
- "Treat benchmarks as product surface" — the conformance gate includes p50/p95 latency measurements for both profiles, with explicit thresholds.
- "Preserve compatibility deliberately" — both profiles carry the same canonical blind-service messages (DESCRIBE/CELL/INBOX/CORE/FORWARD). The transport is transparent to the application.
- "Keep public APIs explicit and small" — the client surface is one function: `blindRequest(operation, payload, privacyPolicy)` that returns a result + coverage evidence.

**Approval:** *"The hot path is clean — one HPKE seal + one HTTP round-trip for browsers, one Noise frame + one forward hop for native. The extra latency is the real cost, not the crypto. Two things: (1) the padding buckets MUST be benchmarked — don't pad everything to 32 KiB just because it's simpler; measure the actual request size distribution and pick buckets that cover 95th percentile without wasting bandwidth. (2) The Protomux forward path reuses `forward-relay.js`'s caps — good, don't add a second cap system. The existing 64 MB per-forward and 5 forwards/peer limits are the right starting point; measure before adjusting."*

---

## 2. Architecture

```
BROWSER PATH (split-web-ohttp-v1):

  Browser ──HTTPS──▶ Oblivious Ingress A ──OHTTP──▶ Gateway/Storage B
   (has IP,          (sees IP + opaque        (sees decapsulated
    Origin)           OHTTP message;           request + ingress IP;
                      NOT the inner             NOT browser IP or
                      request)                  Origin)

  Privacy: A and B must be independently operated. Under non-collusion:
           B cannot bind the request to the browser's IP.
           A cannot read the request content.
           Neither alone identifies both "who" and "what."


NATIVE PATH (split-native-protomux-v1):

  Native client ──Noise──▶ Entry relay A ──Noise──▶ Exit relay B ──▶ Storage C
   (has IP)                (sees client IP           (sees entry IP         (sees exit IP,
                            + chosen exit;            + storage dest;        NOT client IP)
                            NOT storage dest          NOT client IP)
                            or payload)

  Privacy: A, B, C should be different operators. Under non-collusion:
           C cannot bind the request to the client's IP.
           A cannot see the blind payload (end-to-end Noise over the circuit).
           The forward-relay byte bridge is reused; only framing changes.
```

### 2.1 Role separation table

| Role | Sees | Does NOT see |
| --- | --- | --- |
| **Browser** | Its own IP, the ingress URL, the OHTTP gateway config | The gateway/storage IP |
| **Oblivious ingress (A)** | Browser IP, opaque OHTTP message, outer size/timing, selected gateway route | Inner operation, slot, cell bytes, app identity |
| **Gateway/storage (B)** | Ingress IP, decapsulated operation, random slot, padding class, timing/volume | Browser IP, browser Origin, app path/credential |
| **Native client** | Its own IP, entry relay endpoint | Exit relay identity, storage destination (until circuit opens) |
| **Entry relay (A)** | Client IP, chosen exit, circuit sizes/timing | Storage destination, blind operation, payload, app identity |
| **Exit relay (B)** | Entry identity/IP, storage endpoint, circuit sizes/timing | Original client IP, end-to-end blind payload |
| **Storage (C)** | Exit IP, generic operation, random slot, padding class, timing/volume | Original client IP, entry identity, app fields |

No row promises non-collusion. The claim is conditional on independent operation.

---

## 3. Profile 1: split-web-ohttp-v1 (browser path)

### 3.1 Standards used

- **RFC 9458** — Oblivious HTTP (OHTTP). Request/response encapsulation using HPKE.
- **RFC 9180** — HPKE (Hybrid Public Key Encryption). One-shot seal/open.
- **RFC 9292** — Binary HTTP. bHTTP framing for the inner request/response.
- No new cryptographic constructions. No invented HPKE suites.

### 3.2 Gateway key configuration

The gateway publishes a signed key config. Clients fetch it via `DESCRIBE` on the ingress or through the signed capability document.

```text
BlindOhttpKeyConfigV1 {
  version:           u8 = 1
  gatewayRelayKey:   32 bytes          // Ed25519 public key of the gateway operator
  configId:          u8                // rotation identifier
  kemId:             u16               // RFC 9180 KEM (default: 0x0010 = DHKEM(X25519))
  kdfId:             u16               // RFC 9180 KDF (default: 0x0001 = HKDF-SHA256)
  aeadId:            u16               // RFC 9180 AEAD (default: 0x0001 = AES-128-GCM)
  encodedPublicKey:  bounded bytes[1..256]  // KEM public key
  notBeforeEpoch:    u32               // seconds, inclusive
  notAfterEpoch:     u32               // seconds, exclusive
  previousConfigHash: optional 32 bytes  // BLAKE2b-256 of prior config for chained rotation
  signature:         64 bytes          // Ed25519 signature by gatewayRelayKey
}
```

**Signature domain:** `ASCII("hiverelay.blind.ohttp-key-config.v1\0") || ` all preceding bytes.

**Rules:**
- Configs MUST overlap for at least 2 epochs during rotation.
- Clients reject: rollback below a witnessed config, unknown suites, validity > 30 days (2,592,000 seconds), or reuse of `configId` with different key bytes.
- The `configId` space is per-gateway-operator (per `gatewayRelayKey`), not global.

### 3.3 OHTTP request encapsulation

For each blind-service operation (CELL.PUT, CELL.GET, INBOX.READ, etc.):

1. **Build the inner binary HTTP request** (RFC 9292 bHTTP framing):
   - Method: `POST`
   - Path: one of the five fixed routes (`/api/blind/v1/cell`, `/api/blind/v1/inbox`, etc.)
   - Body: the canonical `BlindDispatchFrameV1` (from the master spec §7.3.1)
   - No `Origin`, `Referer`, `Cookie`, `Client-Hint`, or `Fetch-Metadata` headers. Only `Content-Type: application/ohttp-msg`.

2. **HPKE seal** (RFC 9180) the binary HTTP request using the gateway's public key:
   - Fresh HPKE context per request (no context reuse).
   - `info` parameter: `ASCII("ohttp-req") || configId`
   - Output: `enc || ciphertext` where `enc` is the KEM encapsulated key.

3. **Wrap in the OHTTP request envelope** (RFC 9458 §3):
   - 1 byte: `configId`
   - `enc` length-prefixed
   - `ciphertext` (the rest)

4. **Pad** to the next negotiated size bucket (§3.5).

5. **POST** to the shared generic ingress route: `POST /ohttp req`. The ingress URL is the same for all apps using the substrate.

### 3.4 Oblivious ingress service

The ingress is a new HiveRelay role. It is deliberately minimal:

```text
Receive POST /ohttp-req
  ├── Verify Content-Type = application/ohttp-msg
  ├── Read the configId from byte 0
  ├── Look up the gateway route for this configId (from signed descriptor)
  ├── Strip ALL browser headers:
  │     Origin, Referer, Cookie, Set-Cookie, Client-Hint-*,
  │     Sec-Fetch-*, Sec-CH-*, User-Agent, Accept-Language,
  │     Forwarded, X-Forwarded-For, X-Real-IP
  ├── Forward ONLY:
  │     the opaque OHTTP message body
  │     + the generic gateway route
  │     + a new ingress-generated correlation ID (random 16 bytes,
  │       used only for this request's response matching, never logged)
  └── Return the gateway's opaque response to the browser
```

**Critical:** The ingress does NOT decrypt the OHTTP message. It cannot see the inner request. It sees only "a browser at IP X sent an opaque blob to gateway Y."

### 3.5 Padding classes

Fixed-size buckets, negotiated in the gateway key config. Both request and response are padded to the next bucket.

```text
SizeClass  Request bytes  Response bytes  Use case
0          1 KiB          1 KiB           DESCRIBE, small CELL.GET
1          4 KiB          4 KiB           CELL.PUT (typical post), INBOX.READ
2          16 KiB         16 KiB          CELL.PUT (long body), BATCH_GET
3          64 KiB         64 KiB          maximum single request
```

**Selection:** the client picks the smallest bucket that fits the request. The gateway picks the smallest bucket that fits the response. No negotiation per-request — the bucket is determined by size alone, not by content.

### 3.6 The opaque-origin iframe construction

The browser's `Origin` header is sent by the page's origin, which the ingress sees. To hide it, the OHTTP client runs inside a sandboxed opaque-origin iframe:

```html
<iframe sandbox="allow-scripts"
        src="about:blank"
        style="display:none"
        id="ohttp-worker">
</iframe>
```

The iframe has:
- `sandbox="allow-scripts"` WITHOUT `allow-same-origin` → the iframe gets an opaque origin, not the app's origin.
- Communication via `MessageChannel` (bounded binary jobs only, no structured cloning of app objects).
- `credentials: "omit"`, `referrerPolicy: "no-referrer"` on all fetches.

**What this achieves:** the `fetch()` call inside the iframe sends `Origin: null` (or omits it entirely, depending on browser), not `Origin: https://peerit.site`.

**What it does NOT achieve (until proven):** some browsers may leak the app origin through other channels (SNI, TLS session resumption, cache timing, service worker registration, error messages). The conformance gate (§6) requires wire-capture evidence across Chromium, Firefox, and Safari/iOS proving none of these leak a stable app discriminator.

**Honest label until that gate passes:** "storage-wire app opacity" — NOT "application-blind ingress."

---

## 4. Profile 2: split-native-protomux-v1 (native path)

### 4.1 What's reused

The existing `forward-relay.js` already provides:
- Demand-dialled byte bridging: `OPEN(targetPubkey)` → relay dials target → bridges DATA frames.
- Onion composition: `connectViaForward(relay2, relay1)` gives a 2-hop path.
- Caps: 64 MB/forward, 5 forwards/peer, 30 dials/min/peer, 64 KB/frame.

**What changes:** the OPEN/DATA/CLOSE messages are upgraded to the spec's `BlindForward` family with circuit nonces, request commitments, flow control, and signed open-results.

### 4.2 BlindForward frame formats

These extend the existing `forward-relay.js` protocol. The frames ride on the same Protomux channel (`FORWARD_PROTOCOL_NAME = 'hiverelay-forward'`).

#### 4.2.1 BlindForwardOpenV1

```text
offset  size  field
0       1     version = 1
1       32    targetPubkey              // the exit/storage relay's Ed25519 key
33      16    routeId                   // random, identifies this circuit
49      32    nextDescriptorHash        // BLAKE2b-256 of the next hop's signed descriptor
81      32    circuitNonce              // random, binds all frames on this circuit
113     4     requestedInitialWindow    // 64 KiB..1 MiB
117     4     requestedIdleMillis        // 1000..120000
121     4     requestedLifetimeMillis    // 1000..3600000
125     32    hopAdmission               // anonymous quota token or PoW proof
157     32    requestCommitment          // BLAKE2b-256 of all preceding fields
189     64    signature                  // Ed25519 by the entry relay's key
```

**Signature domain:** `ASCII("hiverelay.blind.forward-open.v1\0")`

#### 4.2.2 BlindForwardOpenResultV1

```text
offset  size  field
0       1     version = 1
1       32    relayPublicKey             // the relay that processed the OPEN
33      16    routeId                    // echoed from the request
49      32    nextDescriptorHash         // echoed
81      32    circuitNonce               // echoed
113     8     streamId                   // assigned by this relay
121     4     grantedInitialWindow       // <= requested, <= 1 MiB
125     4     maxDataBytes               // 1..65536
129     8     maxCircuitBytes            // aggregate both directions
137     4     idleMillis                 // <= requested, <= 120000
141     4     lifetimeMillis             // <= requested, <= 3600000
145     4     openedAtEpoch              // when the circuit was created
149     32    requestCommitment          // echoed from the OPEN
181     64    signature                  // Ed25519 by relayPublicKey
```

**Signature domain:** `ASCII("hiverelay.blind.forward-open-result.v1\0")`

#### 4.2.3 BlindForwardDataV1

```text
offset  size  field
0       1     version = 1
1       32    circuitNonce               // identifies the circuit
33      8     offset                     // strictly increasing, next expected byte
41      n     bytes                      // 1..maxDataBytes of opaque payload
```

The payload is end-to-end Noise-encrypted by the client and the storage relay. The forward relays see only opaque bytes — exactly like Tor relays see only cells.

#### 4.2.4 BlindForwardWindowV1

```text
offset  size  field
0       1     version = 1
1       32    circuitNonce
33      8     consumedThrough            // bytes consumed by the next hop
41      4     creditIncrement            // 1..1 MiB; total credit remains capped
```

#### 4.2.5 BlindForwardCloseV1

```text
offset  size  field
0       1     version = 1
1       32    circuitNonce
33      1     closeKind                  // 1=FIN (send side), 2=ABORT (both sides)
34      8     finalSendOffset
42      1     reasonCode                 // generic bounded enum, no app text
```

### 4.3 End-to-end Noise session

On top of the forward circuit, the client and the storage relay run a separate Noise XX handshake. The Noise session carries the canonical blind-service messages (CELL/INBOX/CORE/DESCRIBE). The forward relays (entry and exit) see only Noise-encrypted bytes — they cannot read the operations.

This is the same pattern Tor uses: the circuit carries cells; the application-layer encryption (TLS in Tor's case, Noise here) protects the content from the relays.

### 4.4 Fallback policy

```text
strict mode:
  if no split path available → FAIL CLOSED
  never silently use direct

balanced mode:
  if no split path available → explicit user/policy permission to use direct
  claim downgrades visibly in the UI
  log the downgrade in coverage evidence
```

---

## 5. Transport descriptors

Both profiles require signed, expiring transport descriptors advertised via `DESCRIBE`:

```text
BlindTransportDescriptorV1 {
  version:          u8 = 1
  relayIdentityKey: 32 bytes          // stable Ed25519 operator key
  role:             u8                // 1=ingress, 2=gateway, 3=entry, 4=exit, 5=storage, 6=onion
  protocolVersion:  u16               // hiverelay-blind major.minor
  endpoint:         bounded string    // URL (OHTTP) or pubkey (Protomux)
  ohttpConfigHash:  optional 32 bytes // if role=ingress, hash of current key config
  paddingClasses:   u8                // bitmap of supported size classes
  notBeforeEpoch:   u32
  notAfterEpoch:    u32
  signature:        64 bytes          // Ed25519 by relayIdentityKey
}
```

**Domain:** `ASCII("hiverelay.blind.transport-descriptor.v1\0")`

Clients select transports based on:
1. The signed descriptor (is it valid? is the role what I need?)
2. The privacy policy (strict/balanced)
3. Operator diversity (are entry, exit, storage different operators?)
4. Health (is the endpoint reachable?)

---

## 6. Conformance gates

### 6.1 OHTTP conformance (P3-W)

| Gate | What it proves |
| --- | --- |
| `ohttp-key-rotation` | Configs overlap ≥2 epochs; clients reject rollback/stale/reused-configId |
| `ohttp-encap-roundtrip` | A CELL.PUT encapsulated → ingress → gateway → decapsulated → dispatched, with correct response |
| `ohttp-header-strip` | Ingress logs contain NO browser Origin/Referer/Cookie/IP after forwarding |
| `ohttp-opaque-frame` | Wire capture across Chromium, Firefox, Safari proving `Origin: null` and no SNI/cache/SW leak |
| `ohttp-padding-buckets` | Request/response sizes match the bucket table exactly; no size-based fingerprinting within a bucket |
| `ohttp-non-collusion` | Ingress and gateway on separate hosts; logs from both sides cannot link IP to slot without the other |

### 6.2 Protomux split conformance (P3-N)

| Gate | What it proves |
| --- | --- |
| `forward-frame-vectors` | Byte-exact test vectors for BlindForwardOpen/Data/Window/Close/OpenResult |
| `forward-flow-control` | WINDOW never grants > 1 MiB outstanding; zero-credit stops reading; no unbounded queue |
| `forward-noise-e2e` | Entry/exit relays see only opaque bytes; blind-service messages verify end-to-end |
| `forward-circuit-lifecycle` | ABORT, quota-expiry, idle-timeout, and maxCircuitBytes all close cleanly with resource release |
| `forward-fail-closed` | Strict mode rejects direct fallback; balanced mode downgrades visibly |

### 6.3 Shared conformance

| Gate | What it proves |
| --- | --- |
| `abi-hash-stable` | Adding the FORWARD family doesn't break the frozen ABI hash without re-versioning |
| `coverage-evidence` | The path resolver returns evidence-bearing results, not just a transport name |
| `downgrade-visible` | UI shows which privacy tier the user is actually on |

---

## 7. Threat model

### 7.1 What split transport achieves (honestly)

| Property | Achieved? | Under what assumption |
| --- | --- | --- |
| Storage relay cannot see client IP | ✅ Yes | Ingress ≠ storage operator (non-collusion) |
| Ingress cannot see request content | ✅ Yes | HPKE encryption (cryptographic) |
| Storage relay cannot see browser Origin | ✅ Yes | OHTTP encapsulation strips headers; opaque iframe hides origin |
| Storage relay cannot tell which app | 🟡 Partial | At G2-W yes; but gateway/route choice, padding schedule, and traffic cadence can fingerprint apps that select distinct configs. Shared route pool required for the stronger claim. |
| Timing correlation resistance | ❌ No | No cover traffic; timing/volume observable |
| Read-interest privacy (which slot you read) | ❌ No | The gateway sees the decapsulated request including the slot. Needs PIR. |
| Global observer resistance | ❌ No | A global adversary can correlate ingress and gateway traffic |

### 7.2 Adversary analysis

| Adversary | Can | Cannot |
| --- | --- | --- |
| Honest-but-curious ingress | See client IP, opaque OHTTP message size, selected gateway route | Read the inner request, identify the app (if shared routes), see the slot |
| Honest-but-curious gateway/storage | See decapsulated request, slot, padding class, ingress IP, timing | See client IP, browser Origin, app credential |
| Colluding ingress + gateway | Correlate client IP to requested slot via timing/volume matching | Break HPKE encryption; read the Noise-protected payload on the native path |
| Global passive observer | Observe both ingress and gateway traffic; statistically correlate | Break encryption; but can infer the relationship with enough traffic |
| Malicious ingress (drops/replays) | Drop messages, replay OHTTP messages (idempotent handlers absorb this) | Forge or modify the inner request (HPKE integrity) |
| Compromised browser origin | Ship malicious JS, steal capabilities before encapsulation | This is outside transport security; mitigated by signed-release chain + PearBrowser |

---

## 8. Honest claim ladder for split transport

Following the same discipline as the substrate's G0–G5 ladder:

| Claim | True? | Conditions |
| --- | --- | --- |
| "Your IP is hidden from the storage relay" | ✅ | Under A/B non-collusion |
| "The ingress cannot read your request" | ✅ | Cryptographically (HPKE) |
| "The storage relay cannot tell which app you're using from the wire" | 🟡 | At G2-W with shared routes and opaque iframe; "storage-wire app opacity" until wire-capture proof |
| "The storage relay cannot tell which post you read" | ❌ | Needs PIR; explicitly out of scope |
| "Your traffic is anonymous" | ❌ | Timing/volume/IP-to-slot correlation possible under collusion |
| "It resists a global observer" | ❌ | No cover traffic; research-grade only |

**Forbidden claims:** "anonymous," "untraceable," "the relay can't see you." All imply stronger properties than split transport delivers.

**Permitted claims:** "source-IP-separated under non-collusion," "request content hidden from the ingress," "storage-wire app opacity (pending wire proof)."

---

## 9. Implementation work plan

### Phase 1: Protomux split (native, weeks 2–4)

| WP | Deliverable | Effort |
| --- | --- | --- |
| ST-01 | Upgrade `forward-relay.js` to BlindForward frames (Open/OpenResult/Data/Window/Close) | Medium |
| ST-02 | End-to-end Noise session over the forward circuit | Medium |
| ST-03 | Transport descriptors (signed, role-tagged, health-gated) | Small |
| ST-04 | Strict/balanced fallback policy + coverage evidence | Small |
| ST-05 | P3-N conformance tests + byte-exact vectors | Medium |

**Gate:** ≥2 independent operators (entry ≠ exit ≠ storage).

### Phase 2: OHTTP split (browser, weeks 4–8)

| WP | Deliverable | Effort |
| --- | --- | --- |
| ST-06 | `BlindOhttpKeyConfigV1` signing, advertisement, rotation | Small |
| ST-07 | OHTTP encapsulation (RFC 9458 + 9180) in the browser client | Medium |
| ST-08 | Oblivious ingress service (receive → strip → forward) | Medium |
| ST-09 | Gateway/storage decapsulation adapter | Small |
| ST-10 | `opaque-ohttp-frame-v1` sandboxed iframe construction | Hard |
| ST-11 | Cross-browser wire capture (Chromium, Firefox, Safari/iOS) | Medium-high |
| ST-12 | Padding class benchmarking (real request distribution) | Small |
| ST-13 | P3-W conformance tests | Medium |

**Gate:** independently operated ingress + gateway; wire-capture proof across all three browser engines.

### Phase 3: shared route pool + ongoing discipline

| WP | Deliverable | Effort |
| --- | --- | --- |
| ST-14 | Shared generic route pool (all substrate apps use the same ingress URL + routes) | Small code, ongoing discipline |
| ST-15 | App-neutral selection policy (no per-app gateway/route/config) | Small |
| ST-16 | Ongoing non-collusion auditing (operator diversity evidence) | Operational |

---

## 10. Relationship to existing specs

| Existing spec | Relationship |
| --- | --- |
| `BLIND-APP-AGNOSTIC-MASTER-SPEC.md` §6.3 | This spec implements the `split-web-ohttp-v1` and `split-native-protomux-v1` profiles defined there |
| `BLIND-APP-AGNOSTIC-MASTER-SPEC.md` §7.3.2 | This spec implements the FORWARD family frames defined there |
| `NYM-HIVERELAY-METADATA-PRIVACY-SPEC` | Complementary: Nym covers control-plane mixing; this spec covers bulk request routing. They compose: Nym for bounded async control, split transport for synchronous CELL/INBOX operations |
| `TOR-V3-RELAY-ANONYMITY-SPEC` | Orthogonal: Tor hides the *relay's* location from clients; this spec hides the *client's* location from the relay. Both can be active simultaneously |
| `RELAY-ANONYMITY-DECISION-MATRIX` | This spec adds the client-side axis that the decision matrix's `relayLocation` axis complemented |

---

## 11. What does NOT change

- The canonical blind-service messages (DESCRIBE/CELL/INBOX/CORE/FORWARD) are unchanged.
- The `abiHash` registration for the existing five families is unchanged.
- Adding the FORWARD family's BlindForward frames to the wire protocol requires an `abiHash` bump — all conforming clients and relays update together.
- Application logic (peerit's posts, votes, moderation) is completely unaware of which transport profile is in use.
- The blind substrate's storage guarantees (G0/G1/G2-S/G3) are independent of transport. Split transport adds G2-W/G4-T on top; it does not weaken any existing guarantee.
