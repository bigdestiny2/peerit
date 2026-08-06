#!/usr/bin/env node

// LIVE WRITE DRILL — Peerit T2 CELL.PUT milestone. Real Chromium, LIVE fleet,
// ONE declared smoke comment authored against the pow-issuance-v1 write path.
//
//   node scripts/browser-peerit-t2-cell-put-live-drill.mjs --out <transcript.json>
//
// Proves, on the LIVE relays (public endpoints only — describe/cell/issuer):
//   (a) the signed limited Cell-PUT authority profile verifies at release 28;
//   (b) ONE comment record is built through the app's genuine construction path
//       (PeeritLocalIdentityV1 + Data.addComment over PeeritSubstrateSync: v2
//       seal, okey key binding, REAL 14-bit in-record PoW, Ed25519 signature)
//       and passes the app's own ingest verifier (tag-334 operation authority,
//       content-id/target/PoW re-derivation, moderation overlay);
//   (c) BOTH live relays qualify through the GENUINE
//       qualifyPermissionlessRelayCandidates seam with
//       createPowIssuanceV1AdmissionProviderFactory (descriptor walk + health +
//       descriptor-driven admission parameters all real);
//   (d) ONE 20-bit pow-issuance mint buys ONE 2-slot token (ONE /challenge,
//       ONE /redeem — never more) admitting ONE CELL.PUT per relay;
//   (e) each CELL.PUT receipt is verified twice: page-side by the vendored
//       control's verifyOperationResult (the production path) and Node-side by
//       the reference blind-protocol codec + relay public key (status STORED);
//   (f) byte-exact CELL.GET readback on BOTH relays opens to the exact authored
//       record, which then renders (marker text) through the app's genuine
//       render pipeline in the page DOM;
//   (g) NO INBOX operation of any kind is constructed or sent (traced log).
//
// Fleet etiquette: exactly ONE authored record per run (ONE token, ONE PUT per
// relay). Read-only phases retry transient failures with backoff; the write
// never re-mints inside a run. Re-runs mint a NEW record (fresh timestamp).
//
// CSP note: the production seq-28 connect-src allows the two relay origins but
// NOT the :8443 pow-issuance issuer origins (different origins). The drill page
// therefore relaxes connect-src by EXACTLY those two issuer origins and records
// the deviation in the transcript; every other directive byte is the production
// CSP, and the page-side code path (modules, issuer URLs) is byte-identical to
// what production runs. A local proxy was rejected: it would have changed the
// page-side URL the spend provider fetches, i.e. the code path under test.
//
// CORS note (fleet finding): separately from CSP, the issuer origins answer
// without CORS headers while both relay edges emit Access-Control-Allow-Origin:
// *. The drill emulates ONLY that header posture at the browser boundary
// (Playwright route; see below) so Chromium exposes the issuer's own genuine
// responses to the page. The production write path needs the same one-line
// fleet fix; the drill transcript records it as a finding.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { chromium } from 'playwright'
import sodium from 'sodium-universal'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
// Production truth is the DEPLOYED fleet tree (00-core/hiverelay).
const VI_ROOT = process.env.HIVERELAY_V1_INTEGRATION_ROOT ||
  path.resolve(ROOT, '..', '..', '00-core', 'hiverelay')
const vi = (...parts) => pathToFileURL(path.join(VI_ROOT, ...parts)).href
const protocol = await import(vi('packages', 'blind-protocol', 'index.js'))
const {
  CELL_RECEIPT_RESULT,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindReceiptV1,
  decodeCanonical,
  resultSignaturePayload
} = protocol
// Independent Node-side ingest check of the exact bytes the relays served back
// (same genuine modules the page runs — they are environment-portable).
const { decodePeeritInnerOperationBatchV1 } =
  await import(pathToFileURL(path.join(ROOT, 'js/substrate/peerit-operation-authority-v1.js')).href)
const { unseal } = await import(pathToFileURL(path.join(ROOT, 'js/seal.js')).href)
const { hasValidContentId, hasValidContentRef, validCommunitySlug, TYPE } =
  await import(pathToFileURL(path.join(ROOT, 'js/model.js')).href)
const { MIN_BITS, verify: verifyPow } =
  await import(pathToFileURL(path.join(ROOT, 'js/pow-current.js')).href)

const EXPECTED_CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; " +
  "connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz " +
  "https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const ISSUER_ORIGINS = Object.freeze([
  'https://relay-syd.p2phiverelay.xyz:8443',
  'https://relay-dal.p2phiverelay.xyz:8443'
])
// The drill CSP: production bytes with connect-src extended by exactly the two
// pow-issuance issuer origins the signed Cell-PUT profile pins. Nothing else.
const DRILL_CSP = EXPECTED_CSP.replace(
  'https://relay-dal.p2phiverelay.xyz;',
  'https://relay-dal.p2phiverelay.xyz https://relay-syd.p2phiverelay.xyz:8443 https://relay-dal.p2phiverelay.xyz:8443;')
assert.notEqual(DRILL_CSP, EXPECTED_CSP)

const RELEASE_SEQUENCE = 28
// Release-pinned discovery authority (the production runtime authority pins the
// same key): deploy/peerit-seed-bootstrap-v1-seq28.json payload.authorityPublicKey.
const SEED_AUTHORITY_PUBLIC_KEY = '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec'
// The designated drill target: the r/hiverelay seed post inside the signed
// seq-28 bootstrap (identified by reading the 39 signed seed records back from
// the live relays; every field below is re-verified at runtime from the exact
// served bytes, never trusted from this table).
const PARENT = Object.freeze({
  community: 'hiverelay',
  recordId: 'afd1d932c00538718de03a3131dd6a7cdcc3f314ad33aa44022b6472625dc165',
  cid: '437e05f8d467571c46c37e8fedae89a2c89a76307fd465e7b4982177318753ba',
  author: 'e3a7a4265251ac07dbffa099a189b1af4dc54926a31cbb577507c375f5a791fd',
  contentNonce: 'v1-seed-p2pbuilders-7'
})
const MARKER = 'T2 write smoke — declared, lease expires ≤30d'
const LEASE_CLASS = 2 // profile maximumCellLeaseClass; 28 epochs = 7 days ≤ 30d
const UNTIL_PHASES = new Set(['authority', 'qualify', 'parent', 'author', 'full'])

function fail (message) { throw new Error(message) }

function argument (name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

function sha256 (bytes) { return createHash('sha256').update(bytes).digest('hex') }

function log (line) { console.log(`    [t2-live-drill] ${line}`) }

function contentType (file) {
  if (file.endsWith('.html')) return 'text/html; charset=utf-8'
  if (file.endsWith('.mjs') || file.endsWith('.js')) return 'text/javascript; charset=utf-8'
  if (file.endsWith('.json')) return 'application/json; charset=utf-8'
  if (file.endsWith('.md')) return 'text/markdown; charset=utf-8'
  if (file.endsWith('.css')) return 'text/css; charset=utf-8'
  if (file.endsWith('.svg')) return 'image/svg+xml'
  if (file.endsWith('.png')) return 'image/png'
  if (file.endsWith('.ico')) return 'image/x-icon'
  return 'application/octet-stream'
}

function send (response, status, type, body) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body)
  response.writeHead(status, {
    'Content-Type': type,
    'Content-Length': bytes.byteLength,
    'Content-Security-Policy': DRILL_CSP,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  })
  response.end(bytes)
}

// ---------------------------------------------------------------------------
// The page-side drill controller. Served from the local harness and executed by
// real Chromium under the drill CSP. Every import below resolves inside the
// signed seq-28 web closure; no drill-only page module weakens a check.
// ---------------------------------------------------------------------------
function controllerSource ({ untilPhase }) {
  return `
import {
  PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  verifyPeeritLimitedCellPutProfileV1
} from '/js/substrate/limited-cell-put-profile.mjs';
import {
  POW_ISSUANCE_V1_SCHEME_ID,
  createPowIssuanceV1AdmissionProviderFactory
} from '/js/substrate/pow-issuance-spend-provider.mjs';
import {
  isTransientDescriptorFetchFailure,
  qualifyPermissionlessRelayCandidates
} from '/js/substrate/relay-consumer.js';
import { createBlindCellRelay } from '/js/substrate/blind-client-relay.js';
import {
  decodePeeritSeedReadCapabilityV1,
  hashPeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '/js/substrate/seed-bootstrap-v1.mjs';
import {
  createPeeritInnerOperationBatchV1,
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '/js/substrate/peerit-operation-authority-v1.js';
import { createPeeritSubstrateSync } from '/js/substrate/peerit-substrate-sync.js';
import { createMemoryPeeritJournal } from '/js/substrate/peerit-journal.js';
import { createPeeritProductRuntimeV1 } from '/js/substrate/peerit-product-runtime.js';
import { createPeeritLocalIdentityV1 } from '/js/substrate/local-identity.js';
import { createIdentityStore, memoryKv } from '/js/identity-store.js';
import { mountPeeritProductUiV1 } from '/js/substrate/peerit-product-ui.js';
import {
  TYPE,
  hasValidContentId,
  hasValidContentRef,
  validCommunitySlug
} from '/js/model.js';
import { unseal } from '/js/seal.js';
import { expectedKeyV2 } from '/js/canon.js';
import { MIN_BITS, verify as verifyPow } from '/js/pow-current.js';
import * as control from '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs';
import * as cellGetModule from '/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs';

const UNTIL=${JSON.stringify(untilPhase)};
const PARENT=${JSON.stringify(PARENT)};
const MARKER=${JSON.stringify(MARKER)};
const LEASE_CLASS=${LEASE_CLASS};
const SEED_AUTHORITY_PUBLIC_KEY=${JSON.stringify(SEED_AUTHORITY_PUBLIC_KEY)};
const RELEASE_SEQUENCE=${RELEASE_SEQUENCE};
const EXTERNAL_ORIGINS=new Set([
  'https://relay-syd.p2phiverelay.xyz',
  'https://relay-dal.p2phiverelay.xyz',
  'https://relay-syd.p2phiverelay.xyz:8443',
  'https://relay-dal.p2phiverelay.xyz:8443'
]);
const EPOCH_MILLIS=21600000;

const requests=[];
const violations=[];
let phase='controller-start';
const t0=Date.now();

document.addEventListener('securitypolicyviolation',event=>{
  violations.push({
    blockedURI:String(event.blockedURI||''),
    effectiveDirective:String(event.effectiveDirective||''),
    violatedDirective:String(event.violatedDirective||'')
  });
});

function setPhase(value){phase=value;globalThis.__peeritT2Phase=value;}
function elapsed(){return Date.now()-t0;}
function log(line){console.log('[t2-live-drill] +'+elapsed()+'ms '+line);}
function cleanError(error){
  return {
    name:String(error&&error.name||'Error'),
    code:error&&typeof error.code==='string'?error.code:null,
    message:String(error&&error.message||error)
  };
}
const encoder=new TextEncoder();
function hex(bytes){
  const view=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  let out='';
  for(const byte of view)out+=byte.toString(16).padStart(2,'0');
  return out;
}
function fromHex(value){
  const out=new Uint8Array(value.length/2);
  for(let i=0;i<out.length;i++)out[i]=Number.parseInt(value.slice(i*2,i*2+2),16);
  return out;
}
function bytesEqual(left,right){
  const a=left instanceof Uint8Array?left:new Uint8Array(left);
  const b=right instanceof Uint8Array?right:new Uint8Array(right);
  if(a.byteLength!==b.byteLength)return false;
  let d=0;
  for(let i=0;i<a.byteLength;i++)d|=a[i]^b[i];
  return d===0;
}
async function sha256hex(bytes){
  const view=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',view)));
}
function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}

// Every external fetch is traced; the trace is the no-INBOX / declared-route
// evidence (same-origin closure fetches are not relay traffic).
async function tracedFetch(input,init={}){
  const requestUrl=new URL(input instanceof Request?input.url:String(input),location.href);
  const external=EXTERNAL_ORIGINS.has(requestUrl.origin);
  let row=null;
  if(external){
    const method=String((init&&init.method)||(input instanceof Request&&input.method)||'GET').toUpperCase();
    let requestBytes=null;
    let requestSha256=null;
    const body=init&&init.body;
    if(body!=null&&(body instanceof Uint8Array||body instanceof ArrayBuffer||ArrayBuffer.isView(body))){
      const view=body instanceof Uint8Array?body:
        (body instanceof ArrayBuffer?new Uint8Array(body):new Uint8Array(body.buffer,body.byteOffset,body.byteLength));
      requestBytes=view.byteLength;
      requestSha256=await sha256hex(view);
    }
    row={at:Date.now(),phase,url:requestUrl.href,origin:requestUrl.origin,path:requestUrl.pathname,method,status:null,requestBytes,requestSha256,responseBytes:null,error:null};
    requests.push(row);
  }
  try{
    const response=await fetch(input,init);
    if(row){
      row.status=response.status;
      if(response.ok)row.responseBytes=(await response.clone().arrayBuffer()).byteLength;
    }
    return response;
  }catch(error){
    if(row)row.error=cleanError(error);
    throw error;
  }
}

function isTransient(error){
  if(!error)return false;
  if(isTransientDescriptorFetchFailure(error))return true;
  if(error.name==='AbortError'||error.name==='TimeoutError')return true;
  if(error instanceof TypeError)return true;
  const code=error.code;
  return code==='TRANSPORT_FAILURE'||code==='RETRYABLE_NOT_SENT'||
    code==='HIVERELAY_REMOTE_RETRYABLE'||code==='HIVERELAY_READBACK_PENDING'||
    code==='PEERIT_POW_ISSUANCE_CHALLENGE_UNAVAILABLE';
}
async function withRetry(label,fn,options={}){
  const attempts=options.attempts||5;
  const baseMillis=options.baseMillis||2000;
  let last=null;
  for(let attempt=1;attempt<=attempts;attempt++){
    try{return await fn(attempt);}
    catch(error){
      last=error;
      log('retry: '+label+' attempt '+attempt+'/'+attempts+': '+(error.code||error.name||'')+' '+String(error.message).slice(0,120));
      if(attempt===attempts||!isTransient(error))break;
      await sleep(Math.min(30000,baseMillis*(2**(attempt-1))));
    }
  }
  throw last;
}

const transcript={
  schema:'peerit-t2-cell-put-live-drill-v1',
  milestone:'T2 CELL.PUT live write drill',
  startedAt:new Date(t0).toISOString(),
  releaseSequence:RELEASE_SEQUENCE,
  marker:MARKER,
  leaseClass:LEASE_CLASS,
  csp:{},
  authority:{},
  relays:[],
  parent:{},
  record:{},
  token:{},
  write:{},
  render:{},
  assertions:{},
  requests,
  violations
};

async function run(){

// --------------------------------------------------------------------------
// Phase: authority — verify the signed Cell-PUT profile + signed seq-28 seed.
// --------------------------------------------------------------------------
setPhase('authority');
const profileBytes=new Uint8Array(await (await fetch('/peerit-limited-cell-put-profile-v1.json')).arrayBuffer());
const putProfile=verifyPeeritLimitedCellPutProfileV1(profileBytes,{releaseSequence:RELEASE_SEQUENCE});
if(putProfile.mode!=='explicit-user-writes'||putProfile.networkPuts!==1||putProfile.ordinaryDelivery!=='local-only'){
  throw new Error('PUT authority posture drifted');
}
const issuerUrlByRelayId=new Map();
const relayKeyHexByRelayId=new Map();
for(const row of putProfile.relays){
  issuerUrlByRelayId.set(row.relayId,new TextDecoder().decode(row.issuanceUrl));
  relayKeyHexByRelayId.set(row.relayId,hex(row.relayPublicKey));
}
transcript.authority.putProfile={
  schema:putProfile.schema,
  releaseSequence:putProfile.releaseSequence,
  mode:putProfile.mode,
  networkPuts:putProfile.networkPuts,
  ordinaryDelivery:putProfile.ordinaryDelivery,
  powIssuance:{
    schemeId:putProfile.powIssuance.schemeId,
    profileId:putProfile.powIssuance.profileId,
    difficultyBits:putProfile.powIssuance.difficultyBits,
    maximumTokenAllowance:putProfile.powIssuance.maximumTokenAllowance,
    maximumCellSizeClass:putProfile.powIssuance.maximumCellSizeClass,
    maximumCellLeaseClass:putProfile.powIssuance.maximumCellLeaseClass
  },
  relays:putProfile.relays.map(row=>({relayId:row.relayId,issuanceUrl:issuerUrlByRelayId.get(row.relayId),relayPublicKey:relayKeyHexByRelayId.get(row.relayId)}))
};
log('authority: limited Cell-PUT profile v1 verified at release '+putProfile.releaseSequence+
  ' (schemeId '+putProfile.powIssuance.schemeId+'/profileId '+putProfile.powIssuance.profileId+
  ', difficulty '+putProfile.powIssuance.difficultyBits+', allowance ≤'+putProfile.powIssuance.maximumTokenAllowance+
  ', sizeClass ≤'+putProfile.powIssuance.maximumCellSizeClass+', leaseClass ≤'+putProfile.powIssuance.maximumCellLeaseClass+', networkPuts 1 explicit-user-writes)');

const bootstrapBytes=new Uint8Array(await (await fetch('/peerit-seed-bootstrap-v1.json')).arrayBuffer());
// The artifact hash is self-computed over the exact served bytes (the release
// pin-history reverse binding is the runtime gate's proof, not this drill's);
// the release-pinned authority SIGNATURE is what authenticates the payload here.
const bootstrapHash=await hashPeeritSeedBootstrapV1(bootstrapBytes);
const seed=await verifyPeeritSeedBootstrapV1(bootstrapBytes,{
  authorityPublicKey:SEED_AUTHORITY_PUBLIC_KEY,
  releaseSequence:RELEASE_SEQUENCE,
  expectedArtifactHash:bootstrapHash,
  previousBootstrapHash:null,
  now:Date.now()
});
transcript.authority.seedBootstrap={
  artifactHash:bootstrapHash,
  sourceId:seed.sourceId,
  bootstrapSequence:Number(seed.payload.bootstrapSequence),
  releaseSequence:seed.payload.releaseSequence,
  authorityPublicKey:seed.payload.authorityPublicKey,
  signatureVerified:true,
  hashBinding:'self-computed over the served signed artifact (signature is the authority check)',
  recordCount:seed.payload.records.length,
  relays:seed.payload.relays.map(row=>row.relayId)
};
log('authority: signed seq-'+RELEASE_SEQUENCE+' seed bootstrap verified ('+seed.payload.records.length+' records, relays '+seed.payload.relays.map(r=>r.relayId).join('+')+')');

const parentRecord=seed.payload.records.find(row=>row.recordId===PARENT.recordId);
if(!parentRecord)throw new Error('designated parent record is not in the signed seed bootstrap');
if(parentRecord.authorPublicKey!==PARENT.author)throw new Error('designated parent author drifted');
transcript.parent={community:PARENT.community,recordId:PARENT.recordId,cid:PARENT.cid,author:PARENT.author,contentNonce:PARENT.contentNonce};

if(UNTIL!=='authority'){

// --------------------------------------------------------------------------
// Shared runtime pieces.
// --------------------------------------------------------------------------
const runtime=control.createBrowserCryptoRuntime(globalThis.crypto);
const nowEpoch=()=>Math.floor(Date.now()/EPOCH_MILLIS);
const monotonicMillis=()=>globalThis.performance.now();
const cellGet=cellGetModule.createBlindCellGetControl({
  runtime,
  nowEpoch,
  monotonicMillis,
  supportedProtocolProfiles:putProfile.supportedProtocolProfiles,
  supportedTransportProfiles:putProfile.supportedTransportProfiles,
  fetch:tracedFetch
});

// The ONE pow-issuance factory for the drill record (profileId 8 / schemeId 1,
// issuer origins exactly as the verified profile pins them).
const factory=createPowIssuanceV1AdmissionProviderFactory({
  profileId:PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  schemeId:POW_ISSUANCE_V1_SCHEME_ID,
  issuers:putProfile.relays.map(row=>({
    relayPublicKey:row.relayPublicKey,
    issuanceUrl:issuerUrlByRelayId.get(row.relayId)
  })),
  fetch:tracedFetch,
  onProgress:nonce=>log('mint progress: '+nonce+' pow-issuance candidates')
});

// In-memory drill vault: the seam's mandatory persistence seam, and the
// transcript's capture point for prepared replicas / verified receipts /
// verified readbacks. No crash recovery inside one drill page load.
const vault={entries:new Map(),captured:{prepared:new Map(),results:new Map(),readbacks:new Map()}};
function vaultKey(intentId,targetId){return intentId+':'+String(targetId).toLowerCase();}
function relayIdForPublicKey(value){
  // The flush machinery's targetContext carries relayPublicKey as a lowercase
  // hex string (blind-client-relay.js fixedHex); accept that or raw bytes.
  const publicKeyHex=typeof value==='string'?value.toLowerCase():hex(value);
  for(const row of putProfile.relays){
    if(hex(row.relayPublicKey)===publicKeyHex)return row.relayId;
  }
  return null;
}
async function persistPreparedReplica(input){
  const relayId=relayIdForPublicKey(input.targetContext.relayPublicKey);
  vault.entries.set(vaultKey(input.intentId,input.targetId),{
    stage:'prepared',
    revision:1,
    evidenceRef:null,
    payload:{
      version:1,stage:1,
      intentId:input.intentId,
      logicalId:input.logicalId,
      innerCodec:input.innerCodec,
      innerLength:input.innerLength,
      sizeClass:input.sizeClass,
      logicalHash:input.logicalHash,
      encodingCommitment:input.encodingCommitment,
      targetId:input.targetId,
      targetContext:input.targetContext,
      readTargetContext:input.readTargetContext,
      prepared:input.prepared,
      readCapability:input.prepared.readCap
    }
  });
  vault.captured.prepared.set(relayId,{
    requestCommitment:hex(input.prepared.requestCommitment),
    declaredBlobHash:hex(input.prepared.request.declaredBlobHash),
    requestSha256:await sha256hex(input.prepared.requestBytes),
    requestBytes:input.prepared.requestBytes.byteLength,
    storageSlot:hex(input.prepared.readCap.storageSlot),
    expectedCellBlobHash:hex(input.prepared.readCap.expectedCellBlobHash),
    sizeClass:input.prepared.readCap.sizeClass
  });
  log('vault: persisted prepared CELL.PUT replica for '+relayId+' (commitment '+hex(input.prepared.requestCommitment).slice(0,16)+'…)');
}
async function persistVerifiedResult(input){
  const key=vaultKey(input.intentId,input.targetId);
  const entry=vault.entries.get(key);
  if(!entry)throw new Error('verified result without a persisted prepared replica');
  const relayId=relayIdForPublicKey(input.targetContext.relayPublicKey);
  const resultHash=await sha256hex(input.resultBytes);
  const evidenceRef='blind-cell-put:'+resultHash;
  entry.stage='verified';
  entry.revision=2;
  entry.evidenceRef=evidenceRef;
  entry.payload.stage=2;
  entry.payload.resultBytes=input.resultBytes;
  vault.captured.results.set(relayId,{resultBytes:hex(input.resultBytes),resultSha256:resultHash,evidenceRef});
  log('vault: '+relayId+' CELL.PUT receipt verified by the vendored control (evidence '+evidenceRef.slice(0,40)+'…)');
  return {evidenceRef,revision:2};
}
async function persistVerifiedReadback(input){
  const key=vaultKey(input.intentId,input.targetId);
  const entry=vault.entries.get(key);
  if(!entry)throw new Error('verified readback without a persisted prepared replica');
  const relayId=relayIdForPublicKey(input.targetContext.relayPublicKey);
  const evidenceRef='blind-cell-get:'+hex(input.readbackRequestCommitment);
  entry.stage='readback-verified';
  entry.revision=3;
  entry.evidenceRef=evidenceRef;
  entry.payload.stage=3;
  entry.payload.readbackResultBytes=input.readbackResultBytes;
  entry.payload.readbackRequestCommitment=input.readbackRequestCommitment;
  entry.payload.readbackInnerBytes=input.readbackInnerBytes;
  vault.captured.readbacks.set(relayId,{
    readbackSha256:await sha256hex(input.readbackInnerBytes),
    readbackBytes:input.readbackInnerBytes.byteLength,
    readbackRequestCommitment:hex(input.readbackRequestCommitment),
    evidenceRef,
    innerBytes:hex(input.readbackInnerBytes)
  });
  log('vault: '+relayId+' CELL.GET readback verified ('+input.readbackInnerBytes.byteLength+' opened bytes, evidence '+evidenceRef.slice(0,40)+'…)');
  return {evidenceRef,revision:3};
}
async function loadPersistedReplica(intentId,targetId){
  const entry=vault.entries.get(vaultKey(intentId,targetId));
  if(!entry)return null;
  return {stage:entry.stage,revision:entry.revision,evidenceRef:entry.evidenceRef,payload:entry.payload};
}

// --------------------------------------------------------------------------
// Phase: qualify — BOTH live relays through the GENUINE seam. Per relay:
// fresh descriptor head (anchor-checked), full chain walk to the signed
// genesis, descriptor-driven admission parameters, then
// qualifyPermissionlessRelayCandidates with the pow-issuance factory.
// --------------------------------------------------------------------------
setPhase('qualify');
const qualified=[];

async function qualifyOneRelay(relay){
  const canonicalUrlBytes=encoder.encode(relay.canonicalDescribeUrl);
  const continuityRoot=fromHex(relay.continuityRootRelayPublicKey);
  // 1. fresh descriptor head (unpinned read) — validate it against the signed
  //    seed anchors before pinning anything.
  const headDescriptor=await withRetry(relay.relayId+' head',()=>cellGet.fetchDescriptorHead({
    canonicalUrl:canonicalUrlBytes,timeoutMillis:15000
  }));
  const head=cellGet.descriptorLinkage(headDescriptor);
  if(hex(head.storeId)!==relay.storeId||
     hex(head.relayPublicKey)!==relay.continuityRootRelayPublicKey||
     head.descriptorSequence<BigInt(relay.minimumDescriptorSequence)){
    throw new Error(relay.relayId+' descriptor head is outside the signed seed anchors');
  }
  const headHash=hex(head.descriptorHash);
  log(relay.relayId+': descriptor head seq '+head.descriptorSequence+' ('+headHash.slice(0,16)+'…) anchors ok; walking chain to signed genesis');
  // 2. chain walk to the signed genesis through the write control's verified
  //    bootstrap client (every link signature-verified on accept below).
  const bootstrapClient=new control.BlindDescriptorBootstrapHttpClient({runtime,fetch:tracedFetch});
  const trustBackend=new control.MemoryDescriptorTrustBackend();
  const trustStore=new control.DescriptorTrustStore(trustBackend);
  const chain=[];
  let currentHash=head.descriptorHash;
  for(let depth=0;depth<4096;depth++){
    const descriptor=await withRetry(relay.relayId+' descriptor seq-'+(Number(head.descriptorSequence)-chain.length),()=>bootstrapClient.fetchVerifiedDescriptor({
      canonicalUrl:canonicalUrlBytes,
      expectedDescriptorHash:currentHash,
      continuityRootRelayPublicKey:continuityRoot,
      nowEpoch:nowEpoch(),
      history:true,
      supportedProtocolProfiles:putProfile.supportedProtocolProfiles,
      supportedTransportProfiles:putProfile.supportedTransportProfiles
    }));
    const link=control.verifiedDescriptorLinkage(descriptor);
    chain.unshift({descriptor,link});
    if(link.descriptorSequence===0n)break;
    if(!link.previousDescriptorHash)throw new Error(relay.relayId+' descriptor chain broke before genesis');
    currentHash=link.previousDescriptorHash;
  }
  if(chain.length!==Number(head.descriptorSequence)+1||
     hex(chain[0].link.descriptorHash)!==relay.descriptorGenesisHash||
     hex(chain[0].link.relayPublicKey)!==relay.continuityRootRelayPublicKey||
     hex(chain[0].link.storeId)!==relay.storeId){
    throw new Error(relay.relayId+' descriptor chain does not terminate at the signed genesis');
  }
  let trusted=null;
  for(const{descriptor,link}of chain){
    trusted=await trustStore.accept(descriptor,link.descriptorSequence===0n
      ?{pinnedDescriptorHash:link.descriptorHash,continuityRootRelayPublicKey:continuityRoot}
      :{continuityRootRelayPublicKey:continuityRoot});
  }
  const descriptorValidity=control.trustedDescriptorValidity(trusted);
  if(nowEpoch()<descriptorValidity.issuedEpoch||nowEpoch()>=descriptorValidity.expiresEpoch){
    throw new Error(relay.relayId+' descriptor is outside its signed epoch window');
  }
  // 3. descriptor-driven pow-issuance admission parameters (never hardcoded).
  const advertised=control.trustedAdmissionProfile(trusted,PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1);
  if(!advertised||advertised.schemeId!==POW_ISSUANCE_V1_SCHEME_ID||
     advertised.conformanceClass!==1||advertised.roleBits!==49||advertised.parameterUrl!=null){
    throw new Error(relay.relayId+' does not advertise the exact signed pow-issuance admission profile');
  }
  log(relay.relayId+': chain accepted ('+chain.length+' descriptors, genesis '+relay.descriptorGenesisHash.slice(0,12)+
    '…); descriptor-driven admission parameterHash '+hex(advertised.parameterHash).slice(0,16)+'…');
  // 4. the GENUINE seam: health + admission-parameter verification + branded
  //    adapter assembly, with the pow-issuance factory as the provider seam.
  const seamProfile=Object.freeze({
    supportedProtocolProfiles:putProfile.supportedProtocolProfiles,
    supportedTransportProfiles:putProfile.supportedTransportProfiles,
    requirement:putProfile.requirement,
    readRequirement:putProfile.readRequirement,
    describeFamilyId:1,
    admissionParametersOperationId:3,
    admissionProfile:Object.freeze({
      profileId:PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
      schemeId:POW_ISSUANCE_V1_SCHEME_ID,
      conformanceClass:1,
      roleBits:49,
      parameterUrl:null,
      parameterHash:advertised.parameterHash
    })
  });
  const qualification=await qualifyPermissionlessRelayCandidates({
    control,
    blindClient:control,
    cryptoRuntime:runtime,
    nowEpoch,
    monotonicMillis,
    profile:seamProfile,
    candidates:[Object.freeze({
      canonicalUrl:relay.canonicalDescribeUrl,
      expectedDescriptorHash:head.descriptorHash,
      continuityRootRelayPublicKey:continuityRoot,
      descriptorPinned:true,
      sources:Object.freeze(['user'])
    })],
    trustStore,
    descriptorTrustBackend:trustBackend,
    fetch:tracedFetch,
    createAdmissionProvider:factory.createAdmissionProvider,
    persistPreparedReplica,
    persistVerifiedResult,
    persistVerifiedReadback,
    loadPersistedReplica,
    createRelayAdapter(options){
      return createBlindCellRelay({...options,blindClient:control,control,leaseClass:LEASE_CLASS});
    },
    timeoutMillis:15000,
    totalQualificationTimeoutMillis:120000
  });
  if(qualification.failures.length!==0||qualification.adapters.length!==1){
    throw new Error(relay.relayId+' seam qualification failed: '+JSON.stringify(qualification.failures));
  }
  return {
    relay,
    adapter:qualification.adapters[0],
    headHash,
    descriptorSequence:Number(head.descriptorSequence),
    parameterHash:hex(advertised.parameterHash),
    descriptorValidity:{issuedEpoch:descriptorValidity.issuedEpoch,expiresEpoch:descriptorValidity.expiresEpoch},
    leaseExpiresEpoch:qualification.status.leaseExpiresEpoch,
    status:{qualifiedRelayCount:qualification.status.qualifiedRelayCount,admissionParametersVerified:qualification.status.admissionParametersVerified}
  };
}

for(const relay of seed.payload.relays){
  let lastError=null;
  let row=null;
  for(let cycle=1;cycle<=3&&!row;cycle++){
    try{
      row=await withRetry(relay.relayId+' qualify',()=>qualifyOneRelay(relay),{attempts:5,baseMillis:3000});
    }catch(error){
      lastError=error;
      log(relay.relayId+' qualification cycle '+cycle+' failed: '+(error.code||'')+' '+String(error.message).slice(0,140)+
        (cycle<3?'; waiting 60s before re-probing the head':''));
      if(cycle<3)await sleep(60000);
    }
  }
  if(!row)throw Object.assign(lastError||new Error(relay.relayId+' unqualified'),{code:(lastError&&lastError.code)||'PEERIT_RELAY_QUALIFICATION_FAILED'});
  qualified.push(row);
  transcript.relays.push({
    relayId:relay.relayId,
    canonicalDescribeUrl:relay.canonicalDescribeUrl,
    descriptorHeadHash:row.headHash,
    descriptorSequence:row.descriptorSequence,
    parameterHash:row.parameterHash,
    parameterHashSource:'current signature-verified descriptor (descriptor-driven)',
    descriptorValidity:row.descriptorValidity,
    leaseExpiresEpoch:row.leaseExpiresEpoch,
    seam:row.status
  });
  log(relay.relayId+': QUALIFIED through the genuine seam (head '+row.headHash.slice(0,12)+'…, descriptor seq '+row.descriptorSequence+', lease epoch ≤'+row.leaseExpiresEpoch+')');
}
if(qualified.length!==2)throw new Error('the drill requires BOTH live relays qualified');

const adapterByRelayId=new Map(qualified.map(row=>[row.relay.relayId,row.adapter]));

if(UNTIL!=='qualify'){

// --------------------------------------------------------------------------
// Phase: parent — read the designated r/hiverelay seed post back through the
// qualified adapter's genuine capability-bound CELL.GET path, verify it
// through the tag-334 operation authority, and stage it into the genuine
// local stack so Data.addComment can thread against it.
// --------------------------------------------------------------------------
setPhase('parent');
let parentOpened=null;
let parentReadRelayId=null;
for(const relayId of['dal-1','syd-1']){
  const replica=parentRecord.replicas.find(row=>row.relayId===relayId);
  const adapter=adapterByRelayId.get(relayId);
  if(!replica||!adapter)continue;
  try{
    parentOpened=await withRetry(relayId+' parent read',()=>adapter.readCellCapability({
      relayId,
      targetId:replica.targetId,
      readCapability:decodePeeritSeedReadCapabilityV1(replica.readCapability),
      innerLength:parentRecord.innerLength,
      sizeClass:parentRecord.sizeClass
    }),{attempts:5,baseMillis:2000});
    parentReadRelayId=relayId;
    break;
  }catch(error){
    log(relayId+' parent read failed: '+(error.code||'')+' '+String(error.message).slice(0,120));
  }
}
if(!parentOpened)throw new Error('neither qualified relay returned the designated parent cell');
const parentEnvelope=await decodePeeritInnerOperationBatchV1(
  parentRecord.innerCodec,parentOpened.innerBytes,{expectedAuthorPublicKey:parentRecord.authorPublicKey});
if(parentEnvelope.operations.length!==1)throw new Error('parent cell is not a single-operation envelope');
const parentStored=parentEnvelope.operations[0].data;
const parentLogical={...(await unseal(parentStored.sealed)),author:parentStored._k,createdAt:parentStored.createdAt,editedAt:parentStored.editedAt,deleted:parentStored.deleted};
if(parentStored._t!=='post'||parentLogical.community!==PARENT.community||parentLogical.cid!==PARENT.cid||
   parentLogical.contentNonce!==PARENT.contentNonce||
   !(await hasValidContentId(TYPE.POST,parentLogical))){
  throw new Error('the served parent cell does not reproduce the designated r/hiverelay protocol-v3 post');
}
if(hex(parentEnvelope.logicalHash)!==parentRecord.logicalHash||
   Number(parentEnvelope.innerLength)!==parentRecord.innerLength){
  throw new Error('parent envelope does not match its signed bootstrap identity');
}
transcript.parent.readFrom=parentReadRelayId;
transcript.parent.evidenceRef=parentOpened.evidenceRef;
transcript.parent.verified='tag-334 operation authority + unsealed protocol-v3 post identity re-derived';
log('parent: r/'+PARENT.community+' post '+PARENT.cid.slice(0,12)+'… read back from '+parentReadRelayId+
  ' and verified (author '+PARENT.author.slice(0,12)+'…, nonce '+PARENT.contentNonce+')');

if(UNTIL!=='parent'){

// --------------------------------------------------------------------------
// Phase: author — the app's genuine construction path. PeeritLocalIdentityV1
// + PeeritProductRuntimeV1 (Data over PeeritSubstrateSync on a memory journal,
// all in-memory/throwaway): durable-writer activation, v2 seal, okey binding,
// REAL 14-bit in-record comment PoW, Ed25519 signature, genuine append.
// --------------------------------------------------------------------------
setPhase('author');
const identity=createPeeritLocalIdentityV1();
const journal=createMemoryPeeritJournal();
const sync=createPeeritSubstrateSync({
  journal,
  relays:[],
  relayHints:[],
  requireVerifiedRelayAdapters:true,
  autoFlush:false
});
const memStorage=(()=>{const m=new Map();return{getItem:k=>(m.has(k)?m.get(k):null),setItem:(k,v)=>m.set(k,String(v)),removeItem:k=>m.delete(k)};})();
const productRuntime=createPeeritProductRuntimeV1({
  storage:memStorage,
  sync,
  identity,
  identityStore:createIdentityStore({kv:memoryKv()})
});
await productRuntime.ready();
// Stage the verified parent post into the local view through the genuine
// append path (full operation-authority validation). It queues as a local
// intent on a throwaway memory journal with zero relays and autoFlush off, so
// it never produces network work; the drill's own CELL.PUT below carries only
// the authored comment.
await sync.append({type:'v2',data:parentStored});

const runStamp=new Date().toISOString();
const body=MARKER+'\\n\\nDeclared drill record of the Peerit T2 CELL.PUT live write drill '+
  '(scripts/browser-peerit-t2-cell-put-live-drill.mjs). Authored '+runStamp+' by an ephemeral drill identity; '+
  'one 2-slot pow-issuance-v1 token admits this single comment to both launch relays. '+
  'Not community content; it expires with its ≤7d cell lease (leaseClass '+LEASE_CLASS+').';
const commentLogical=await productRuntime.data.addComment({
  community:PARENT.community,
  postCid:PARENT.cid,
  parentCid:null,
  body,
  onProgress:nonce=>log('comment PoW progress: '+nonce+' candidates')
});
const me=identity.me();
if(!me.pubkey||commentLogical.author!==me.pubkey)throw new Error('drill identity did not author the comment');

const wireKey=await expectedKeyV2({...commentLogical,_t:TYPE.COMMENT});
const storedComment=await sync.get(wireKey);
if(!storedComment||storedComment._k!==me.pubkey||storedComment._t!==TYPE.COMMENT){
  throw new Error('authored comment is not materialized under its okey in the local view');
}
if(!storedComment.pow||storedComment.pow.bits<MIN_BITS.comment){
  throw new Error('comment record lacks its genuine 14-bit in-record proof');
}
log('author: comment '+commentLogical.cid.slice(0,12)+'… constructed by the genuine Data.addComment path '+
  '(in-record PoW '+storedComment.pow.bits+' bits at nonce '+storedComment.pow.nonce+', author '+me.pubkey.slice(0,12)+'…)');

const envelope=await createPeeritInnerOperationBatchV1(
  [{type:'v2',data:storedComment}],{expectedAuthorPublicKey:me.pubkey});
const innerBytes=new Uint8Array(envelope.innerBytes);
const publication={
  intentId:hex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec,innerBytes)),
  logicalId:hex(envelope.logicalHash),
  innerCodec:envelope.innerCodec,
  innerBytes,
  innerLength:Number(envelope.innerLength),
  sizeClass:envelope.sizeClass,
  logicalHash:new Uint8Array(envelope.logicalHash),
  encodingCommitment:new Uint8Array(envelope.encodingCommitment),
  authorPublicKey:envelope.authorPublicKey,
  wireKeys:[...envelope.operationWireKeys].sort()
};
// Round-trip: the sealed envelope decodes to the identical signed record.
const roundTrip=await decodePeeritInnerOperationBatchV1(
  publication.innerCodec,publication.innerBytes,{expectedAuthorPublicKey:me.pubkey});
if(hex(roundTrip.logicalHash)!==publication.logicalId)throw new Error('authored envelope failed its own round-trip');
if(publication.sizeClass!==1)throw new Error('drill comment must stay a sizeClass-1 cell');
transcript.record={
  cid:commentLogical.cid,
  intentId:publication.intentId,
  logicalHash:publication.logicalId,
  encodingCommitment:hex(publication.encodingCommitment),
  innerCodec:publication.innerCodec,
  innerLength:publication.innerLength,
  sizeClass:publication.sizeClass,
  leaseClass:LEASE_CLASS,
  wireKeys:publication.wireKeys,
  author:me.pubkey,
  contentNonce:commentLogical.contentNonce,
  createdAt:commentLogical.createdAt,
  commentPow:{bits:storedComment.pow.bits,nonce:storedComment.pow.nonce,targetHash:storedComment.pow.targetHash,v:storedComment.pow.v},
  board:PARENT.community,
  parentCid:PARENT.cid,
  body,
  innerBytes:hex(innerBytes)
};
log('author: tag-'+publication.innerCodec+' envelope '+publication.intentId.slice(0,16)+'… ('+publication.innerLength+
  ' bytes, sizeClass '+publication.sizeClass+', leaseClass '+LEASE_CLASS+') passes the operation authority round-trip');

if(UNTIL!=='author'){

// --------------------------------------------------------------------------
// Phase: write — ONE record session, ONE 2-slot token, ONE CELL.PUT per
// relay, verified receipts, byte-exact readback on BOTH relays.
// --------------------------------------------------------------------------
setPhase('write');
const recordSession=factory.beginRecord({
  relayPublicKeys:putProfile.relays.map(row=>row.relayPublicKey)
});
if(recordSession.allowance!==2)throw new Error('drill record must span exactly two relay slots');

let minted=null;
const preparedByRelayId=new Map();
try{
  await Promise.all(qualified.map(async row=>{
    const prepared=await row.adapter.prepare(publication);
    preparedByRelayId.set(row.relay.relayId,prepared);
  }));
  minted=await recordSession.complete;
}catch(error){
  factory.closeOpenRecord();
  throw error;
}
const redeemRequests=requests.filter(row=>row.path==='/redeem');
const challengeRequests=requests.filter(row=>row.path==='/challenge');
// ONE token per record is the invariant. A challenge that outlives the mint is
// a liveness event (never a verification failure): the provider restarts from
// a FRESH challenge, bounded at 3 attempts — so extra challenge/redeem traffic
// is lawful only as HTTP-400 expiry-class failures ahead of the one 200.
const successfulRedeems=redeemRequests.filter(row=>row.status===200);
const failedRedeems=redeemRequests.filter(row=>row.status!==200);
if(successfulRedeems.length!==1)throw new Error('exactly ONE successful /redeem (one token) may occur per drill record (saw '+successfulRedeems.length+')');
if(failedRedeems.some(row=>row.status!==400))throw new Error('a failed /redeem was not the issuer expiry class');
if(redeemRequests.length>3)throw new Error('pow-issuance challenge-expiry retries exceeded the bounded budget (saw '+redeemRequests.length+')');
if(challengeRequests.length!==redeemRequests.length)throw new Error('every /redeem must follow a fresh /challenge');
const redeemed200=successfulRedeems[0];
const slotOf=relayId=>recordSession.slotIndexOf(fromHex(relayKeyHexByRelayId.get(relayId)));
transcript.token={
  issuerOrigin:new URL(redeemed200.url).origin,
  challengeReceivedAt:new Date(challengeRequests[challengeRequests.length-1].at).toISOString(),
  redeemCompletedAt:new Date(redeemed200.at).toISOString(),
  difficultyBits:minted.difficultyBits,
  mintMillis:minted.mintMillis,
  attempts:String(minted.attempts),
  nonce:String(minted.nonce),
  allowance:minted.allowance,
  expiryEpoch:minted.expiryEpoch,
  recordCommitment:hex(minted.recordCommitment),
  redeemCalls:redeemRequests.length,
  challengeCalls:challengeRequests.length,
  expiryRetries:minted.expiryRetries,
  slotOrder:['dal-1','syd-1'].map(relayId=>slotOf(relayId)).join(',')
};
log('write: ONE '+minted.difficultyBits+'-bit PoW minted in '+minted.mintMillis+'ms ('+minted.attempts+
  ' attempts) → ONE '+minted.allowance+'-slot token (expiryEpoch '+minted.expiryEpoch+
  '); /challenge ×'+challengeRequests.length+' + /redeem ×'+redeemRequests.length+' on '+new URL(redeemed200.url).origin+
  (minted.expiryRetries?' ('+minted.expiryRetries+' challenge-expiry restart'+(minted.expiryRetries===1?'':'s')+', fresh challenge)':'')+
  ' (slot 0 = syd-1, slot 1 = dal-1)');

async function sendWithRecovery(row){
  const prepared=preparedByRelayId.get(row.relay.relayId);
  for(let attempt=1;attempt<=5;attempt++){
    try{
      const result=await row.adapter.send({...publication,prepared});
      if(!result||result.ok!==true||result.readbackVerified!==true){
        throw new Error(row.relay.relayId+' CELL.PUT lacks verified readback');
      }
      return result;
    }catch(error){
      const safeToRetry=error&&(error.safeToRetry===true||error.code==='RETRYABLE_NOT_SENT'||isTransient(error));
      const remote=error&&error.remote?' remote='+JSON.stringify(error.remote).slice(0,240):'';
      log('write: '+row.relay.relayId+' send attempt '+attempt+'/5: '+(error.code||'')+' '+String(error.message).slice(0,120)+remote);
      if(!safeToRetry||attempt===5){
        // Ambiguous outcome: the ONLY automatic recovery is the genuine
        // GET-only reconcile — a PUT is never re-sent after ambiguity.
        const reconciled=await row.adapter.reconcile({...publication});
        if(!reconciled||reconciled.ok!==true||reconciled.readbackVerified!==true){
          throw new Error(row.relay.relayId+' could not reconcile the CELL.PUT outcome');
        }
        return reconciled;
      }
      await sleep(Math.min(5000*(2**(attempt-1)), 90000));
    }
  }
}
for(const row of qualified){
  const result=await sendWithRecovery(row);
  const relayId=row.relay.relayId;
  const captured=vault.captured.results.get(relayId);
  const readback=vault.captured.readbacks.get(relayId);
  if(!captured||!readback)throw new Error(relayId+' missed its verified receipt/readback capture');
  if(!bytesEqual(fromHex(readback.innerBytes),publication.innerBytes)){
    throw new Error(relayId+' readback does not open to the exact authored record bytes');
  }
  const preparedCapture=vault.captured.prepared.get(relayId);
  transcript.relays.find(value=>value.relayId===relayId).write={
    slotIndex:slotOf(relayId),
    requestCommitment:preparedCapture.requestCommitment,
    declaredBlobHash:preparedCapture.declaredBlobHash,
    putRequestSha256:preparedCapture.requestSha256,
    receiptEvidenceRef:captured.evidenceRef,
    receiptBytes:captured.resultBytes,
    receiptVerifiedPageSide:'vendored control verifyOperationResult (endpoint binding + receipt signature)',
    readbackEvidenceRef:readback.evidenceRef,
    readbackSha256:readback.readbackSha256,
    readbackInnerBytes:readback.innerBytes,
    readbackByteExact:true,
    deliveryEvidenceRef:result.evidenceRef
  };
  log('write: '+relayId+' CELL.PUT accepted (slot '+slotOf(relayId)+
    ', receipt verified) → byte-exact CELL.GET readback ('+readback.readbackBytes+' opened bytes == authored record)');
}
recordSession.close();
transcript.token.recordSessionClosed=true;

// --------------------------------------------------------------------------
// Phase: render — the readback record through the app's ingest checks and its
// genuine render pipeline; the marker must reach the DOM as a visible comment.
// --------------------------------------------------------------------------
setPhase('render');
for(const relayId of['dal-1','syd-1']){
  const readback=vault.captured.readbacks.get(relayId);
  const decoded=await decodePeeritInnerOperationBatchV1(
    publication.innerCodec,fromHex(readback.innerBytes),{expectedAuthorPublicKey:me.pubkey});
  const stored=decoded.operations[0].data;
  // The exact non-legacy checks js/pow.js makeValidator runs for a comment,
  // composed from the closure's genuine modules (makeValidator's legacy
  // allowlists cannot match a freshly signed record).
  const logical={...(await unseal(stored.sealed)),author:stored._k,createdAt:stored.createdAt,editedAt:stored.editedAt,deleted:stored.deleted};
  if(stored._t!==TYPE.COMMENT||!(await hasValidContentId(TYPE.COMMENT,logical))){
    throw new Error(relayId+' readback comment fails content-id re-derivation');
  }
  if(!validCommunitySlug(logical.community)||logical.postCid!==logical.targetRef?.cid||
     !(await hasValidContentRef(logical.targetRef,TYPE.POST))||
     logical.parentCid!==null||logical.parentRef!==null){
    throw new Error(relayId+' readback comment fails target binding');
  }
  if(!(await verifyPow(TYPE.COMMENT,stored,MIN_BITS.comment))){
    throw new Error(relayId+' readback comment fails its 14-bit in-record PoW');
  }
  log('render: '+relayId+' readback record passes the ingest verifier (signature, content-id, target binding, 14-bit PoW)');
}
// The local view already holds the parent post + the authored comment via the
// genuine append path; the relay-served bytes are byte-identical to what was
// appended (asserted above), so rendering the local view renders the record
// both relays now serve.
const ui=mountPeeritProductUiV1(productRuntime,{document,window});
location.hash='#/r/'+PARENT.community+'/post/'+PARENT.cid;
await ui.render();
await ui.render();
const commentNode=document.querySelector('article.comment[data-comment="'+commentLogical.cid+'"]');
const markerInDom=document.body.textContent.includes(MARKER);
if(!commentNode||!markerInDom){
  throw new Error('the drill comment does not render in the page DOM');
}
if(commentNode.textContent.includes('Collapsed')||commentNode.textContent.includes('Buried')){
  throw new Error('the drill comment renders as moderated away, not visible');
}
transcript.render={
  engine:'mountPeeritProductUiV1 + preparePeeritCommentsForRenderV1 over genuine Data/PeeritSubstrateSync (memory journal)',
  commentCid:commentLogical.cid,
  markerInDom:true,
  visibleComments:document.querySelectorAll('article.comment').length,
  route:location.hash,
  fullAppBoot:false,
  note:'Harness page with the app’s real render modules (accepted by the milestone); a full app boot would add the 39-record recovery soak and the production write install seam, which stays release-blocked by design.'
};
log('render: comment renders as a visible comment under r/'+PARENT.community+' post '+PARENT.cid.slice(0,12)+
  '… with the exact marker text ('+transcript.render.visibleComments+' comment node(s) in DOM)');

setPhase('done');
}}}}

// --------------------------------------------------------------------------
// Final page-side assertions: traced routes, no INBOX, no violations.
// --------------------------------------------------------------------------
transcript.wallTimeMillis=elapsed();
transcript.assertions.externalOrigins=[...new Set(requests.map(row=>row.origin))];
transcript.assertions.paths=[...new Set(requests.map(row=>row.path))];
transcript.assertions.inboxRequests=requests.filter(row=>/inbox/i.test(row.url)).length;
transcript.assertions.redeemCalls=requests.filter(row=>row.path==='/redeem').length;
transcript.assertions.challengeCalls=requests.filter(row=>row.path==='/challenge').length;
transcript.assertions.cspViolations=violations.length;
transcript.assertions.completedThrough=UNTIL==='full'?'render':UNTIL;
transcript.csp={
  deviation:'connect-src extended by exactly the two pow-issuance issuer origins (:8443) the signed Cell-PUT profile pins; every other directive byte is the production CSP',
  reason:'the production seq-28 connect-src allows the relay origins but not the distinct :8443 issuer origins; a local proxy was rejected because it would change the page-side URL the spend provider fetches',
  issuerOrigins:['https://relay-syd.p2phiverelay.xyz:8443','https://relay-dal.p2phiverelay.xyz:8443']
};
if(UNTIL!=='full')setPhase('done');
return transcript;
}

run().then(value=>{
  globalThis.__peeritT2Result={ok:true,until:UNTIL,phase,transcript:value};
}).catch(error=>{
  log('FATAL in phase '+phase+': '+(error.code||'')+' '+String(error.message||error).slice(0,200));
  transcript.wallTimeMillis=elapsed();
  globalThis.__peeritT2Fatal={ok:false,until:UNTIL,phase,fatal:cleanError(error),requests,violations,transcript};
});
`.trim()
}

// ---------------------------------------------------------------------------
// Node-side harness: serve the signed closure, drive Chromium, verify the
// receipts a second time against the reference codec, emit the transcript.
// ---------------------------------------------------------------------------
const out = argument('--out', '/tmp/peerit-seq28-live-write-drill.json')
const untilPhase = String(argument('--until', 'full'))
if (!UNTIL_PHASES.has(untilPhase)) fail(`--until must be one of ${[...UNTIL_PHASES].join(', ')}`)
const candidate = path.resolve(ROOT, argument('--candidate', 'web'))

const indexBytes = await readFile(path.join(candidate, 'index.html'))
const indexHtml = indexBytes.toString('utf8')
const sequenceMatch = /<meta\s+[^>]*name=["']peerit-release-sequence["'][^>]*content=["'](\d+)["']/i.exec(indexHtml)
if (!sequenceMatch || Number(sequenceMatch[1]) !== RELEASE_SEQUENCE) {
  fail(`candidate index is not release sequence ${RELEASE_SEQUENCE}`)
}
const headerPolicyBytes = await readFile(path.join(ROOT, 'deploy/render-security-headers.json'))
const headerPolicySha256 = sha256(headerPolicyBytes)
const headers = JSON.parse(headerPolicyBytes.toString('utf8'))
const cspRows = (headers.headers || []).filter(row => row.name === 'Content-Security-Policy')
if (cspRows.length !== 1 || cspRows[0].value !== EXPECTED_CSP) {
  fail('production CSP bytes drifted from the expected seq-28 policy')
}
if (/\b(?:wasm-unsafe-eval|unsafe-eval)\b/.test(EXPECTED_CSP)) {
  fail('production CSP unexpectedly permits dynamic evaluation')
}
log(`candidate: ${candidate} (seq ${RELEASE_SEQUENCE}); header policy sha256 ${headerPolicySha256.slice(0, 16)}…`)
log(`CSP deviation: connect-src += ${ISSUER_ORIGINS.join(' + ')} (the signed profile's issuer origins); all other directive bytes are production`)

const harness = Buffer.from('<!doctype html><html><head><meta charset="utf-8">' +
  '<title>peerit T2 CELL.PUT live write drill</title>' +
  '<script type="module" src="/__peerit_t2_drill__.mjs"></script></head><body></body></html>')
const controller = Buffer.from(controllerSource({ untilPhase }))

const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname)
    if (pathname === '/') return send(response, 200, 'text/html; charset=utf-8', harness)
    if (pathname === '/__peerit_t2_drill__.mjs') {
      return send(response, 200, 'text/javascript; charset=utf-8', controller)
    }
    const file = path.resolve(candidate, `.${pathname}`)
    if (file !== candidate && !file.startsWith(`${candidate}${path.sep}`)) {
      return send(response, 403, 'text/plain; charset=utf-8', 'forbidden')
    }
    const bytes = await readFile(file)
    send(response, 200, contentType(file), bytes)
  } catch (error) {
    const status = error && error.code === 'ENOENT' ? 404 : 500
    send(response, status, 'text/plain; charset=utf-8', status === 404 ? 'not found' : 'server error')
  }
})
await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})

const watchdog = setTimeout(() => {
  console.error('    [t2-live-drill] WATCHDOG: drill exceeded its bounded deadline')
  process.exit(1)
}, 1_800_000)
watchdog.unref()

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PEERIT_GATE_CHROMIUM_EXECUTABLE || undefined
})
const context = await browser.newContext({ serviceWorkers: 'block' })

// Fleet finding surfaced by this drill's first write attempt: the pow-issuance
// issuer origins (:8443) answer WITHOUT CORS headers, while both relay edges
// emit `Access-Control-Allow-Origin: *` (verified live). A real browser page
// cannot read issuer responses until the issuer matches the edges' posture —
// the production browser write path needs exactly that fleet change. To let
// the proof run anyway, the drill emulates ONLY that header posture at the
// browser boundary: Playwright route interception forwards every issuer call
// to the genuine :8443 origin (route.fetch) and appends
// `Access-Control-Allow-Origin: *` to the issuer's own response, plus a local
// 204 preflight answer for the JSON POST. Page-side code, issuer URLs, methods
// and payloads remain byte-identical to production; no check is weakened. The
// interception counters are asserted against the page-side request trace.
const issuerIntercept = { challenge: 0, redeem: 0, preflight: 0, other: 0 }
for (const origin of ISSUER_ORIGINS) {
  await context.route(`${origin}/**`, async route => {
    const request = route.request()
    if (request.method() === 'OPTIONS') {
      issuerIntercept.preflight++
      await route.fulfill({
        status: 204,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type',
          'access-control-max-age': '600'
        }
      })
      return
    }
    const pathname = new URL(request.url()).pathname
    if (pathname === '/challenge') issuerIntercept.challenge++
    else if (pathname === '/redeem') issuerIntercept.redeem++
    else issuerIntercept.other++
    const response = await route.fetch()
    await route.fulfill({
      response,
      headers: { ...response.headers(), 'access-control-allow-origin': '*' }
    })
  })
}

const page = await context.newPage()
const pageErrors = []
const consoleErrors = []
page.on('pageerror', error => pageErrors.push({ name: error.name, message: error.message }))
page.on('console', message => {
  const text = message.text()
  if (text.startsWith('[t2-live-drill]')) console.log(`    ${text}`)
  else if (message.type() === 'error') consoleErrors.push(text)
})

let result = null
let fatal = null
try {
  await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load', timeout: 60000 })
  await page.waitForFunction(() => globalThis.__peeritT2Result != null || globalThis.__peeritT2Fatal != null,
    null, { timeout: 1_200_000 })
  result = await page.evaluate(() => globalThis.__peeritT2Result || null)
  fatal = await page.evaluate(() => globalThis.__peeritT2Fatal || null)
} finally {
  await page.close().catch(() => {})
  await context.close().catch(() => {})
  await browser.close().catch(() => {})
  await new Promise(resolve => server.close(resolve))
  clearTimeout(watchdog)
}

async function dumpPartial (payload) {
  const partial = payload && payload.transcript && typeof payload.transcript === 'object'
    ? payload.transcript
    : { schema: 'peerit-t2-cell-put-live-drill-v1' }
  partial.verdict = 'FAIL'
  partial.phase = payload && payload.phase
  partial.fatal = payload && payload.fatal
  partial.pageErrors = pageErrors
  partial.consoleErrors = consoleErrors
  await writeFile(out, `${JSON.stringify(partial, null, 2)}\n`).catch(() => {})
}

if (fatal) {
  console.error(`    [t2-live-drill] page fatal in phase ${fatal.phase}: ${JSON.stringify(fatal.fatal)}`)
  await dumpPartial(fatal)
  console.error(`    [t2-live-drill] partial transcript written: ${out}`)
  process.exitCode = 1
} else if (!result || result.ok !== true) {
  console.error('    [t2-live-drill] drill produced no result')
  await dumpPartial(null)
  process.exitCode = 1
} else {
  const transcript = result.transcript
  let passed = false
  try {
    assert.deepEqual(pageErrors, [], `page errors: ${JSON.stringify(pageErrors)}`)
    assert.equal(consoleErrors.some(value => /content security policy|refused to|wasm/i.test(value)), false,
      `browser emitted a CSP/runtime console error: ${JSON.stringify(consoleErrors)}`)
    assert.deepEqual(transcript.violations, [], `CSP violations: ${JSON.stringify(transcript.violations)}`)

    // Route/origin assertions — no INBOX, nothing undeclared.
    assert.equal(transcript.assertions.inboxRequests, 0, 'an INBOX request was traced')
    for (const origin of transcript.assertions.externalOrigins) {
      assert.ok([
        'https://relay-syd.p2phiverelay.xyz',
        'https://relay-dal.p2phiverelay.xyz',
        ...ISSUER_ORIGINS
      ].includes(origin), `undeclared origin ${origin}`)
    }
    for (const requestPath of transcript.assertions.paths) {
      assert.ok(['/api/blind/v1/describe', '/api/blind/v1/cell', '/challenge', '/redeem'].includes(requestPath),
        `undeclared route ${requestPath}`)
    }
    assert.equal(transcript.requests.some(row => row.status === 401 || row.status === 403), false,
      'a relay refused an operation')

    if (untilPhase === 'full') {
      // Token discipline: ONE token per record. Challenge-expiry restarts are
      // liveness events (bounded 3, fresh challenge, 400 expiry-class only).
      const redeemsTraced = transcript.requests.filter(row => row.path === '/redeem')
      assert.equal(redeemsTraced.filter(row => row.status === 200).length, 1,
        'exactly one successful /redeem (one token) may be traced')
      assert.equal(redeemsTraced.some(row => row.status !== 200 && row.status !== 400), false,
        'a failed /redeem was not the issuer expiry class')
      assert.ok(transcript.assertions.redeemCalls <= 3,
        'pow-issuance challenge-expiry retries exceeded the bounded budget')
      assert.equal(transcript.assertions.challengeCalls, transcript.assertions.redeemCalls,
        'every /redeem must follow a fresh /challenge')
      assert.equal(issuerIntercept.challenge, transcript.assertions.challengeCalls,
        'the CORS boundary must forward exactly the traced challenge calls')
      assert.equal(issuerIntercept.redeem, transcript.assertions.redeemCalls,
        'the CORS boundary must forward exactly the traced redeem calls')
      assert.equal(issuerIntercept.other, 0, 'an undeclared issuer route was intercepted')
      assert.equal(transcript.token.allowance, 2)
      assert.equal(transcript.token.redeemCalls, transcript.assertions.redeemCalls)
      assert.ok(transcript.token.mintMillis > 0, 'the 20-bit mint must have taken measurable time')

      // Reference-codec receipt verification (second, independent check).
      for (const relay of transcript.relays) {
        const write = relay.write
        assert.ok(write, `${relay.relayId} has no write evidence`)
        const receiptBytes = Buffer.from(write.receiptBytes, 'hex')
        const value = decodeCanonical(blindReceiptV1, receiptBytes, { copyBytes: true })
        const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - sodium.crypto_sign_BYTES)
        const relayPublicKey = transcript.authority.putProfile.relays
          .find(row => row.relayId === relay.relayId).relayPublicKey
        const valid = sodium.crypto_sign_verify_detached(
          value.signature,
          resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, unsigned),
          Buffer.from(relayPublicKey, 'hex'))
        assert.equal(valid, true, `${relay.relayId} receipt signature is invalid under the relay public key`)
        assert.equal(value.result, CELL_RECEIPT_RESULT.STORED, `${relay.relayId} receipt is not STORED`)
        assert.equal(value.sizeClass, transcript.record.sizeClass)
        assert.equal(value.leaseClass, LEASE_CLASS, `${relay.relayId} receipt leaseClass drifted`)
        const leaseEpochs = Number(value.leaseEpoch) - Number(value.allocationEpoch)
        assert.ok(leaseEpochs >= 28 && leaseEpochs <= 29,
          `${relay.relayId} lease must be 28 epochs (leaseClass 2 = 7 days ≤ 30d; saw ${leaseEpochs})`)
        assert.equal(Buffer.from(value.cellBlobHash).toString('hex'), write.declaredBlobHash,
          `${relay.relayId} receipt blob hash does not match the prepared replica`)
        assert.equal(Buffer.from(value.requestCommitment).toString('hex'), write.requestCommitment,
          `${relay.relayId} receipt does not commit to the exact PUT request`)
        write.receipt = {
          status: 'STORED',
          signatureValid: true,
          verifiedBy: 'reference blind-protocol codec + relay public key (Node), and vendored verifyOperationResult (page)',
          sizeClass: value.sizeClass,
          leaseClass: value.leaseClass,
          allocationEpoch: Number(value.allocationEpoch),
          leaseEpoch: Number(value.leaseEpoch),
          leaseEpochs,
          leaseDays: 7,
          stateRevision: String(value.stateRevision),
          receiptEpoch: Number(value.receiptEpoch)
        }
        assert.equal(write.readbackByteExact, true, `${relay.relayId} readback was not byte-exact`)
        assert.equal(write.readbackInnerBytes, transcript.record.innerBytes,
          `${relay.relayId} readback bytes differ from the authored envelope bytes`)
        assert.equal(sha256(Buffer.from(write.readbackInnerBytes, 'hex')), write.readbackSha256,
          `${relay.relayId} readback hash does not reproduce the served bytes`)
        log(`receipt ${relay.relayId}: STORED, signature valid under relay key, leaseEpoch ${write.receipt.leaseEpoch} (allocation +${leaseEpochs} epochs ≈7d), readback byte-exact`)
      }

      // Independent Node-side ingest check of the exact served bytes.
      const servedBytes = Buffer.from(transcript.record.innerBytes, 'hex')
      const decoded = await decodePeeritInnerOperationBatchV1(
        transcript.record.innerCodec, new Uint8Array(servedBytes),
        { expectedAuthorPublicKey: transcript.record.author })
      const stored = decoded.operations[0].data
      const logical = {
        ...(await unseal(stored.sealed)),
        author: stored._k,
        createdAt: stored.createdAt,
        editedAt: stored.editedAt,
        deleted: stored.deleted
      }
      assert.equal(stored._t, TYPE.COMMENT)
      assert.equal(await hasValidContentId(TYPE.COMMENT, logical), true,
        'Node-side content-id re-derivation failed')
      assert.ok(validCommunitySlug(logical.community) && logical.postCid === logical.targetRef?.cid)
      assert.equal(await hasValidContentRef(logical.targetRef, TYPE.POST), true)
      assert.equal(logical.parentCid, null)
      assert.equal(logical.parentRef, null)
      assert.equal(await verifyPow(TYPE.COMMENT, stored, MIN_BITS.comment), true,
        'Node-side 14-bit in-record PoW verification failed')
      assert.ok(logical.body.includes(MARKER), 'served record body lacks the exact marker')
      assert.equal(logical.community, PARENT.community)
      assert.equal(logical.postCid, PARENT.cid)
      assert.equal(logical.cid, transcript.record.cid)
      log(`node-ingest: served record re-verified (signature, content-id ${transcript.record.cid.slice(0, 16)}…, target r/${PARENT.community}/${PARENT.cid.slice(0, 12)}…, PoW ${stored.pow.bits} bits, marker present)`)

      // PUT envelope discipline: exactly one 64KiB-class CELL.PUT request body
      // per relay in the write phase (the sizeClass-1 request frame class), no
      // re-writes, no INBOX. Each envelope's byte-exactness is bound by the
      // vendored control's requestCommitment-verified receipt above; the
      // 16KiB-class bodies on the same route are the readback/parent CELL.GET
      // requests, each independently proven byte-exact by verified readback.
      const putBodies = transcript.requests.filter(row =>
        row.phase === 'write' && row.path === '/api/blind/v1/cell' && row.method === 'POST' &&
        row.requestBytes === 65536 && row.status === 200)
      assert.equal(putBodies.length, 2, 'exactly two CELL.PUT envelopes (one per relay) may cross in the write phase')
      const putOrigins = [...new Set(putBodies.map(row => row.origin))].sort()
      const relayOrigins = transcript.relays.map(relay => new URL(relay.canonicalDescribeUrl).origin).sort()
      assert.deepEqual(putOrigins, relayOrigins, 'each relay received exactly its own PUT envelope')
      assert.equal(new Set(putBodies.map(row => row.requestSha256)).size, 2,
        'the two PUT envelopes are the two distinct per-relay replicas')

      // Render + marker.
      assert.equal(transcript.render.markerInDom, true, 'marker text did not reach the DOM')
      assert.equal(transcript.render.commentCid, transcript.record.cid)
      assert.equal(transcript.record.sizeClass, 1)
      assert.equal(transcript.record.leaseClass, LEASE_CLASS)
      assert.ok(transcript.record.commentPow.bits >= 14, 'in-record comment PoW must be ≥14 bits')
      assert.ok(transcript.record.body.includes(MARKER), 'record body must contain the exact marker')
      log(`render: marker verified in DOM (comment ${transcript.record.cid.slice(0, 16)}… under r/${transcript.record.board}/${transcript.record.parentCid.slice(0, 16)}…)`)
    }

    transcript.finishedAt = new Date().toISOString()
    transcript.csp.production = EXPECTED_CSP
    transcript.csp.drill = DRILL_CSP
    transcript.csp.headerPolicySha256 = headerPolicySha256
    transcript.issuerCors = {
      finding: 'the pow-issuance issuer origins (:8443) answer without CORS headers, while both relay edges emit Access-Control-Allow-Origin: * (verified live with curl); a real browser page cannot read issuer responses until the issuer matches the edges posture — a fleet change the production browser write path needs',
      emulation: 'Playwright context.route forwards every issuer call to the genuine :8443 origin (route.fetch) and appends Access-Control-Allow-Origin: * to the issuer own response, plus a local 204 preflight answer for the JSON POST; page-side code, issuer URLs, methods and payloads are byte-identical to production',
      intercepted: issuerIntercept
    }
    transcript.pageErrors = pageErrors
    transcript.consoleErrors = consoleErrors
    transcript.verdict = untilPhase === 'full' ? 'PASS' : `PARTIAL (--until ${untilPhase})`
    await writeFile(out, `${JSON.stringify(transcript, null, 2)}\n`)
    log(`transcript written: ${out}`)
    passed = true
  } catch (error) {
    transcript.finishedAt = new Date().toISOString()
    transcript.verdict = 'FAIL'
    transcript.fatal = { message: error.message, stack: String(error.stack || '').split('\n').slice(0, 6) }
    await writeFile(out, `${JSON.stringify(transcript, null, 2)}\n`).catch(() => {})
    console.error(`    [t2-live-drill] FAIL: ${error.message}`)
    console.error(`    [t2-live-drill] partial transcript written: ${out}`)
  }
  if (passed) {
    if (untilPhase === 'full') {
      log(`drill complete: authority → qualify ×2 → parent read → author → ONE token → CELL.PUT ×2 → receipts ×2 → byte-exact readback ×2 → render, in ${transcript.wallTimeMillis}ms wall`)
      console.log('scripts/browser-peerit-t2-cell-put-live-drill.mjs: PASS')
    } else {
      log(`partial run complete through phase '${untilPhase}' (read-only debug mode; no token minted, no CELL.PUT) in ${transcript.wallTimeMillis}ms wall`)
      console.log(`scripts/browser-peerit-t2-cell-put-live-drill.mjs: PARTIAL (--until ${untilPhase}, exit 0, not the full proof)`)
    }
  } else {
    process.exitCode = 1
  }
}
