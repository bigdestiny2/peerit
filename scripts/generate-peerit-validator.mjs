#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { buildPeeritProfileArtifacts } from '../js/substrate/profile-artifact-builder.mjs'
import { createPeeritProfileCodecCatalogFromIr } from '../js/substrate/profile-codec-ir.mjs'
import { createPeeritProfileStructuralFixtureFactory } from '../js/substrate/profile-codec-fixtures.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from '../js/substrate/profile-external-authority.mjs'
import { peeritProfileNamedSortProjection } from '../js/substrate/profile-validator.mjs'
import {
  PEERIT_VALIDATOR_ARTIFACT_PATH,
  PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH,
  encodePeeritValidatorVectorManifestV1,
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from '../js/substrate/validator-artifact.mjs'
import { bytesEqual, bytesToHex } from '../js/substrate/release-control-primitives.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const check = process.argv.includes('--check')
const vectorRoot = 'protocol/validator/vectors'
const bareImportMirrorPath = 'protocol/validator/peerit-validator-v1.bare.mjs'

function externalAuthorities () {
  const wireArtifacts = {
    specBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-v1.md'))),
    abiBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-abi-v1.cenc'))),
    vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')))
  }
  const clientArtifacts = {
    formatAuthorityBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'))),
    vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')))
  }
  const object = {}
  const map = new Map()
  for (const row of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    const authority = authenticatePeeritProfileExternalCodecAuthorityV1({
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (bytes, name) {
        if (!(bytes instanceof Uint8Array) || bytes.byteLength < row.minimumBytes || bytes.byteLength > row.maximumBytes || name !== row.name) {
          throw new Error(`${row.name} fixture authority rejected noncanonical bytes`)
        }
      }
    })
    object[row.name] = authority
    map.set(row.name, authority)
  }
  return { object: Object.freeze(object), map }
}

function base64DecoderSource (base64) {
  return `
const REGISTRY_BASE64=${JSON.stringify(base64)};
function decodeBase64(value){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let valid=value.length;
  while(valid>0&&value[valid-1]==='=')valid--;
  const output=new Uint8Array(Math.floor(valid*6/8));
  let bits=0,bitCount=0,offset=0;
  for(let index=0;index<valid;index++){
    const digit=alphabet.indexOf(value[index]);
    if(digit<0)throw new Error('invalid embedded profile registry base64');
    bits=(bits<<6)|digit;bitCount+=6;
    if(bitCount>=8){bitCount-=8;output[offset++]=(bits>>bitCount)&255;bits&=(1<<bitCount)-1;}
  }
  return output;
  }
`
}

const bareTextCodecBanner = `
if(typeof globalThis.TextEncoder==='undefined')globalThis.TextEncoder=class TextEncoder{
  encode(value=''){const output=[];for(const character of String(value)){const point=character.codePointAt(0);if(point<=127)output.push(point);else if(point<=2047)output.push(192|(point>>6),128|(point&63));else if(point<=65535)output.push(224|(point>>12),128|((point>>6)&63),128|(point&63));else output.push(240|(point>>18),128|((point>>12)&63),128|((point>>6)&63),128|(point&63));}return Uint8Array.from(output)}
};
if(typeof globalThis.TextDecoder==='undefined')globalThis.TextDecoder=class TextDecoder{
  constructor(label='utf-8',options={}){if(String(label).toLowerCase()!=='utf-8')throw new RangeError('only utf-8 is supported');this.fatal=!!options.fatal}
  decode(input=new Uint8Array()){const bytes=input instanceof Uint8Array?input:new Uint8Array(input);let output='';for(let index=0;index<bytes.length;){const first=bytes[index++];let point,count,minimum;if(first<=127){point=first;count=0;minimum=0}else if(first>=194&&first<=223){point=first&31;count=1;minimum=128}else if(first>=224&&first<=239){point=first&15;count=2;minimum=2048}else if(first>=240&&first<=244){point=first&7;count=3;minimum=65536}else{if(this.fatal)throw new TypeError('invalid UTF-8');output+='\\ufffd';continue}let valid=true;for(let offset=0;offset<count;offset++){const next=bytes[index++];if(next===undefined||(next&192)!==128){valid=false;if(next!==undefined)index--;break}point=(point<<6)|(next&63)}if(!valid||point<minimum||point>1114111||(point>=55296&&point<=57343)){if(this.fatal)throw new TypeError('invalid UTF-8');output+='\\ufffd';continue}output+=String.fromCodePoint(point)}return output}
};
`

async function buildBundle (registryBytes, vectors) {
  const positiveVectors = vectors.filter(vector => vector.path.startsWith('positive/')).map(vector => {
    const match = /^positive\/\d{4}-(.+)\.cenc$/.exec(vector.path)
    if (!match) throw new Error(`unexpected positive validator vector path ${vector.path}`)
    return [match[1], Buffer.from(vector.bytes).toString('base64')]
  })
  const authorityArtifacts = {
    wireSpec: fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-v1.md')).toString('base64'),
    wireAbi: fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-abi-v1.cenc')).toString('base64'),
    wireVectors: fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')).toString('base64'),
    clientFormat: fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc')).toString('base64'),
    clientVectors: fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')).toString('base64')
  }
  const entry = `
import { decodePeeritProfileRegistry } from './js/substrate/profile-artifact-codec.mjs';
import { createPeeritProfileValidatorV1, PEERIT_PROFILE_VALIDATOR_CAPABILITIES_V1 } from './js/substrate/profile-validator.mjs';
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from './js/substrate/profile-external-authority.mjs';
import { blake2b256, concatBytes } from './js/substrate/release-control-primitives.mjs';
${base64DecoderSource(Buffer.from(registryBytes).toString('base64'))}
const POSITIVE_VECTORS=${JSON.stringify(positiveVectors)};
const AUTHORITY_ARTIFACTS=${JSON.stringify(authorityArtifacts)};
const registry=decodePeeritProfileRegistry(decodeBase64(REGISTRY_BASE64));
const compiled=Object.freeze({version:1,schemas:Object.freeze(registry.schemas.map(entry=>entry.codecIr))});
const inventory=Object.freeze({
  schemas:Object.freeze(registry.schemas),
  externalTypes:Object.freeze(registry.externalTypes),
  externalCodecImports:Object.freeze(registry.externalCodecImports),
  profileRegistries:Object.freeze(registry.profileRegistries)
});
export const PEERIT_VALIDATOR_PROFILE_BINDING_V1=Object.freeze({
  profileId:registry.profileId,
  profileSpecHash:new Uint8Array(registry.profileSpecHash),
  inventoryCommitment:new Uint8Array(registry.inventoryCommitment),
  schemaCount:compiled.schemas.length,
  capabilities:PEERIT_PROFILE_VALIDATOR_CAPABILITIES_V1
});
export function createPeeritValidatorV1(options){return createPeeritProfileValidatorV1(compiled,inventory,options)}
export { authenticatePeeritProfileExternalCodecAuthorityV1 };
function runtimeValidator(){
  const authorities={};
  const wireArtifacts={specBytes:decodeBase64(AUTHORITY_ARTIFACTS.wireSpec),abiBytes:decodeBase64(AUTHORITY_ARTIFACTS.wireAbi),vectorManifestBytes:decodeBase64(AUTHORITY_ARTIFACTS.wireVectors)};
  const clientArtifacts={formatAuthorityBytes:decodeBase64(AUTHORITY_ARTIFACTS.clientFormat),vectorManifestBytes:decodeBase64(AUTHORITY_ARTIFACTS.clientVectors)};
  for(const row of inventory.externalCodecImports)authorities[row.name]=authenticatePeeritProfileExternalCodecAuthorityV1({name:row.name,
    authorityKind:row.authorityKind,authorityBinding:row.tupleBinding,
    artifacts:row.authorityKind==='WIRE_TUPLE_V1'?wireArtifacts:clientArtifacts,
    assertCanonical(bytes,name){if(name!==row.name||!(bytes instanceof Uint8Array))throw new Error('bad runtime-vector external codec')}
  });
  return createPeeritProfileValidatorV1(compiled,inventory,{externalAuthorities:authorities,verifySignatures:false});
}
export function computePeeritValidatorRuntimeVectorV1(){
  const validator=runtimeValidator();
  const fixed=value=>{const bytes=new Uint8Array(32);bytes.fill(value);return bytes};
  return validator.catalog.SubstrateTupleV1.encode({specHash:fixed(17),abiHash:fixed(34),vectorSetHash:fixed(51)});
}
export function computePeeritValidatorRuntimeVectorSetHashV1(){
  const validator=runtimeValidator(),chunks=[];
  for(const [name,base64] of POSITIVE_VECTORS){const bytes=decodeBase64(base64),decoded=validator.catalog[name].decode(bytes),encoded=validator.catalog[name].encode(decoded);chunks.push(encoded)}
  return blake2b256(concatBytes(chunks));
}
`
  const result = await build({
    stdin: { contents: entry, resolveDir: root, sourcefile: 'peerit-validator-v1.entry.mjs' },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    target: ['es2020'],
    minify: true,
    legalComments: 'none',
    charset: 'ascii',
    treeShaking: true,
    sourcemap: false,
    banner: { js: bareTextCodecBanner },
    logLevel: 'silent'
  })
  if (result.outputFiles.length !== 1) throw new Error('validator build produced an unexpected output set')
  return new Uint8Array(result.outputFiles[0].contents)
}

function flipTag (bytes) {
  const output = new Uint8Array(bytes)
  output[0] ^= 0x80
  return output
}

function buildVectors (codecIr) {
  const authorities = externalAuthorities()
  const runtimeOptions = { externalAuthorityByName: authorities.map, sortProjection: peeritProfileNamedSortProjection }
  const catalog = createPeeritProfileCodecCatalogFromIr(codecIr, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: authorities.object,
    sortProjection: peeritProfileNamedSortProjection
  })
  const fixtures = createPeeritProfileStructuralFixtureFactory(codecIr, PEERIT_PROFILE_INVENTORY, runtimeOptions)
  const entries = []
  const positives = new Map()
  for (const schema of codecIr.schemas) {
    const prefix = `${String(schema.ordinal).padStart(4, '0')}-${schema.name}`
    const fixture = fixtures.create(schema.name, schema.ordinal * 1009)
    // Generated positives are structural fixtures, but this record's local
    // envelope relation is cheap and important enough to keep internally
    // coherent. Full signed-operation/readback proof is intentionally outside
    // this generic vector generator.
    if (schema.name === 'AuthorBindV1') {
      fixture.logicalHash = new Uint8Array(fixture.initialReplicas[0].logicalHash)
    }
    const positive = catalog[schema.name].encode(fixture)
    catalog[schema.name].decode(positive)
    positives.set(schema.name, positive)
    entries.push({ path: `positive/${prefix}.cenc`, bytes: positive })
    entries.push({ path: `negative/truncated/${prefix}.cenc`, bytes: positive.slice(0, positive.byteLength - 1) })
    entries.push({ path: `negative/bitflip-tag/${prefix}.cenc`, bytes: flipTag(positive) })
  }

  const reordered = new Uint8Array(positives.get('AvailabilityRootV1'))
  const recoveryStart = 76
  const first = reordered.slice(recoveryStart, recoveryStart + 32)
  const second = reordered.slice(recoveryStart + 32, recoveryStart + 64)
  reordered.set(second, recoveryStart)
  reordered.set(first, recoveryStart + 32)
  entries.push({ path: 'negative/semantic/reordered-recovery-keys.cenc', bytes: reordered })

  const duplicate = new Uint8Array(positives.get('AvailabilityRootV1'))
  duplicate.set(duplicate.slice(recoveryStart, recoveryStart + 32), recoveryStart + 32)
  entries.push({ path: 'negative/semantic/duplicate-recovery-key.cenc', bytes: duplicate })

  const crossField = new Uint8Array(positives.get('PeeritRecoveryBundleV1'))
  const ciphertextLengthOffset = 69
  crossField.set([0, 0, 0, 0, 0, 0, 0, 2], ciphertextLengthOffset)
  entries.push({ path: 'negative/semantic/recovery-length-mismatch.cenc', bytes: crossField })

  const innerPositive = positives.get('PeeritInnerOperationBatchV1')
  const invalidUtf8 = Uint8Array.of(innerPositive[0], innerPositive[1], innerPositive[2], 0, 0, 0, 1, 0x94)
  try {
    catalog.PeeritInnerOperationBatchV1.decode(invalidUtf8)
    throw new Error('PeeritInnerOperationBatchV1 accepted a malformed UTF-8 payload')
  } catch (error) {
    if (error && error.message === 'PeeritInnerOperationBatchV1 accepted a malformed UTF-8 payload') throw error
    if (!error || error.code !== 'BAD_RELEASE_CONTROL_ENCODING') throw error
  }
  entries.push({ path: 'negative/semantic/inner-operation-batch-invalid-utf8.cenc', bytes: invalidUtf8 })
  return entries
}

function recursivelyListedFiles (relativeRoot) {
  const absoluteRoot = path.join(root, relativeRoot)
  if (!fs.existsSync(absoluteRoot)) return []
  const output = []
  const visit = (absolute, relative) => {
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      const childAbsolute = path.join(absolute, entry.name)
      const childRelative = path.posix.join(relative, entry.name)
      if (entry.isDirectory()) visit(childAbsolute, childRelative)
      else output.push(childRelative)
    }
  }
  visit(absoluteRoot, relativeRoot)
  return output.sort()
}

function checkedInProblems (outputs) {
  const problems = []
  for (const [relative, expected] of outputs) {
    const absolute = path.join(root, relative)
    if (!fs.existsSync(absolute)) problems.push(`${relative}: missing`)
    else if (!bytesEqual(new Uint8Array(fs.readFileSync(absolute)), expected)) problems.push(`${relative}: generated bytes drift`)
  }
  const expectedVectors = new Set([...outputs.keys()].filter(relative => relative.startsWith(`${vectorRoot}/`)))
  for (const relative of recursivelyListedFiles(vectorRoot)) if (!expectedVectors.has(relative)) problems.push(`${relative}: stale generated vector`)
  return problems
}

function writeOutputs (outputs) {
  for (const [relative, bytes] of outputs) {
    const absolute = path.join(root, relative)
    fs.mkdirSync(path.dirname(absolute), { recursive: true })
    fs.writeFileSync(absolute, bytes)
  }
}

const sourceBytes = new Uint8Array(fs.readFileSync(path.join(root, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md')))
const profile = buildPeeritProfileArtifacts(sourceBytes, PEERIT_PROFILE_INVENTORY)
const vectors = buildVectors(profile.codecIr)
const firstBundle = await buildBundle(profile.registryBytes, vectors)
const secondBundle = await buildBundle(profile.registryBytes, vectors)
if (!bytesEqual(firstBundle, secondBundle)) throw new Error('validator bundle is not deterministic across two isolated builds')
const vectorManifest = encodePeeritValidatorVectorManifestV1(vectors)
const outputs = new Map([
  [PEERIT_VALIDATOR_ARTIFACT_PATH, firstBundle],
  [bareImportMirrorPath, firstBundle],
  [PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH, vectorManifest]
])
for (const vector of vectors) outputs.set(path.posix.join(vectorRoot, vector.path), vector.bytes)

if (!check) writeOutputs(outputs)
const problems = checkedInProblems(outputs)
if (problems.length > 0) {
  for (const problem of problems) process.stderr.write(`${problem}\n`)
  process.exitCode = 1
} else {
  process.stdout.write(`${JSON.stringify({
    schema: 'PeeritValidatorArtifactGenerationV1',
    artifactPath: PEERIT_VALIDATOR_ARTIFACT_PATH,
    artifactBytes: firstBundle.byteLength,
    bareImportMirrorPath,
    validatorArtifactHash: bytesToHex(hashPeeritValidatorArtifactV1(firstBundle)),
    vectorManifestPath: PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH,
    vectorManifestBytes: vectorManifest.byteLength,
    vectorCount: vectors.length,
    validatorVectorSetHash: bytesToHex(hashPeeritValidatorVectorSetV1(vectorManifest)),
    profileSpecHash: bytesToHex(profile.profileSpecHash),
    profileAbiHash: bytesToHex(profile.profileAbiHash),
    externalCodecAuthorityComplete: profile.codecIr.externalCodecAuthorityComplete
  }, null, 2)}\n`)
}
