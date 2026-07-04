// reader-bundle.js — optional browser reader bundle placeholder.
//
// Production web builds replace this file with an esbuilt bundle of
// js/reader-src.mjs (via scripts/build-reader-bundle.mjs). The base site ships
// this explicit stub so a non-dispersal build fails closed with a clear message
// instead of producing a network 404 for a dynamic import.

export async function recoverBody () {
  throw new Error('peerit reader bundle is not included in this build')
}

export async function recoverKey () {
  throw new Error('peerit reader bundle is not included in this build')
}
