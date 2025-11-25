import test from 'ava'

import {
  generateKeyPair as generateKeyPairRust,
  getPublicFromPrivateKey as getPublicFromPrivateKeyRust,
  calculateAgreement as calculateAgreementRust,
  calculateSignature as calculateSignatureRust,
  verifySignature as verifySignatureRust,
} from '../index'
import {
  generateKeyPair as generateKeyPairNode,
  getPublicFromPrivateKey as getPublicFromPrivateKeyNode,
  calculateAgreement as calculateAgreementNode,
  calculateSignature as calculateSignatureNode,
  verifySignature as verifySignatureNode,
} from './curve25519.ts'

// --------------------------------------------
// GLOBAL SHARED STATE (dipakai semua test)
// --------------------------------------------
let rustKeypair
let nodeKeypair
let testMessage
let rustPubFromPriv
let nodePubFromPriv
let sharedRustAB
let sharedNodeAB

// --------------------------------------------
// TEST 1 — generateKeyPair
// --------------------------------------------
test('generateKeyPair: rust vs node match format', (t) => {
  rustKeypair = generateKeyPairRust()
  nodeKeypair = generateKeyPairNode()
  testMessage = Buffer.from('hello world')

  t.is(rustKeypair.pubKey.length, 33)
  t.is(rustKeypair.privKey.length, 32)

  t.is(nodeKeypair.pubKey.length, 33)
  t.is(nodeKeypair.privKey.length, 32)
})

// --------------------------------------------
// TEST 2 — getPublicFromPrivateKey
// --------------------------------------------
test('getPublicFromPrivateKey: rust vs node', (t) => {
  const priv = rustKeypair.privKey

  rustPubFromPriv = getPublicFromPrivateKeyRust(priv)
  nodePubFromPriv = getPublicFromPrivateKeyNode(priv)

  t.is(rustPubFromPriv.length, 33)
  t.is(nodePubFromPriv.length, 33)
})

// --------------------------------------------
// TEST 3 — calculateAgreement
// --------------------------------------------
test('calculateAgreement: Rust vs Node produce same shared key', (t) => {
  const a = rustKeypair
  const b = nodeKeypair

  sharedRustAB = calculateAgreementRust(b.pubKey, a.privKey)
  const sharedRustBA = calculateAgreementRust(a.pubKey, b.privKey)

  t.deepEqual(sharedRustAB, sharedRustBA)

  sharedNodeAB = calculateAgreementNode(b.pubKey, a.privKey)
  const sharedNodeBA = calculateAgreementNode(a.pubKey, b.privKey)

  t.deepEqual(sharedNodeAB, sharedNodeBA)

  t.deepEqual(sharedRustAB, sharedNodeAB)
})

// --------------------------------------------
// TEST 4 — signature / verify
// --------------------------------------------
test('signature: rust vs node - should verify true', (t) => {
  const priv = rustKeypair.privKey
  const pub = rustKeypair.pubKey

  const sigRust = calculateSignatureRust(priv, testMessage)
  const sigNode = calculateSignatureNode(priv, testMessage)

  t.is(sigRust.length, 64)
  t.is(sigNode.length, 64)

  // Verify both signatures
  t.true(verifySignatureRust(pub, testMessage, sigRust))
  t.true(verifySignatureNode(pub, testMessage, sigNode))
})
