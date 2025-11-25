import { Bench } from 'tinybench'
import rust from '../index'
import node from '../curve25519.cjs'

const {
  generateKeyPair: generateKeyPairRust,
  getPublicFromPrivateKey: getPublicRust,
  calculateAgreement: agreementRust,
  calculateSignature: signRust,
  verifySignature: verifyRust,
} = rust
const {
  generateKeyPair: generateKeyPairNode,
  getPublicFromPrivateKey: getPublicNode,
  calculateAgreement: agreementNode,
  calculateSignature: signNode,
  verifySignature: verifyNode,
} = node

const rustKeys = generateKeyPairRust()
const nodeKeys = generateKeyPairNode()

const message = Buffer.from('hello world')

const rustPublicFromPriv = getPublicRust(rustKeys.privKey)
const nodePublicFromPriv = getPublicNode(nodeKeys.privKey)

// Precompute signature
const rustSignature = signRust(rustKeys.privKey, message)
const nodeSignature = signNode(nodeKeys.privKey, message)

// Precompute key agreement
const rustShared = agreementRust(rustKeys.pubKey, rustKeys.privKey)
const nodeShared = agreementNode(nodeKeys.pubKey, nodeKeys.privKey)

// --------------------------------------
// BENCH SETUP
// --------------------------------------

const bench = new Bench()

// ===== generateKeyPair =====
bench.add('Rust generateKeyPair', () => {
  generateKeyPairRust()
})

bench.add('Node generateKeyPair', () => {
  generateKeyPairNode()
})

// ===== getPublicFromPrivateKey =====
bench.add('Rust getPublicFromPrivateKey', () => {
  getPublicRust(rustKeys.privKey)
})

bench.add('Node getPublicFromPrivateKey', () => {
  getPublicNode(nodeKeys.privKey)
})

// ===== calculateAgreement =====
bench.add('Rust calculateAgreement', () => {
  agreementRust(rustKeys.pubKey, rustKeys.privKey)
})

bench.add('Node calculateAgreement', () => {
  agreementNode(nodeKeys.pubKey, nodeKeys.privKey)
})

// ===== calculateSignature =====
bench.add('Rust calculateSignature', () => {
  signRust(rustKeys.privKey, message)
})

bench.add('Node calculateSignature', () => {
  signNode(nodeKeys.privKey, message)
})

// ===== verifySignature =====
bench.add('Rust verifySignature', () => {
  verifyRust(rustKeys.pubKey, message, rustSignature)
})

bench.add('Node verifySignature', () => {
  verifyNode(nodeKeys.pubKey, message, nodeSignature)
})

// --------------------------------------
// RUN
// --------------------------------------

await bench.run()
console.table(bench.table())
