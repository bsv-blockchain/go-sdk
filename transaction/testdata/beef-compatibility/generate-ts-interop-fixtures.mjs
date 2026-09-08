#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const tsRoot = process.env.TS_STACK_ROOT
const identityPath = process.env.IDENTITY_ORIGINAL_JSON
if (!tsRoot || !identityPath) throw new Error('Set TS_STACK_ROOT and IDENTITY_ORIGINAL_JSON')

const sdkPath = path.join(tsRoot, 'packages/sdk/dist/esm/src/transaction/index.js')
const scriptPath = path.join(tsRoot, 'packages/sdk/dist/esm/src/script/index.js')
const { BEEF_V1, BEEF_V2, Beef, MerklePath, Transaction } = await import(sdkPath)
const { Script } = await import(scriptPath)

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex')
const hex = bytes => Buffer.from(bytes).toString('hex')
const bytes = value => Buffer.from(value, 'hex')
const txid = tx => tx.id('hex')
const raw = tx => Buffer.from(tx.toUint8Array())

const protocolSource = {
  tsStackBaseCommit: '2bc799a8d8e535242e6de2d305f426ce3975ea7b',
  c01AcceptedCommit: 'c58f81787e7c2a985a167c15db9fd9ca5fed6c35',
  sdkVersion: '2.5.0',
  beefConstants: 'packages/sdk/src/transaction/BeefConstants.ts',
  beef: 'packages/sdk/src/transaction/Beef.ts',
  beefTx: 'packages/sdk/src/transaction/BeefTx.ts',
  transaction: 'packages/sdk/src/transaction/Transaction.ts',
  beefTests: 'packages/sdk/src/transaction/__tests/Beef.test.ts',
  c01FixtureSource: 'packages/wallet/wallet-toolbox/src/utility/__tests__/identityVerification.fixtures.ts',
  c01FixtureJSON: 'packages/wallet/wallet-toolbox/src/utility/__tests__/fixtures/identity-verification.json'
}

function makeTransaction(previous, outputCount, value, sourceOutputIndex = 0) {
  const tx = new Transaction()
  if (previous == null) {
    tx.addInput({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex,
      unlockingScript: Script.fromASM('OP_TRUE')
    })
  } else {
    tx.addInput({
      sourceTransaction: previous,
      sourceOutputIndex,
      unlockingScript: Script.fromASM('OP_TRUE')
    })
  }
  for (let i = 0; i < outputCount; i++) {
    tx.addOutput({ satoshis: value - i, lockingScript: Script.fromASM('OP_TRUE') })
  }
  return tx
}

function makeJoinTransaction(left, right, value) {
  const tx = new Transaction()
  tx.addInput({ sourceTransaction: left, sourceOutputIndex: 0, unlockingScript: Script.fromASM('OP_TRUE') })
  tx.addInput({ sourceTransaction: right, sourceOutputIndex: 0, unlockingScript: Script.fromASM('OP_TRUE') })
  tx.addOutput({ satoshis: value, lockingScript: Script.fromASM('OP_TRUE') })
  return tx
}

function makeProof(name, txidValue, height, sibling, txOffset = 1) {
  const pathValue = new MerklePath(height, [[
    { offset: txOffset === 1 ? 0 : 1, hash: sibling },
    { offset: txOffset, hash: txidValue, txid: true }
  ]])
  return {
    name,
    blockHeight: height,
    txid: txidValue,
    root: pathValue.computeRoot(txidValue),
    sibling,
    path: pathValue
  }
}

function addRaw(beef, tx, bumpIndex) {
  beef.mergeRawTx(raw(tx), bumpIndex)
}

function recordParsed(bytesValue, targetTxid) {
  const source = Buffer.from(bytesValue)
  const parsed = Beef.fromBinaryView(Buffer.from(source))
  return {
    version: parsed.version,
    versionLE: hex(source.subarray(0, 4)),
    sha256: sha256(source),
    bytes: source.length,
    targetTxid,
    atomicTxid: parsed.atomicTxid,
    bumps: parsed.bumps.map((bump, index) => ({
      index,
      blockHeight: bump.blockHeight,
      hex: hex(bump.toBinary()),
      roots: bump.path.length > 0 && bump.path[0].length > 0
        ? [bump.computeRoot(bump.path[0].find(leaf => leaf.txid)?.hash ?? bump.path[0][0].hash)]
        : []
    })),
    transactions: parsed.txs.map((item, index) => ({
      index,
      txid: item.txid,
      inputTxids: [...item.inputTxids],
      bumpIndex: item.bumpIndex,
      isTxidOnly: item.isTxidOnly,
      rawTxHex: item.rawTxUint8Array == null ? undefined : hex(item.rawTxUint8Array)
    })),
    beefHex: hex(source)
  }
}

function makeFixture(name, version, transactions, proofs, targetTxid, options = {}) {
  const beef = new Beef(version)
  for (const proof of proofs) beef.bumps.push(proof.path)
  for (const item of transactions) {
    if (item.txidOnly) beef.mergeTxidOnly(item.txid)
    else addRaw(beef, item.tx, item.bumpIndex)
  }
  const beefBytes = beef.toUint8Array()
  const atomicBytes = beef.toUint8ArrayAtomic(targetTxid)
  const parsed = recordParsed(beefBytes, targetTxid)
  const parsedAtomic = recordParsed(atomicBytes, targetTxid)
  return {
    name,
    kind: options.kind ?? 'beef',
    version,
    targetTxid,
    sourceTransactionNames: transactions.map(item => item.name),
    beef: parsed,
    atomic: parsedAtomic,
    atomicHex: hex(atomicBytes),
    atomicSha256: sha256(atomicBytes)
  }
}

// Deterministic shared-ancestor DAG: A -> B -> C and A -> D.
const ancestor = makeTransaction(undefined, 2, 100)
const branchB = makeTransaction(ancestor, 1, 90)
const subjectC = makeTransaction(branchB, 1, 80)
const branchD = makeTransaction(ancestor, 1, 70, 1)
const subjectE = makeJoinTransaction(subjectC, branchD, 60)
const txs = [ancestor, branchB, subjectC, branchD, subjectE]
for (const tx of txs) tx.materializeSourceTXIDs()
const txRecords = txs.map((tx, index) => ({
  name: ['ancestor-A', 'branch-B', 'subject-C', 'branch-D', 'subject-E'][index],
  txid: txid(tx),
  rawTxHex: hex(raw(tx)),
  inputTxids: tx.inputs.map(input => input.sourceTXID)
}))

const ancestorProof = makeProof('ancestor-proof', txid(ancestor), 700000, '42'.repeat(32))
const alternateAncestorProof = makeProof('ancestor-proof-alt', txid(ancestor), 700002, '43'.repeat(32))
const unrelatedProof = makeProof('unrelated-proof', '99'.repeat(32), 700001, '88'.repeat(32))

const fullDag = [
  { name: 'ancestor-A', tx: ancestor, bumpIndex: 0 },
  { name: 'branch-B', tx: branchB },
  { name: 'subject-C', tx: subjectC },
  { name: 'branch-D', tx: branchD }
]
const joinDag = [...fullDag, { name: 'subject-E', tx: subjectE }]
const fixtures = [
  makeFixture('v1-shared-ancestor-dag', BEEF_V1, fullDag, [ancestorProof], txid(subjectC)),
  makeFixture('v2-shared-ancestor-dag', BEEF_V2, fullDag, [ancestorProof], txid(subjectC)),
  makeFixture('atomic-v1-shared-ancestor-dag', BEEF_V1, fullDag, [ancestorProof], txid(subjectC), { kind: 'atomic' }),
  makeFixture('atomic-v2-shared-ancestor-dag', BEEF_V2, fullDag, [ancestorProof], txid(subjectC), { kind: 'atomic' }),
  makeFixture('v2-proof-index-0', BEEF_V2, fullDag, [ancestorProof], txid(subjectC), { kind: 'proof-index-0' }),
  makeFixture('v2-proof-index-1', BEEF_V2,
    fullDag.map(item => item.name === 'ancestor-A' ? { ...item, bumpIndex: 1 } : item),
    [unrelatedProof, alternateAncestorProof], txid(subjectC), { kind: 'proof-index-1' }),
  makeFixture('v1-proof-variant-0', BEEF_V1, fullDag,
    [ancestorProof, alternateAncestorProof], txid(subjectC)),
  makeFixture('v1-proof-variant-1', BEEF_V1,
    fullDag.map(item => item.name === 'ancestor-A' ? { ...item, bumpIndex: 1 } : item),
    [ancestorProof, alternateAncestorProof], txid(subjectC)),
  makeFixture('v2-proof-variant-0', BEEF_V2, fullDag,
    [ancestorProof, alternateAncestorProof], txid(subjectC)),
  makeFixture('v2-proof-variant-1', BEEF_V2,
    fullDag.map(item => item.name === 'ancestor-A' ? { ...item, bumpIndex: 1 } : item),
    [ancestorProof, alternateAncestorProof], txid(subjectC)),
  makeFixture('v1-shared-ancestor-join', BEEF_V1, joinDag, [ancestorProof], txid(subjectE)),
  makeFixture('v2-shared-ancestor-join', BEEF_V2, joinDag, [ancestorProof], txid(subjectE)),
  makeFixture('atomic-v1-shared-ancestor-join', BEEF_V1, joinDag, [ancestorProof], txid(subjectE), { kind: 'atomic' }),
  makeFixture('atomic-v2-shared-ancestor-join', BEEF_V2, joinDag, [ancestorProof], txid(subjectE), { kind: 'atomic' }),
  makeFixture('v2-txid-only-ancestor', BEEF_V2, [
    { name: 'ancestor-A', txidOnly: true, txid: txid(ancestor) },
    { name: 'branch-B', tx: branchB },
    { name: 'subject-C', tx: subjectC }
  ], [], txid(subjectC), { kind: 'txid-only-ancestor' }),
  makeFixture('v2-txid-only-subject', BEEF_V2, [
    { name: 'ancestor-A', tx: ancestor },
    { name: 'subject-C', txidOnly: true, txid: txid(subjectC) }
  ], [], txid(subjectC), { kind: 'txid-only-subject' })
]

const identity = JSON.parse(fs.readFileSync(identityPath, 'utf8'))
const identityBeef = Buffer.from(identity.beefBase64, 'base64')
const identityAtomic = Buffer.from(identity.atomicBEEFBase64, 'base64')
const identityEntry = {
  name: identity.name,
  kind: 'identity-original-exact',
  targetTxid: identity.txid,
  expectedBeefSha256: identity.beefSha256,
  expectedAtomicSha256: identity.atomicBEEFSha256,
  beef: recordParsed(identityBeef, identity.txid),
  atomic: recordParsed(identityAtomic, identity.txid),
  atomicHex: hex(identityAtomic),
  atomicSha256: sha256(identityAtomic),
  metadata: {
    merkleRoot: identity.merkleRoot,
    ancestorTxid: identity.ancestorTxid,
    outputsToAdmit: identity.outputsToAdmit
  }
}

const output = {
  schemaVersion: 1,
  source: protocolSource,
  constants: { BEEF_V1, BEEF_V2, ATOMIC_BEEF: 0x01010101 },
  transactions: txRecords,
  proofs: [ancestorProof, unrelatedProof].map(({ path: _path, ...rest }) => rest),
  fixtures: [...fixtures, identityEntry]
}

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`)
