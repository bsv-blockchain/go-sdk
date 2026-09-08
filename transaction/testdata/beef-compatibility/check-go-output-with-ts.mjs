#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const tsRoot = process.env.TS_STACK_ROOT
const matrixPath = process.env.TS_INTEROP_FIXTURES
const goOutputPath = process.env.GO_BEEF_PROBE_OUTPUT
if (!tsRoot || !matrixPath || !goOutputPath) {
  throw new Error('Set TS_STACK_ROOT, TS_INTEROP_FIXTURES, and GO_BEEF_PROBE_OUTPUT')
}

const transactionPath = path.join(tsRoot, 'packages/sdk/dist/esm/src/transaction/index.js')
const { Beef, Transaction } = await import(transactionPath)
const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'))
const goResults = JSON.parse(fs.readFileSync(goOutputPath, 'utf8'))
const byName = new Map(matrix.fixtures.map(fixture => [fixture.name, fixture]))
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex')
const hex = value => Buffer.from(value).toString('hex')
const equal = (a, b) => Buffer.from(a).equals(Buffer.from(b))
const failures = []
const check = (condition, message) => { if (!condition) failures.push(message) }

function checkMetadata(beef, expected, label) {
  const records = new Map(expected.transactions.map(item => [item.txid, item]))
  check(beef.txs.length === records.size, `${label}: transaction count differs`)
  for (const item of beef.txs) {
    const wanted = records.get(item.txid)
    check(wanted != null, `${label}: unexpected transaction ${item.txid}`)
    if (wanted == null) continue
    check(item.isTxidOnly === wanted.isTxidOnly, `${label}: txid-only representation changed`)
    if (!item.isTxidOnly) {
      check(hex(item.rawTxUint8Array) === wanted.rawTxHex, `${label}: raw transaction changed`)
      const rawID = crypto.createHash('sha256').update(crypto.createHash('sha256').update(item.rawTxUint8Array).digest()).digest().reverse().toString('hex')
      check(rawID === item.txid, `${label}: independent double-SHA256 txid differs`)
    }
    check((item.bumpIndex == null) === (wanted.bumpIndex == null), `${label}: proof presence changed for ${item.txid}`)
    if (item.bumpIndex != null && wanted.bumpIndex != null) {
      const bump = beef.bumps[item.bumpIndex]
      const proof = expected.bumps[wanted.bumpIndex]
      check(bump != null && proof != null, `${label}: invalid proof index`)
      if (bump != null && proof != null) {
        check(hex(bump.toBinary()) === proof.hex, `${label}: selected proof bytes changed for ${item.txid}`)
        check(proof.roots.includes(bump.computeRoot(item.txid)), `${label}: selected proof root changed for ${item.txid}`)
      }
    }
  }
}

check(goResults.length === matrix.fixtures.length, 'forward matrix is incomplete')

for (const go of goResults) {
  const expected = byName.get(go.name)
  check(expected != null, `${go.name}: fixture missing from TS matrix`)
  if (expected == null) continue

  const beefBytes = Buffer.from(go.beef.beefHex, 'hex')
  const atomicBytes = Buffer.from(go.atomicHex, 'hex')
  check(go.targetTxid === expected.targetTxid, `${go.name}: target txid differs from TS matrix`)
  check(go.beef.sha256 === sha256(beefBytes), `${go.name}: Go BEEF SHA-256 is wrong`)
  check(go.atomic.sha256 === sha256(atomicBytes), `${go.name}: Go AtomicBEEF SHA-256 is wrong`)
  const identityExact = expected.kind === 'identity-original-exact'
  if (identityExact) {
    check(go.beef.beefHex === expected.beef.beefHex, `${go.name}: identity BEEF bytes differ`)
    check(go.atomicHex === expected.atomicHex, `${go.name}: identity AtomicBEEF bytes differ`)
  }

  const beef = Beef.fromBinaryView(Buffer.from(beefBytes))
  const atomic = Beef.fromBinaryView(Buffer.from(atomicBytes))
  checkMetadata(beef, expected.beef, `${go.name}/BEEF`)
  checkMetadata(atomic, expected.atomic, `${go.name}/Atomic`)
  check(beef.version === expected.beef.version, `${go.name}: BEEF version mismatch`)
  check(atomic.atomicTxid === expected.targetTxid, `${go.name}: atomic subject txid mismatch`)
  check(atomic.isAtomic(expected.targetTxid), `${go.name}: AtomicBEEF inclusion closure is false`)
  check(hex(atomicBytes.subarray(0, 4)) === '01010101', `${go.name}: atomic prefix mismatch`)
  check(equal(atomicBytes, atomic.toUint8ArrayAtomic(expected.targetTxid)), `${go.name}: TS AtomicBEEF round-trip differs`)

  const expectedTxs = expected.beef.transactions
  const expectedAtomicTxs = expected.atomic.transactions
  const expectedTxByID = new Map(expectedTxs.map(item => [item.txid, item]))
  const expectedAtomicTxByID = new Map(expectedAtomicTxs.map(item => [item.txid, item]))
  check(beef.txs.length === expectedTxs.length, `${go.name}: BEEF transaction count differs`)
  check(atomic.txs.length === expectedAtomicTxs.length, `${go.name}: Atomic transaction count differs`)
  check([...beef.txs].every(item => expectedTxByID.has(item.txid)), `${go.name}: BEEF transaction set differs`)
  check([...atomic.txs].every(item => expectedAtomicTxByID.has(item.txid)), `${go.name}: Atomic transaction set differs`)
  const expectedBeefBumpBytes = new Set(expected.beef.bumps.map(item => item.hex))
  const expectedAtomicBumpBytes = new Set(expected.atomic.bumps.map(item => item.hex))
  const actualBeefBumpBytes = new Set(beef.bumps.map(item => hex(item.toBinary())))
  const actualAtomicBumpBytes = new Set(atomic.bumps.map(item => hex(item.toBinary())))
  check(expectedBeefBumpBytes.size === actualBeefBumpBytes.size && [...expectedBeefBumpBytes].every(item => actualBeefBumpBytes.has(item)), `${go.name}: BEEF BUMP bytes differ`)
  check(expectedAtomicBumpBytes.size === actualAtomicBumpBytes.size && [...expectedAtomicBumpBytes].every(item => actualAtomicBumpBytes.has(item)), `${go.name}: Atomic BUMP bytes differ`)

  for (const item of beef.txs) {
    const expectedRecord = expectedTxByID.get(item.txid) ?? expectedAtomicTxByID.get(item.txid)
    check(expectedRecord != null, `${go.name}: parsed tx ${item.txid} absent from TS metadata`)
    if (item.rawTxUint8Array != null) {
      const parsedTx = Transaction.fromBinary(Buffer.from(item.rawTxUint8Array))
      check(parsedTx.id('hex') === item.txid, `${go.name}: raw txid recomputation failed for ${item.txid}`)
      if (expectedRecord?.rawTxHex != null) {
        check(hex(item.rawTxUint8Array) === expectedRecord.rawTxHex, `${go.name}: raw tx bytes differ for ${item.txid}`)
      }
      const inputs = parsedTx.inputs.map(input => input.sourceTXID)
      // Proven entries intentionally clear inputTxids: their BUMP is the
      // validity anchor and the parser does not use their ancestry for sort.
      if (item.bumpIndex === undefined) {
        check(JSON.stringify(inputs) === JSON.stringify(item.inputTxids), `${go.name}: input txids differ for ${item.txid}`)
      }
      const index = beef.txs.findIndex(candidate => candidate.txid === item.txid)
      for (const input of inputs) {
        const parentIndex = beef.txs.findIndex(candidate => candidate.txid === input)
        if (parentIndex >= 0) check(parentIndex < index, `${go.name}: parent ${input} follows child ${item.txid}`)
      }
    } else {
      check(item.isTxidOnly, `${go.name}: missing raw tx is not marked txid-only for ${item.txid}`)
    }
  }

  for (let index = 0; index < beef.bumps.length; index++) {
    const bump = beef.bumps[index]
    const leaf = bump.path.flat().find(candidate => candidate.txid === true)
    check(leaf?.hash != null, `${go.name}: BUMP ${index} has no txid-marked leaf`)
    if (leaf?.hash != null) {
      const root = bump.computeRoot(leaf.hash)
      check(root === go.beef.bumpRoots[index], `${go.name}: BUMP ${index} root recomputation failed`)
    }
  }

  const target = beef.txs.find(item => item.txid === expected.targetTxid)
  if (target?.isTxidOnly === true) {
    let rejected = false
    try { Transaction.fromAtomicBEEF(Buffer.from(atomicBytes)) } catch { rejected = true }
    check(rejected, `${go.name}: txid-only subject unexpectedly yielded a Transaction`)
  } else {
    let parsedSubject
    try { parsedSubject = Transaction.fromAtomicBEEF(Buffer.from(atomicBytes)) } catch (error) {
      failures.push(`${go.name}: AtomicBEEF subject parse failed: ${error.message}`)
    }
    if (parsedSubject != null) check(parsedSubject.id('hex') === expected.targetTxid, `${go.name}: AtomicBEEF target recomputation failed`)
  }
}

const proof0 = matrix.fixtures.find(fixture => fixture.name === 'v2-proof-index-0')
const proof1 = matrix.fixtures.find(fixture => fixture.name === 'v2-proof-index-1')
if (proof0 != null && proof1 != null) {
  const ancestorTxid = matrix.transactions.find(item => item.name === 'ancestor-A')?.txid
  const tx0 = proof0.beef.transactions.find(item => item.txid === ancestorTxid)
  const tx1 = proof1.beef.transactions.find(item => item.txid === ancestorTxid)
  check(proof0.targetTxid === proof1.targetTxid, 'proof variants: target txids differ')
  check(tx0?.bumpIndex === 0 && tx1?.bumpIndex === 1, 'proof variants: ancestor BUMP indices are not 0 and 1')
}

const identity = matrix.fixtures.find(fixture => fixture.kind === 'identity-original-exact')
if (identity != null) {
  check(identity.beef.sha256 === identity.expectedBeefSha256, 'identity fixture: BEEF digest changed')
  check(identity.atomicSha256 === identity.expectedAtomicSha256, 'identity fixture: AtomicBEEF digest changed')
}

const result = { checked: goResults.length, failures }
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
if (failures.length > 0) process.exitCode = 1
