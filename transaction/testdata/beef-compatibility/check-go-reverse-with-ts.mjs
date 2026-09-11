#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const tsRoot = process.env.TS_STACK_ROOT
const matrixPath = process.env.TS_INTEROP_FIXTURES
const reversePath = process.env.GO_REVERSE_OUTPUT
if (!tsRoot || !matrixPath || !reversePath) throw new Error('Set TS_STACK_ROOT, TS_INTEROP_FIXTURES, and GO_REVERSE_OUTPUT')

const { Beef, Transaction } = await import(path.join(tsRoot, 'packages/sdk/dist/esm/src/transaction/index.js'))
const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'))
const outputs = JSON.parse(fs.readFileSync(reversePath, 'utf8'))
const expected = new Map(matrix.fixtures.map(f => [f.name, f]))
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

const expectedCount = matrix.fixtures.reduce((n, f) => n + (f.beef.transactions.some(t => t.isTxidOnly) ? 1 : 2), 0)
check(outputs.length === expectedCount, 'reverse matrix is incomplete')

for (const output of outputs) {
  const fixture = expected.get(output.name)
  check(fixture != null, `${output.name}/${output.kind}: fixture missing`)
  if (!fixture) continue
  const body = Buffer.from(output.beefHex, 'hex')
  const atomicBytes = Buffer.from(output.atomicHex, 'hex')
  let beef
  let atomic
  try { beef = Beef.fromBinaryView(Buffer.from(body)) } catch (error) { failures.push(`${output.name}/${output.kind}: TS BEEF parse failed: ${error.message}`); continue }
  try { atomic = Beef.fromBinaryView(Buffer.from(atomicBytes)) } catch (error) { failures.push(`${output.name}/${output.kind}: TS AtomicBEEF parse failed: ${error.message}`); continue }
  checkMetadata(beef, fixture.beef, `${output.name}/${output.kind}/BEEF`)
  checkMetadata(atomic, fixture.atomic, `${output.name}/${output.kind}/Atomic`)
  const digestBytes = output.kind === 'go-created-atomic-v2' ? atomicBytes : body
  check(sha256(digestBytes) === output.sha256, `${output.name}/${output.kind}: serialized digest mismatch`)
  check(beef.version === output.version, `${output.name}/${output.kind}: version mismatch`)
  check(hex(atomicBytes.subarray(0, 4)) === '01010101', `${output.name}/${output.kind}: atomic prefix mismatch`)
  check(atomic.atomicTxid === output.targetTxid, `${output.name}/${output.kind}: atomic subject mismatch`)
  check(atomic.isAtomic(output.targetTxid), `${output.name}/${output.kind}: atomic closure false`)
  check(equal(atomicBytes, atomic.toUint8ArrayAtomic(output.targetTxid)), `${output.name}/${output.kind}: atomic TS roundtrip differs`)
  check(beef.txs.some(item => item.txid === output.targetTxid), `${output.name}/${output.kind}: target absent`)

  const txids = new Set()
  for (let index = 0; index < beef.txs.length; index++) {
    const item = beef.txs[index]
    check(!txids.has(item.txid), `${output.name}/${output.kind}: duplicate txid ${item.txid}`)
    txids.add(item.txid)
    if (item.rawTxUint8Array != null) {
      const parsed = Transaction.fromBinary(Buffer.from(item.rawTxUint8Array))
      check(parsed.id('hex') === item.txid, `${output.name}/${output.kind}: raw txid recomputation failed for ${item.txid}`)
      for (const input of parsed.inputs) {
        const parentIndex = beef.txs.findIndex(candidate => candidate.txid === input.sourceTXID)
        if (parentIndex >= 0) check(parentIndex < index, `${output.name}/${output.kind}: parent follows child ${item.txid}`)
      }
    } else {
      check(item.isTxidOnly, `${output.name}/${output.kind}: missing raw tx is not txid-only`)
    }
  }
  for (const [index, bump] of beef.bumps.entries()) {
    const leaf = bump.path.flat().find(candidate => candidate.txid === true)
    check(leaf?.hash != null, `${output.name}/${output.kind}: BUMP ${index} lacks txid leaf`)
    if (leaf?.hash != null) check(bump.computeRoot(leaf.hash) != null, `${output.name}/${output.kind}: BUMP ${index} root failed`)
  }
  const subject = beef.txs.find(item => item.txid === output.targetTxid)
  if (subject?.isTxidOnly) {
    let rejected = false
    try { Transaction.fromAtomicBEEF(Buffer.from(atomicBytes)) } catch { rejected = true }
    check(rejected, `${output.name}/${output.kind}: txid-only subject unexpectedly parsed as Transaction`)
  } else {
    try {
      const parsed = Transaction.fromAtomicBEEF(Buffer.from(atomicBytes))
      check(parsed.id('hex') === output.targetTxid, `${output.name}/${output.kind}: atomic target recomputation failed`)
    } catch (error) { failures.push(`${output.name}/${output.kind}: atomic subject parse failed: ${error.message}`) }
  }
}

process.stdout.write(`${JSON.stringify({ checked: outputs.length, failures }, null, 2)}\n`)
if (failures.length) process.exitCode = 1
