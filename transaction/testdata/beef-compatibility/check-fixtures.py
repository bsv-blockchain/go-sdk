#!/usr/bin/env python3
"""Independently check this corpus's txids and one-level BUMP roots using hashlib.

This deliberately understands only the fixture proof profile, not arbitrary
BUMP validation, scripts, chain headers, certificates, or unspentness.
"""
import hashlib
import json
from pathlib import Path


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(data, offset):
    prefix = data[offset]
    if prefix < 253:
        return prefix, offset + 1
    size = {253: 2, 254: 4, 255: 8}[prefix]
    end = offset + 1 + size
    assert end <= len(data)
    return int.from_bytes(data[offset + 1:end], 'little'), end


def proof_root(encoded):
    data = bytes.fromhex(encoded)
    height, pos = varint(data, 0)
    assert data[pos] == 1, 'fixture checker supports exactly one path level'
    count, pos = varint(data, pos + 1)
    leaves = {}
    for _ in range(count):
        offset, pos = varint(data, pos)
        flags = data[pos]
        pos += 1
        assert flags in (0, 2), 'fixture checker expects explicit nonduplicate hashes'
        assert pos + 32 <= len(data)
        leaves[offset] = data[pos:pos + 32]
        pos += 32
    assert pos == len(data)
    assert set(leaves) == {0, 1}, 'fixture checker expects two leaves'
    return height, hash256(leaves[0] + leaves[1])[::-1].hex(), leaves


def main():
    matrix = json.loads(Path(__file__).with_name('ts-interop-fixtures.json').read_text())
    raw_transactions = set()
    proofs = set()
    for fixture in matrix['fixtures']:
        for kind in ('beef', 'atomic'):
            record = fixture[kind]
            for bump in record['bumps']:
                height, root, _ = proof_root(bump['hex'])
                assert height == bump['blockHeight']
                assert bump['roots'] == [root]
                proofs.add(bump['hex'])
            for tx in record['transactions']:
                if tx['isTxidOnly']:
                    assert not tx.get('rawTxHex')
                    continue
                raw = bytes.fromhex(tx['rawTxHex'])
                assert hash256(raw)[::-1].hex() == tx['txid']
                raw_transactions.add(raw)
                if 'bumpIndex' in tx:
                    _, _, leaves = proof_root(record['bumps'][tx['bumpIndex']]['hex'])
                    assert bytes.fromhex(tx['txid'])[::-1] in leaves.values()
        if fixture['kind'] == 'identity-original-exact':
            assert hashlib.sha256(bytes.fromhex(fixture['beef']['beefHex'])).hexdigest() == fixture['expectedBeefSha256']
            assert hashlib.sha256(bytes.fromhex(fixture['atomicHex'])).hexdigest() == fixture['expectedAtomicSha256']
    print(json.dumps({'fixtures': len(matrix['fixtures']), 'unique_raw_transactions': len(raw_transactions),
                      'unique_two_leaf_proofs': len(proofs), 'failures': []}))


if __name__ == '__main__':
    main()
