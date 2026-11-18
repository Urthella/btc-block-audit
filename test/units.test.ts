import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

import { GENESIS, POW_LIMIT, display, hashValue, heightPush, merkleRoot, parseBlock, sha256d, subsidy, target } from "../src/bitcoin.ts";

const genesis = Buffer.from(JSON.parse(gunzipSync(readFileSync(new URL("fixtures/genesis.json.gz", import.meta.url))).toString()).raw["0"], "base64");

test("the genesis block parses to its well-known hash and merkle root", () => {
  const block = parseBlock(genesis);
  assert.equal(display(block.header.hash), GENESIS);
  assert.equal(display(block.header.merkleRoot), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
  assert.equal(display(block.txs[0].txid), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "one transaction: the root is its ID");
  assert.equal(block.txs[0].outputs[0].value, 5_000_000_000n);
  assert.equal(block.weight, 285 * 4, "no witness data: 4 weight units a byte");
  assert.ok(hashValue(block.header.hash) <= target(block.header.bits));
});

test("compact bits decode to targets", () => {
  assert.equal(target(0x1d00ffff), POW_LIMIT);
  assert.equal(target(0x1d00ffff), 0x00000000ffff0000000000000000000000000000000000000000000000000000n);
  assert.equal(target(0x17021673), 0x021673n << 160n);
  assert.equal(target(0x03123456), 0x123456n);
  assert.equal(target(0x02123456), 0x1234n, "a small exponent shifts the mantissa right");
  assert.equal(target(0x1d80ffff), 0n, "the sign bit makes a negative target, which no block can meet");
});

test("an odd merkle level pairs its last hash with itself", () => {
  const [a, b, c] = ["a", "b", "c"].map((s) => sha256d(Buffer.from(s)));
  const pair = (x: Buffer, y: Buffer) => sha256d(Buffer.concat([x, y]));
  assert.deepEqual(merkleRoot([a]), a);
  assert.deepEqual(merkleRoot([a, b]), pair(a, b));
  assert.deepEqual(merkleRoot([a, b, c]), pair(pair(a, b), pair(c, c)));
  assert.deepEqual(merkleRoot([a, b, c, c]), merkleRoot([a, b, c]), "CVE-2012-2459: repeating the last gives the same root");
});

test("BIP34 heights push as minimal script numbers", () => {
  assert.equal(heightPush(976_387).toString("hex"), "0303e60e");
  assert.equal(heightPush(227_931).toString("hex"), "035b7a03");
  assert.equal(heightPush(255).toString("hex"), "02ff00", "a top bit set takes a zero byte, to stay positive");
  assert.equal(heightPush(0x8000).toString("hex"), "03008000");
  assert.equal(heightPush(16).toString("hex"), "0110");
});

test("the subsidy halves every 210,000 blocks, to nothing", () => {
  assert.equal(subsidy(0), 5_000_000_000n);
  assert.equal(subsidy(209_999), 5_000_000_000n);
  assert.equal(subsidy(210_000), 2_500_000_000n);
  assert.equal(subsidy(840_000), 312_500_000n);
  assert.equal(subsidy(1_050_000), 156_250_000n);
  assert.equal(subsidy(64 * 210_000), 0n);
});
