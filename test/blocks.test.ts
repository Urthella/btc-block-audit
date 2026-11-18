// Audits the saved mainnet blocks, then breaks them one rule at a time.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

import { type Check, type Collected, audit } from "../src/audit.ts";
import { parseBlock } from "../src/bitcoin.ts";

function load(name: string): Collected {
  const f = JSON.parse(gunzipSync(readFileSync(new URL(`fixtures/${name}.json.gz`, import.meta.url))).toString());
  return { first: f.first, last: f.last, blocks: f.blocks, raw: new Map(Object.entries(f.raw as Record<string, string>).map(([h, b]) => [Number(h), Buffer.from(b, "base64")])) };
}

/** The fixture with one block's bytes changed by `change`, which gets a private copy and its parse. */
function tampered(name: string, height: number, change: (raw: Buffer, block: ReturnType<typeof parseBlock>) => Buffer | void): Collected {
  const c = load(name);
  const raw = Buffer.from(c.raw.get(height)!);
  c.raw.set(height, change(raw, parseBlock(raw)) ?? raw);
  return c;
}

const failed = (c: Collected) => audit(c).failures.map((f) => `${f.height} ${f.check}`).sort();
const all = (applies: number) => ({ passed: applies, applies });

test("two recent blocks pass every check, though the second's clock is behind the first's", () => {
  const c = load("recent");
  const [a, b] = [976_386, 976_387].map((h) => parseBlock(c.raw.get(h)!).header.time);
  assert.ok(b < a, "the fixture's point: timestamps may go backwards, as long as they pass median time past");
  const report = audit(c);
  assert.deepEqual(report.failures, []);
  for (const check of ["id", "pow", "chain", "coinbase", "merkle", "witness", "weight", "bip34", "mtp", "bits"] as Check[]) assert.deepEqual(report.checks[check], all(2), check);
  assert.equal(report.transactions, 2721 + 1428);
  assert.equal(report.maxWeight, 3_997_605, "mempool.space lists the same weight");
  assert.equal(report.subsidy, "312500000");
});

test("2010's blocks have no BIP34 height or witnesses, and one starts a retarget period", () => {
  const report = audit(load("old"));
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.checks.bip34, all(0));
  assert.deepEqual(report.checks.witness, all(0));
  assert.deepEqual(report.checks.bits, all(1));
  assert.deepEqual(report.retargets, [100_800]);
  assert.equal(report.medianFees, "0");
});

test("the genesis block builds on nothing", () => {
  const report = audit(load("genesis"));
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.checks.chain, all(0));
  assert.deepEqual(report.checks.mtp, all(0));
  assert.deepEqual(report.checks.id, all(1));
  assert.equal(report.subsidy, "5000000000");
});

test("a changed nonce breaks the ID, the proof of work and the next block's link", () => {
  const c = tampered("recent", 976_386, (raw) => {
    raw[76] ^= 1;
  });
  assert.deepEqual(failed(c), ["976386 id", "976386 pow", "976387 chain"]);
});

test("a changed output breaks the merkle root and the witness commitment", () => {
  const c = tampered("recent", 976_387, (_, block) => {
    block.txs[5].outputs[0].script[0] ^= 1;
  });
  assert.deepEqual(failed(c), ["976387 merkle", "976387 witness"]);
});

test("a changed witness breaks only the witness commitment", () => {
  const c = tampered("recent", 976_387, (_, block) => {
    const input = block.txs.slice(1).flatMap((t) => t.inputs).find((i) => i.witness[0]?.length)!;
    input.witness[0][0] ^= 1;
  });
  assert.deepEqual(failed(c), ["976387 witness"]);
});

test("a coinbase pushing the wrong height breaks BIP34, and the merkle root with it", () => {
  const c = tampered("recent", 976_387, (_, block) => {
    block.txs[0].inputs[0].scriptSig[1] ^= 1;
  });
  assert.deepEqual(failed(c), ["976387 bip34", "976387 merkle"]);
});

/** The block with a copy of transaction `index` added at the end; both fixtures' counts take three bytes. */
function withCopy(raw: Buffer, block: ReturnType<typeof parseBlock>, index: number): Buffer {
  assert.equal(raw[80], 0xfd);
  const start = 83 + block.txs.slice(0, index).reduce((n, t) => n + t.totalSize, 0);
  const out = Buffer.concat([raw, raw.subarray(start, start + block.txs[index].totalSize)]);
  out.writeUInt16LE(block.txs.length + 1, 81);
  return out;
}

test("CVE-2012-2459: repeating the last of an odd number of transactions keeps the root, and still fails", () => {
  const c = tampered("recent", 976_386, (raw, block) => withCopy(raw, block, block.txs.length - 1));
  const report = audit(c);
  assert.deepEqual(failed(c), ["976386 merkle"]);
  assert.equal(report.failures[0].detail, "two transactions share an ID");
});

test("one transaction too many takes a block past 4,000,000 weight units", () => {
  const c = tampered("recent", 976_387, (raw, block) => withCopy(raw, block, 1));
  assert.deepEqual(failed(c), ["976387 merkle", "976387 weight", "976387 witness"]);
});

test("a second coinbase fails", () => {
  const c = tampered("old", 100_799, (raw, block) => {
    const input = block.txs[1].inputs[0];
    input.prevTxid.fill(0);
    raw.writeUInt32LE(0xffffffff, input.prevTxid.byteOffset - raw.byteOffset + 32);
  });
  assert.ok(failed(c).includes("100799 coinbase"));
});

test("a time at the median of the 11 before fails median time past", () => {
  const c = load("recent");
  const times = c.blocks.filter((b) => b.height < 976_387 && b.height >= 976_376).map((b) => b.timestamp).sort((a, b) => a - b);
  const median = times[5];
  const raw = Buffer.from(c.raw.get(976_387)!);
  raw.writeUInt32LE(median, 68);
  c.raw.set(976_387, raw);
  assert.ok(failed(c).includes("976387 mtp"));
  raw.writeUInt32LE(median + 1, 68);
  assert.ok(!failed(c).includes("976387 mtp"), "one second later passes");
});

test("bits easier than mainnet's limit fail even though every hash meets them", () => {
  const c = tampered("recent", 976_387, (raw) => {
    raw.writeUInt32LE(0x2100ffff, 72); // a target of 0xffff × 2^240
  });
  assert.ok(failed(c).includes("976387 pow"));
});

test("witness data with no commitment to it fails", () => {
  const c = tampered("recent", 976_387, (_, block) => {
    for (const o of block.txs[0].outputs) if (o.script.subarray(0, 6).toString("hex") === "6a24aa21a9ed") o.script[0] = 0x6b;
  });
  assert.deepEqual(failed(c), ["976387 merkle", "976387 witness"]);
  assert.equal(audit(c).failures.find((f) => f.check === "witness")!.detail, "it has witness data and no commitment to it");
});

test("bits that change inside a retarget period fail", () => {
  const c = tampered("recent", 976_387, (raw) => {
    raw.writeUInt32LE(raw.readUInt32LE(72) + 1, 72);
  });
  assert.ok(failed(c).includes("976387 bits"));
});

test("API header fields that don't hash to their ID, and bytes that don't parse, can't be audited", () => {
  const c = load("recent");
  c.blocks[3] = { ...c.blocks[3], timestamp: c.blocks[3].timestamp + 1 };
  assert.throws(() => audit(c), /the API's fields for block 976378 don't hash to its ID/);
  const d = load("recent");
  d.raw.set(976_387, d.raw.get(976_387)!.subarray(0, 100_000));
  assert.throws(() => audit(d), /block 976387 doesn't parse: the block ends/);
});
