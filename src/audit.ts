// Audits a range of mainnet blocks from their raw bytes. The headers just before the range come
// from the API's block list: each is rebuilt from its fields and must hash to its ID and link to
// the next, so the first audited block's own header vouches for them, timestamps included.

import { BIP34_HEIGHT, GENESIS, MAX_WEIGHT, POW_LIMIT, display, expectedCommitment, hashValue, heightPush, internal, isCoinbase, merkleRoot, parseBlock, parseHeader, subsidy, target, witnessCommitment } from "./bitcoin.ts";
import type { BlockInfo, Esplora } from "./esplora.ts";

/** Median time past looks at the 11 blocks before. */
const MTP_SPAN = 11;
const RETARGET_INTERVAL = 2016;
/** BIP141's witness commitment rules apply from here on. */
const SEGWIT_HEIGHT = 481_824;

export interface Collected {
  first: number;
  last: number;
  /** Ascending, from up to 11 blocks before `first` to `last`. */
  blocks: BlockInfo[];
  raw: Map<number, Buffer>;
}

export async function collect(api: Esplora, count: number, to?: number): Promise<Collected> {
  const genesis = await api.text("/block-height/0");
  if (genesis !== GENESIS) throw new Error(`this checks mainnet's rules, and the API's genesis block is ${genesis}`);
  const last = to ?? Number(await api.text("/blocks/tip/height"));
  const first = Math.max(0, last - count + 1);
  const lo = Math.max(0, first - MTP_SPAN);
  const byHeight = new Map<number, BlockInfo>();
  // Each page lists ten blocks, from the height asked for down.
  for (let h = last; h >= lo; h -= 10) for (const b of await api.json<BlockInfo[]>(`/blocks/${h}`)) byHeight.set(b.height, b);
  const blocks: BlockInfo[] = [];
  for (let h = lo; h <= last; h++) {
    const b = byHeight.get(h);
    if (!b) throw new Error(`the API listed no block ${h}`);
    blocks.push(b);
  }
  const raw = new Map<number, Buffer>();
  for (const b of blocks) if (b.height >= first) raw.set(b.height, await api.bytes(`/block/${b.id}/raw`));
  return { first, last, blocks, raw };
}

/** A header rebuilt from the fields the API lists. */
export function headerBytes(b: BlockInfo): Buffer {
  const out = Buffer.alloc(80);
  out.writeUInt32LE(b.version >>> 0, 0);
  internal(b.previousblockhash ?? "00".repeat(32)).copy(out, 4);
  internal(b.merkle_root).copy(out, 36);
  out.writeUInt32LE(b.timestamp, 68);
  out.writeUInt32LE(b.bits, 72);
  out.writeUInt32LE(b.nonce, 76);
  return out;
}

export const CHECKS = {
  id: "the header hashes to the ID the API gave",
  pow: "the hash meets the target its bits set",
  chain: "it builds on the block before it",
  coinbase: "it has one coinbase, and it comes first",
  merkle: "the merkle root of its transaction IDs matches the header",
  witness: "the witness commitment matches its transactions' witnesses",
  weight: "its weight is at most 4,000,000",
  bip34: "the coinbase starts with the block's height (BIP34)",
  mtp: "its time is after the median of the 11 blocks before it",
  bits: "its difficulty bits are the block before's, inside a retarget period",
} as const;
export type Check = keyof typeof CHECKS;

export interface Report {
  first: number;
  last: number;
  transactions: number;
  maxWeight: number;
  checks: Record<Check, { passed: number; applies: number }>;
  failures: { height: number; check: Check; detail: string }[];
  /** Audited blocks that start a retarget period, where the bits may change. */
  retargets: number[];
  /** The newest block's subsidy, and what the coinbases claimed beyond theirs. */
  subsidy: string;
  medianFees: string;
}

const hex = (b: Buffer) => b.toString("hex");

export function audit({ first, last, blocks, raw }: Collected): Report {
  const checks = Object.fromEntries(Object.keys(CHECKS).map((k) => [k, { passed: 0, applies: 0 }])) as Report["checks"];
  const report: Report = { first, last, transactions: 0, maxWeight: 0, checks, failures: [], retargets: [], subsidy: "0", medianFees: "0" };
  const record = (height: number, check: Check, ok: boolean, detail: () => string) => {
    checks[check].applies++;
    if (ok) checks[check].passed++;
    else report.failures.push({ height, check, detail: detail() });
  };
  /** Headers this has verified, by height. */
  const known = new Map<number, { hash: Buffer; time: number; bits: number }>();
  const fees: bigint[] = [];

  for (const info of blocks) {
    const h = info.height;
    if (h < first) {
      const header = parseHeader(headerBytes(info));
      const prev = known.get(h - 1);
      if (display(header.hash) !== info.id || (prev && !header.prev.equals(prev.hash))) throw new Error(`the API's fields for block ${h} don't hash to its ID or don't link to block ${h - 1}`);
      known.set(h, { hash: header.hash, time: header.time, bits: header.bits });
      continue;
    }
    let block;
    try {
      block = parseBlock(raw.get(h)!);
    } catch (error) {
      throw new Error(`block ${h} doesn't parse: ${(error as Error).message}`);
    }
    const { header, txs } = block;
    report.transactions += txs.length;
    report.maxWeight = Math.max(report.maxWeight, block.weight);

    record(h, "id", display(header.hash) === info.id, () => `the header hashes to ${display(header.hash)}, not ${info.id}`);
    const t = target(header.bits);
    record(h, "pow", t > 0n && t <= POW_LIMIT && hashValue(header.hash) <= t, () => `hash ${display(header.hash)} isn't at or under target ${t.toString(16).padStart(64, "0")}`);
    const prev = known.get(h - 1);
    if (h > 0) record(h, "chain", !!prev && header.prev.equals(prev.hash), () => `it builds on ${display(header.prev)}, not ${prev ? display(prev.hash) : "a block this saw"}`);

    const coinbases = txs.filter(isCoinbase).length;
    record(h, "coinbase", txs.length > 0 && isCoinbase(txs[0]) && coinbases === 1, () => `${coinbases} coinbase transactions, the first ${txs.length && isCoinbase(txs[0]) ? "first" : "not first"}`);
    const txids = txs.map((t) => t.txid);
    // CVE-2012-2459: a repeated transaction can give the same root as a valid block.
    const unique = new Set(txids.map(hex)).size === txids.length;
    const root = txids.length ? merkleRoot(txids) : Buffer.alloc(32);
    record(h, "merkle", unique && root.equals(header.merkleRoot), () => (unique ? `its transaction IDs give root ${display(root)}, the header has ${display(header.merkleRoot)}` : "two transactions share an ID"));

    if (h >= SEGWIT_HEIGHT && txs.length) {
      const committed = witnessCommitment(txs[0]);
      if (committed) {
        const expected = expectedCommitment(txs);
        record(h, "witness", !!expected && committed.equals(expected), () => (expected ? `it commits to ${hex(committed)}, its witnesses give ${hex(expected)}` : "the coinbase's witness isn't one 32-byte value"));
      } else if (txs.some((t) => t.hasWitness)) {
        record(h, "witness", false, () => "it has witness data and no commitment to it");
      }
    }
    record(h, "weight", block.weight <= MAX_WEIGHT, () => `its weight is ${block.weight.toLocaleString("en-US")}`);
    if (h >= BIP34_HEIGHT) {
      const push = heightPush(h);
      const sig = txs[0]?.inputs[0]?.scriptSig ?? Buffer.alloc(0);
      record(h, "bip34", sig.subarray(0, push.length).equals(push), () => `the coinbase starts ${hex(sig.subarray(0, push.length))}, not ${hex(push)}`);
    }

    const times: number[] = [];
    for (let k = 1; k <= MTP_SPAN && known.has(h - k); k++) times.push(known.get(h - k)!.time);
    if (times.length) {
      const median = times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
      record(h, "mtp", header.time > median, () => `its time ${header.time} isn't after ${median}, the median of the ${times.length} before it`);
    }
    if (h > 0) {
      if (h % RETARGET_INTERVAL === 0) report.retargets.push(h);
      else record(h, "bits", !!prev && header.bits === prev.bits, () => `its bits are ${header.bits.toString(16)}, the block before's ${prev?.bits.toString(16)}`);
    }

    known.set(h, { hash: header.hash, time: header.time, bits: header.bits });
    const paid = txs[0]?.outputs.reduce((sum, o) => sum + o.value, 0n) ?? 0n;
    fees.push(paid - subsidy(h));
    report.subsidy = String(subsidy(h));
  }
  const sorted = fees.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  report.medianFees = String(sorted[Math.floor((sorted.length - 1) / 2)] ?? 0n);
  return report;
}

export const exitCode = (report: Report) => (report.failures.length ? 1 : 0);

const number = (n: number) => n.toLocaleString("en-US");
const btc = (sats: string) => (Number(sats) / 1e8).toLocaleString("en-US", { maximumFractionDigits: 8 });

export function describe(report: Report): string {
  const n = report.last - report.first + 1;
  const lines = [`${number(n)} blocks, ${number(report.first)} to ${number(report.last)}: ${number(report.transactions)} transactions, the heaviest ${number(report.maxWeight)} weight units`];
  for (const [name, text] of Object.entries(CHECKS) as [Check, string][]) {
    const { passed, applies } = report.checks[name];
    lines.push(`  check: ${text}: ${number(passed)} of ${number(applies)}${applies < n ? ` (${number(n - applies)} not subject to it)` : ""}`);
    for (const f of report.failures.filter((f) => f.check === name).slice(0, 5)) lines.push(`    block ${number(f.height)}: ${f.detail}`);
  }
  for (const h of report.retargets) lines.push(`  block ${number(h)} starts a retarget period, so its new bits aren't checked`);
  lines.push(`  coinbase: ${btc(report.subsidy)} BTC of new coins a block, and a median ${btc(report.medianFees)} BTC claimed in fees`);
  return lines.join("\n");
}
