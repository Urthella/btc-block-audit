// Bitcoin's block format and the consensus rules a block's own bytes can be checked against:
// header hash and proof of work, transaction IDs and the merkle root, the SegWit witness
// commitment, weight, and the BIP34 height in the coinbase.

import { createHash } from "node:crypto";

export const sha256d = (data: Uint8Array): Buffer => createHash("sha256").update(createHash("sha256").update(data).digest()).digest();

/** Bitcoin prints hashes byte-reversed; these convert between that and the order in the bytes. */
export const display = (hash: Uint8Array) => Buffer.from(hash).reverse().toString("hex");
export const internal = (hex: string) => Buffer.from(hex, "hex").reverse();

export const GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
/** The easiest target mainnet allows: bits 0x1d00ffff. */
export const POW_LIMIT = 0xffffn << 208n;
export const MAX_WEIGHT = 4_000_000;
/** Mainnet enforced BIP34 from this block on. */
export const BIP34_HEIGHT = 227_931;

export interface Header {
  version: number;
  prev: Buffer;
  merkleRoot: Buffer;
  time: number;
  bits: number;
  nonce: number;
  hash: Buffer;
}

export function parseHeader(raw: Buffer): Header {
  if (raw.length < 80) throw new Error(`a header is 80 bytes, not ${raw.length}`);
  const h = raw.subarray(0, 80);
  return { version: h.readUInt32LE(0), prev: h.subarray(4, 36), merkleRoot: h.subarray(36, 68), time: h.readUInt32LE(68), bits: h.readUInt32LE(72), nonce: h.readUInt32LE(76), hash: sha256d(h) };
}

/** The target that compact `bits` encode, or 0 for an encoding no valid block uses. */
export function target(bits: number): bigint {
  if (bits & 0x00800000) return 0n; // the sign bit: a negative target
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x007fffff);
  return exponent <= 3 ? mantissa >> BigInt(8 * (3 - exponent)) : mantissa << BigInt(8 * (exponent - 3));
}

/** The compact bits Bitcoin Core's GetCompact gives a target: three bytes of mantissa, one of size. */
export function compact(t: bigint): number {
  let size = t === 0n ? 0 : Math.ceil(t.toString(2).length / 8);
  let mantissa = Number(size <= 3 ? t << BigInt(8 * (3 - size)) : t >> BigInt(8 * (size - 3)));
  // A mantissa with its top bit set would read as negative: move a byte into the size.
  if (mantissa & 0x00800000) {
    mantissa >>= 8;
    size++;
  }
  return ((size << 24) | mantissa) >>> 0;
}

/** Two weeks: what a retarget period of 2,016 blocks should take. */
export const TARGET_TIMESPAN = 14 * 24 * 60 * 60;

/**
 * Bitcoin Core's CalculateNextWorkRequired. The timespan runs from the period's first block's time
 * to its last's, 2,015 intervals rather than 2,016, and is clamped to between a quarter and four
 * times two weeks; the new target scales the last one by it, no easier than mainnet's limit.
 */
export function nextBits(lastBits: number, firstTime: number, lastTime: number): number {
  const timespan = Math.min(Math.max(lastTime - firstTime, TARGET_TIMESPAN / 4), TARGET_TIMESPAN * 4);
  let next = (target(lastBits) * BigInt(timespan)) / BigInt(TARGET_TIMESPAN);
  if (next > POW_LIMIT) next = POW_LIMIT;
  return compact(next);
}

/** A block hash as the number proof of work compares with the target. */
export const hashValue = (hash: Uint8Array) => BigInt(`0x${display(hash)}`);

class Reader {
  buf: Buffer;
  pos: number;
  constructor(buf: Buffer, pos = 0) {
    this.buf = buf;
    this.pos = pos;
  }
  take(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error(`the block ends ${this.pos + n - this.buf.length} bytes early`);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u32 = () => this.take(4).readUInt32LE(0);
  varint(): number {
    const first = this.take(1)[0];
    if (first < 0xfd) return first;
    if (first === 0xfd) return this.take(2).readUInt16LE(0);
    if (first === 0xfe) return this.u32();
    const n = this.take(8).readBigUInt64LE(0);
    if (n > BigInt(this.buf.length)) throw new Error(`a count of ${n} can't fit in the block`);
    return Number(n);
  }
  bytes = () => this.take(this.varint());
}

export interface Input {
  prevTxid: Buffer;
  vout: number;
  scriptSig: Buffer;
  sequence: number;
  witness: Buffer[];
}

export interface Tx {
  /** Internal byte order, as the merkle tree uses them. */
  txid: Buffer;
  wtxid: Buffer;
  inputs: Input[];
  outputs: { value: bigint; script: Buffer }[];
  hasWitness: boolean;
  /** Bytes without the witness, and with it. Weight is 3 × base + total. */
  baseSize: number;
  totalSize: number;
}

function parseTx(r: Reader): Tx {
  const start = r.pos;
  r.take(4); // version
  const hasWitness = r.buf[r.pos] === 0x00;
  if (hasWitness) {
    const [, flag] = r.take(2);
    if (flag !== 0x01) throw new Error(`a transaction with witness flag ${flag}`);
  }
  const bodyStart = r.pos;
  const inputs: Input[] = [];
  for (let i = r.varint(); i > 0; i--) inputs.push({ prevTxid: r.take(32), vout: r.u32(), scriptSig: r.bytes(), sequence: r.u32(), witness: [] });
  const outputs: Tx["outputs"] = [];
  for (let i = r.varint(); i > 0; i--) outputs.push({ value: r.take(8).readBigUInt64LE(0), script: r.bytes() });
  const bodyEnd = r.pos;
  if (hasWitness) for (const input of inputs) for (let i = r.varint(); i > 0; i--) input.witness.push(r.bytes());
  const lockTime = r.take(4);
  const whole = r.buf.subarray(start, r.pos);
  // The txid leaves the marker, flag and witnesses out; the wtxid hashes everything.
  const base = hasWitness ? Buffer.concat([r.buf.subarray(start, start + 4), r.buf.subarray(bodyStart, bodyEnd), lockTime]) : whole;
  return { txid: sha256d(base), wtxid: sha256d(whole), inputs, outputs, hasWitness, baseSize: base.length, totalSize: whole.length };
}

export interface Block {
  header: Header;
  txs: Tx[];
  weight: number;
}

export function parseBlock(raw: Buffer): Block {
  const header = parseHeader(raw);
  const r = new Reader(raw, 80);
  const txs: Tx[] = [];
  for (let i = r.varint(); i > 0; i--) txs.push(parseTx(r));
  if (r.pos !== raw.length) throw new Error(`${raw.length - r.pos} bytes after the last transaction`);
  const countSize = r.pos - 80 - txs.reduce((n, t) => n + t.totalSize, 0);
  // The header and transaction count carry no witness data: 4 weight units a byte.
  const weight = (80 + countSize) * 4 + txs.reduce((w, t) => w + t.baseSize * 3 + t.totalSize, 0);
  return { header, txs, weight };
}

/** Bitcoin's merkle tree: an odd level pairs its last hash with itself. */
export function merkleRoot(hashes: Buffer[]): Buffer {
  if (!hashes.length) throw new Error("a merkle tree of nothing");
  let level = hashes;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]])));
    level = next;
  }
  return level[0];
}

export const isCoinbase = (tx: Tx) => tx.inputs.length === 1 && tx.inputs[0].vout === 0xffffffff && tx.inputs[0].prevTxid.every((b) => b === 0);

const COMMITMENT_PREFIX = Buffer.from("6a24aa21a9ed", "hex");

/** BIP141: the commitment is in the coinbase's last output whose script starts OP_RETURN 0xaa21a9ed. */
export function witnessCommitment(coinbase: Tx): Buffer | undefined {
  for (let i = coinbase.outputs.length - 1; i >= 0; i--) {
    const script = coinbase.outputs[i].script;
    if (script.length >= 38 && script.subarray(0, 6).equals(COMMITMENT_PREFIX)) return script.subarray(6, 38);
  }
  return undefined;
}

/** What the commitment should be: the witness merkle root, the coinbase's wtxid counted as zero, hashed with the coinbase's 32-byte witness. */
export function expectedCommitment(txs: Tx[]): Buffer | undefined {
  const reserved = txs[0].inputs[0]?.witness;
  if (reserved?.length !== 1 || reserved[0].length !== 32) return undefined;
  const root = merkleRoot([Buffer.alloc(32), ...txs.slice(1).map((t) => t.wtxid)]);
  return sha256d(Buffer.concat([root, reserved[0]]));
}

/** BIP34: the coinbase's scriptSig starts by pushing the height, as a minimal script number. */
export function heightPush(height: number): Buffer {
  const bytes: number[] = [];
  for (let h = height; h > 0; h = Math.floor(h / 256)) bytes.push(h % 256);
  if (bytes.length && bytes[bytes.length - 1] & 0x80) bytes.push(0); // keep it positive
  return Buffer.from([bytes.length, ...bytes]);
}

/** The new coins a block may create: 50 BTC, halved every 210,000 blocks. */
export function subsidy(height: number): bigint {
  const halvings = Math.floor(height / 210_000);
  return halvings >= 64 ? 0n : 5_000_000_000n >> BigInt(halvings);
}
