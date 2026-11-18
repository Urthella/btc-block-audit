// Runs the real CLI against a fake Esplora API serving the saved blocks, which can be told to
// misbehave.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

import { GENESIS } from "../src/bitcoin.ts";
import type { BlockInfo } from "../src/esplora.ts";

const MAIN = fileURLToPath(new URL("../src/main.ts", import.meta.url));
const infos = new Map<number, BlockInfo>();
const raws = new Map<string, Buffer>();
for (const name of ["recent", "old", "genesis"]) {
  const f = JSON.parse(gunzipSync(readFileSync(new URL(`fixtures/${name}.json.gz`, import.meta.url))).toString());
  for (const b of f.blocks as BlockInfo[]) infos.set(b.height, b);
  for (const [h, b64] of Object.entries(f.raw as Record<string, string>)) raws.set(infos.get(Number(h))!.id, Buffer.from(b64, "base64"));
}
for (const b of JSON.parse(gunzipSync(readFileSync(new URL("fixtures/retargets.json.gz", import.meta.url))).toString()) as BlockInfo[]) infos.set(b.height, b);
const TIP = 976_387;

let rateLimits = 0;
let flipNonce: number | undefined;
let genesis = GENESIS;

const server = createServer((request, response) => {
  const send = (status: number, body: string | Buffer) => response.writeHead(status).end(body);
  if (rateLimits > 0) {
    rateLimits--;
    return send(429, "Too Many Requests");
  }
  const url = request.url!;
  let m: RegExpMatchArray | null;
  if (url === "/api/block-height/0") return send(200, genesis);
  if (url === "/api/blocks/tip/height") return send(200, String(TIP));
  if ((m = url.match(/^\/api\/blocks\/(\d+)$/))) {
    const page = [];
    for (let h = Number(m[1]); h > Number(m[1]) - 10; h--) if (infos.has(h)) page.push(infos.get(h));
    return send(200, JSON.stringify(page));
  }
  if ((m = url.match(/^\/api\/block\/([0-9a-f]{64})\/raw$/)) && raws.has(m[1])) {
    const raw = Buffer.from(raws.get(m[1])!);
    if (infos.get(flipNonce ?? -1)?.id === m[1]) raw[76] ^= 1;
    return send(200, raw);
  }
  send(404, "Not Found");
});
await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
server.unref();
const API = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;

function run(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [MAIN, "--api", API, ...args], (error, stdout, stderr) => resolve({ code: error ? Number(error.code) : 0, stdout, stderr }));
  });
}

test("audits the newest blocks, exit 0", async () => {
  const { code, stdout, stderr } = await run("--blocks", "2");
  assert.equal(code, 0, stderr);
  assert.match(stdout, /^2 blocks, 976,386 to 976,387: 4,149 transactions, the heaviest 3,997,605 weight units\n/);
  assert.match(stdout, /check: the merkle root of its transaction IDs matches the header: 2 of 2\n/);
  assert.match(stdout, /check: its time is after the median of the 11 blocks before it: 2 of 2\n/);
  assert.match(stdout, /coinbase: 3\.125 BTC of new coins a block/);
});

test("--to audits older blocks, and says which rules don't apply to them", async () => {
  const { code, stdout, stderr } = await run("--to", "100800", "--blocks", "2");
  assert.equal(code, 0, stderr);
  assert.match(stdout, /check: the coinbase starts with the block's height \(BIP34\): 0 of 0 \(2 not subject to it\)/);
  assert.match(stdout, /block 100,800 starts a retarget period, so its new bits aren't checked here; --retarget checks them/);
});

test("--retarget checks the last difficulty adjustments", async () => {
  const { code, stdout, stderr } = await run("--blocks", "2", "--retarget", "3");
  assert.equal(code, 0, stderr);
  const lines = stdout.split("\n").filter((l) => l.includes("retarget at block"));
  assert.deepEqual(lines.map((l) => l.match(/block ([\d,]+)/)![1]), ["975,744", "973,728", "971,712"]);
  for (const l of lines) assert.match(l, /the period before took \d+ days \d+ hours, against two weeks, so difficulty (rose|fell) \d+\.\d\d%: bits [0-9a-f]{8}, as the formula gives$/);
  assert.match(lines[0], /difficulty fell .*bits 17021673/);
});

test("--json prints the report", async () => {
  const { code, stdout } = await run("--to", "0", "--blocks", "1", "--json");
  assert.equal(code, 0);
  const report = JSON.parse(stdout);
  assert.equal(report.first, 0);
  assert.deepEqual(report.checks.pow, { passed: 1, applies: 1 });
  assert.equal(report.subsidy, "5000000000");
});

test("a block whose bytes don't hash to its ID exits 1 and names it", async () => {
  flipNonce = TIP;
  try {
    const { code, stdout } = await run("--blocks", "2");
    assert.equal(code, 1, stdout);
    assert.match(stdout, /check: the header hashes to the ID the API gave: 1 of 2\n    block 976,387: the header hashes to [0-9a-f]{64}, not 0{19}173d451c/);
  } finally {
    flipNonce = undefined;
  }
});

test("an API that rate-limits is asked again", async () => {
  rateLimits = 2;
  const { code, stderr } = await run("--to", "0", "--blocks", "1");
  assert.equal(code, 0, stderr);
  assert.equal(rateLimits, 0);
});

test("another chain's API exits 2: this checks mainnet's rules", async () => {
  genesis = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"; // testnet4
  try {
    const { code, stderr } = await run("--blocks", "1");
    assert.equal(code, 2);
    assert.match(stderr, /this checks mainnet's rules, and the API's genesis block is 00000000da84/);
  } finally {
    genesis = GENESIS;
  }
});

test("bad arguments and an unreachable API exit 2", async () => {
  for (const args of [["--blocks", "0"], ["--blocks", "101"], ["--blocks", "some"], ["--to", "-1"], ["--to", "tip"], ["--retarget", "51"], ["--retarget", "1.5"]]) {
    const bad = await run(...args);
    assert.equal(bad.code, 2, `${args}: ${bad.stderr}`);
    assert.match(bad.stderr, /usage: btc-block-audit/);
  }
  const missing = await run("--to", "500000", "--blocks", "1");
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /the API listed no block 499989/, "the first of the 11 blocks before");
  const closed = await new Promise<number>((resolve) => execFile(process.execPath, [MAIN, "--api", "http://127.0.0.1:1"], (error) => resolve(error ? Number(error.code) : 0)));
  assert.equal(closed, 2);
});
