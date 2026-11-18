// Saves the blocks the tests run against: two recent mainnet blocks (the second has an earlier
// timestamp than the first), two from 2010 across a retarget, and the genesis block, each with
// the headers before it. Run: node scripts/fetch-fixtures.ts

import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

import { collect } from "../src/audit.ts";
import { Esplora } from "../src/esplora.ts";

const api = new Esplora("https://mempool.space/api");
const ranges = { recent: { to: 976_387, count: 2 }, old: { to: 100_800, count: 2 }, genesis: { to: 0, count: 1 } };

for (const [name, { to, count }] of Object.entries(ranges)) {
  const { first, last, blocks, raw } = await collect(api, count, to);
  const fixture = { first, last, blocks, raw: Object.fromEntries([...raw].map(([h, b]) => [h, b.toString("base64")])) };
  const file = new URL(`../test/fixtures/${name}.json.gz`, import.meta.url);
  writeFileSync(file, gzipSync(JSON.stringify(fixture), { level: 9 }));
  console.log(`${name}: blocks ${first} to ${last}, ${blocks.length} headers`);
}
