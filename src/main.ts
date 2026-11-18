#!/usr/bin/env node
// btc-block-audit: checks Bitcoin mainnet blocks from their raw bytes, as an Esplora API serves
// them: header hash and proof of work, the chain, the merkle root, the witness commitment, weight,
// the BIP34 height and median time past. Exits 1 if a block fails a check, 2 if it couldn't check.

import { parseArgs } from "node:util";

import { audit, collect, collectRetargets, describe, exitCode, retargets } from "./audit.ts";
import { Esplora } from "./esplora.ts";

const USAGE = "usage: btc-block-audit [--api URL] [--blocks N] [--to HEIGHT] [--retarget N] [--json]";

async function main(): Promise<number> {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        api: { type: "string", default: "https://mempool.space/api" },
        blocks: { type: "string", default: "3" },
        to: { type: "string" },
        retarget: { type: "string", default: "0" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    }));
  } catch (error) {
    console.error(`${(error as Error).message}\n${USAGE}`);
    return 2;
  }
  const blocks = Number(values.blocks);
  const to = values.to === undefined ? undefined : Number(values.to);
  const retarget = Number(values.retarget);
  if (values.help) {
    console.error(USAGE);
    return 0;
  }
  if (!Number.isInteger(blocks) || blocks < 1 || blocks > 100) {
    console.error(`--blocks must be 1 to 100: ${values.blocks}\n${USAGE}`);
    return 2;
  }
  if (to !== undefined && (!/^\d+$/.test(values.to!) || !Number.isSafeInteger(to))) {
    console.error(`--to must be a block height: ${values.to}\n${USAGE}`);
    return 2;
  }
  if (!Number.isInteger(retarget) || retarget < 0 || retarget > 50) {
    console.error(`--retarget must be 0 to 50: ${values.retarget}\n${USAGE}`);
    return 2;
  }
  try {
    const api = new Esplora(values.api);
    const collected = await collect(api, blocks, to);
    const report = audit(collected);
    if (retarget) report.adjustments = retargets(await collectRetargets(api, retarget, collected.last), retarget, collected.last);
    console.log(values.json ? JSON.stringify(report, null, 2) : describe(report));
    return exitCode(report);
  } catch (error) {
    console.error(`btc-block-audit: ${(error as Error).message}`);
    return 2;
  }
}

// Not process.exit(): it can trip a libuv assertion on Windows.
process.exitCode = await main();
