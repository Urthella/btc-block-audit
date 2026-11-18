// A small client for the Esplora HTTP API that mempool.space and blockstream.info serve.

const ATTEMPTS = 4;
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

/** A block as Esplora's /blocks list describes it: enough to rebuild its header. */
export interface BlockInfo {
  id: string;
  height: number;
  version: number;
  timestamp: number;
  bits: number;
  nonce: number;
  merkle_root: string;
  previousblockhash: string | null;
}

export class Esplora {
  readonly base: string;
  constructor(base: string) {
    this.base = base.replace(/\/+$/, "");
  }

  private async get(path: string): Promise<Response> {
    for (let attempt = 1; ; attempt++) {
      const response = await fetch(`${this.base}${path}`, { headers: { "user-agent": "btc-block-audit" }, signal: AbortSignal.timeout(60_000) });
      // Public instances answer bursts with 429; wait and ask again.
      if ((response.status === 429 || response.status >= 500) && attempt < ATTEMPTS) {
        await response.body?.cancel();
        await sleep(1000 * attempt);
        continue;
      }
      if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
      return response;
    }
  }

  text = async (path: string) => (await (await this.get(path)).text()).trim();
  json = async <T>(path: string) => (await (await this.get(path)).json()) as T;
  bytes = async (path: string) => Buffer.from(await (await this.get(path)).arrayBuffer());
}
