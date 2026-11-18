# btc-block-audit

Checks Bitcoin mainnet blocks from their raw bytes, as a public Esplora API serves them
(mempool.space by default), against the consensus rules those bytes can prove:

- **proof of work:** the header hashes to the block's ID, and the hash meets the target its bits
  set;
- **the chain:** each block builds on the one before it, and keeps its difficulty bits inside a
  retarget period;
- **the transactions:** exactly one coinbase, first; the merkle root of the transaction IDs
  matches the header, with no repeated transaction (CVE-2012-2459);
- **SegWit:** the coinbase's witness commitment matches the witness merkle root, and the weight is
  at most 4,000,000;
- **BIP34:** the coinbase starts with the block's height;
- **time:** the timestamp is after the median of the 11 blocks before it.

It exits 1 if a block fails a check.

## Why

A block explorer tells you what a block contains. Its raw bytes are enough to check much of that
yourself, without a node: a header that meets its target can't be forged, and it commits to every
transaction through the merkle root.

`btc-block-audit` does that check, and shows how the rules really work:

- **Clocks may go backwards:** block 976,387's timestamp is 3½ minutes earlier than 976,386's.
  That's allowed: the rule is only that it's after the median of the 11 blocks before it.
- **The merkle tree has a flaw:** repeating the last of an odd number of transactions gives the
  same root, so a valid header can describe an invalid block. The tests build such a block from
  block 976,386.
- **SegWit switched on at a retarget:** auditing blocks 481,814 to 481,833, the witness
  commitment check applies from block 481,824 on. BIP9 deployments activate at the start of a
  retarget period.

## Quick start

Needs Node 24 or later, and nothing else.

```sh
git clone https://github.com/Urthella/btc-block-audit && cd btc-block-audit
node src/main.ts --blocks 20
```

```text
20 blocks, 976,369 to 976,388: 72,841 transactions, the heaviest 3,997,838 weight units
  check: the header hashes to the ID the API gave: 20 of 20
  check: the hash meets the target its bits set: 20 of 20
  check: it builds on the block before it: 20 of 20
  check: it has one coinbase, and it comes first: 20 of 20
  check: the merkle root of its transaction IDs matches the header: 20 of 20
  check: the witness commitment matches its transactions' witnesses: 20 of 20
  check: its weight is at most 4,000,000: 20 of 20
  check: the coinbase starts with the block's height (BIP34): 20 of 20
  check: its time is after the median of the 11 blocks before it: 20 of 20
  check: its difficulty bits are the block before's, inside a retarget period: 20 of 20
  coinbase: 3.125 BTC of new coins a block, and a median 0.01999473 BTC claimed in fees
```

- `--api URL` picks the Esplora API: `https://mempool.space/api` by default;
  `https://blockstream.info/api` works too.
- `--blocks N` sets how many blocks to audit: 3 by default, up to 100. Each is downloaded whole,
  about 1.5 MB today.
- `--to HEIGHT` audits the blocks up to that height instead of up to the tip. A rule that didn't
  apply yet, like BIP34 before block 227,931, is counted as such.
- `--json` prints the report as JSON.

Exit codes: 0 when every block passes, 1 when one fails a check, and 2 when it couldn't check:
an API that isn't mainnet's, bytes that don't parse, or bad arguments.

## What it does

- **Reads the blocks' headers** from the API's block list, starting 11 before the first audited
  block. Each header is rebuilt from the listed fields and must hash to its block's ID and link to
  the next, so the first audited block's own header vouches for them, timestamps included. The
  API must also serve mainnet's genesis block.
- **Downloads each audited block whole**, parses every transaction, and computes the transaction
  IDs without the witness data, the witness IDs with it, and the weight: 3 × the bytes without the
  witnesses, plus all of them.
- **Checks the rules above.** The witness commitment is the one in the coinbase's last output
  that starts `OP_RETURN 0xaa21a9ed`; it must equal the double SHA-256 of the witness merkle root,
  the coinbase counted as zero, and the coinbase's 32-byte witness.
- **Reports the coinbase:** the block's subsidy, halved every 210,000 blocks, and the median of
  what the coinbases claimed beyond it, the fees the miners took.

## How it's checked

- **The building blocks:**
  - the genesis block parses to its well-known hash and merkle root;
  - compact bits decode to the right targets, the sign bit and small exponents included;
  - an odd merkle level pairs its last hash with itself, and repeating the last hash keeps the
    root;
  - BIP34 heights push as minimal script numbers;
  - the subsidy halves every 210,000 blocks.
- **Real blocks**, saved by [`scripts/fetch-fixtures.ts`](scripts/fetch-fixtures.ts): blocks
  976,386 and 976,387, blocks 100,799 and 100,800 from 2010, and the genesis block, each with the
  headers before it.
  - All of them pass, and the weight matches the one mempool.space lists.
  - Then they're broken one rule at a time: a changed nonce, an output, a witness, the coinbase's
    height, a repeated transaction, one transaction too many, a second coinbase, a timestamp at
    the median, changed bits, bits easier than mainnet's limit, a missing witness commitment.
    Each fails the checks it should, and only those.
- **End to end:** the CLI runs against a fake Esplora API serving those blocks:
  - the newest blocks, and older ones by `--to`, are audited;
  - a block whose bytes don't hash to its ID exits 1;
  - a rate-limited API is asked again;
  - an API for another chain, bad arguments and an unreachable API exit 2.
- **Mutation testing:** twenty-nine deliberate bugs were planted one at a time, and the tests
  caught every one.
- **Live**, on 2026-11-18, every block passed:
  - mempool.space: the 20 newest, 976,369 to 976,388;
  - blockstream.info: the 10 newest;
  - SegWit's activation, blocks 481,814 to 481,833;
  - the genesis block.

## Limits

- **Only what the block's own bytes prove.** Spending rules need the outputs being spent:
  scripts, signatures, amounts, so the fees and the coinbase's cap aren't checked, and neither is
  BIP30.
- **Mainnet only.** Testnets let difficulty drop within a period and set BIP34 at other heights.
- **New difficulty isn't checked** at the start of a retarget period. The report names those
  blocks.
- **Downloads are whole blocks**, about 1.5 MB each, which is why `--blocks` stops at 100.

## License

MIT
