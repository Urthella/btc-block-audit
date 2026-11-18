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
- **time:** the timestamp is after the median of the 11 blocks before it;
- **difficulty**, with `--retarget`: each adjustment's new bits follow Bitcoin Core's formula.

It exits 1 if a block or an adjustment fails a check.

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
- **The difficulty formula is off by one:** it times 2,015 intervals between the period's first
  and last blocks, not 2,016. Timing 2,016 gets the chain's real bits wrong.
- **2009 ran at the minimum:** the first 15 adjustments, to block 30,240, all came out easier than
  mainnet allows, so the difficulty stayed at its floor until block 32,256 raised it 18.29%.

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
- `--retarget N` also checks the last N difficulty adjustments up to there, 0 by default, up to 50:

  ```text
  retarget at block 975,744: the period before took 15 days 9 hours, against two weeks, so difficulty fell 9.13%: bits 17021673, as the formula gives
  retarget at block 973,728: the period before took 13 days 6 hours, against two weeks, so difficulty rose 5.54%: bits 1701e5ac, as the formula gives
  ```

- `--json` prints the report as JSON.

Exit codes: 0 when every check passes, 1 when a block or an adjustment fails one, and 2 when it
couldn't check: an API that isn't mainnet's, bytes or headers that don't add up, or bad
arguments.

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
- **With `--retarget`, recomputes each adjustment** as Bitcoin Core's `CalculateNextWorkRequired`
  does. The old period's timespan, from its first block's time to its last's, is clamped to
  between a quarter and four times two weeks. The old target is scaled by it, capped at mainnet's
  easiest target, and encoded back to compact bits, which must equal the new period's. The three
  headers used must each hash to their ID and meet their own target. The new period's first must
  build on the old one's last, and the old period's first and last must share their bits.

## How it's checked

- **The building blocks:**
  - the genesis block parses to its well-known hash and merkle root;
  - compact bits decode to the right targets, the sign bit and small exponents included;
  - an odd merkle level pairs its last hash with itself, and repeating the last hash keeps the
    root;
  - BIP34 heights push as minimal script numbers;
  - the subsidy halves every 210,000 blocks;
  - targets encode back to compact bits, and the next target follows the timespan, clamped and
    capped.
- **Real blocks**, saved by [`scripts/fetch-fixtures.ts`](scripts/fetch-fixtures.ts): blocks
  976,386 and 976,387, blocks 100,799 and 100,800 from 2010, and the genesis block, each with the
  headers before it.
  - All of them pass, and the weight matches the one mempool.space lists.
  - Then they're broken one rule at a time: a changed nonce, an output, a witness, the coinbase's
    height, a repeated transaction, one transaction too many, a second coinbase, a timestamp at
    the median, changed bits, bits easier than mainnet's limit, a missing witness commitment.
    Each fails the checks it should, and only those.
- **Real adjustments:** the headers around the last three before block 976,387, the first, at
  block 2,016, and the first rise, at 32,256. All follow the formula, and `--retarget` refuses a
  forged header with no work, a real one from the wrong period, and one the next block doesn't
  build on.
- **End to end:** the CLI runs against a fake Esplora API serving those blocks:
  - the newest blocks, and older ones by `--to`, are audited;
  - `--retarget 3` checks the last three adjustments;
  - a block whose bytes don't hash to its ID exits 1;
  - a rate-limited API is asked again;
  - an API for another chain, bad arguments and an unreachable API exit 2.
- **Mutation testing:** thirty-nine deliberate bugs were planted one at a time, and the tests
  caught every one.
- **Live**, on 2026-11-18, every block and adjustment passed:
  - mempool.space: the 20 newest blocks, 976,369 to 976,388;
  - blockstream.info: the 10 newest;
  - SegWit's activation, blocks 481,814 to 481,833;
  - the genesis block;
  - the last 50 adjustments, back to block 876,960, and the first 16, to 32,256.

## Limits

- **Only what the block's own bytes prove.** Spending rules need the outputs being spent:
  scripts, signatures, amounts, so the fees and the coinbase's cap aren't checked, and neither is
  BIP30.
- **Mainnet only.** Testnets let difficulty drop within a period and set BIP34 at other heights.
- **`--retarget` doesn't fetch the 2,014 blocks between** an old period's first and last. It
  trusts the API's height index for the first, which must still hash to its ID, meet its target
  and carry its period's bits.
- **Downloads are whole blocks**, about 1.5 MB each, which is why `--blocks` stops at 100.

## License

MIT
