# Plumo Prover

Runs the Plumo light client prover. As a user, you must specify the Celo node
from which blocks headers and snark-friendly encodings will be downloaded from.
Plumo will download the data, get it in the format that the SNARK expects and then
run the prover. You must specify the proving key for the BLS snark in the BW6
curve, and optionally may specify another proving key on the BLS12-377 curve for the
CRH to XOF proof which can be used as an optimization.

## Build

```
cargo build --release
```

## Run the CLI

```
Usage: plumo [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL    the celo node's endpoint (default: http://localhost:8545)
  -e, --epoch-duration EPOCH-DURATION
                             the duration of an epoch (in blocks) (default: 17280)
  -s, --start-block START-BLOCK
                             the first block in the range being proven
  -E, --end-block END-BLOCK  the last block in the range being proven
  --epoch-proving-key EPOCH-PROVING-KEY
                             path to the proving key for the BLS SNARK
  -H, --hash-to-bits-proving-key HASH-TO-BITS-PROVING-KEY
                             path to the proving key for the CRH -> XOF SNARK
  -p, --proof-path PROOF-PATH
                             path where the proof will be saved at
  -N, --num-validators NUM-VALIDATORS
                             the number of validators
  -m, --maximum-non-signers MAXIMUM-NON-SIGNERS
                             the max allowed faults
```
