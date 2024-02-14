## Certified DP

### Overview

This repository contains a Rust-based implementation of a certified Binomial mechanism for arbitary differentially-private counting queries, backed by `curve25519-dalek`, which implements Pedersen commitments over the prime-
order Ristretto group.

The Prover and Verifier execute as separate processes and communicate through a localhost TCP socket.

### Getting started

This projects requires Rust [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

To run both the prover and the verifier on a simple example with epsilon=1, n=1024 7-bit database entries, and a query sparsity of 7, run:

`$ python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7`

Both processes will start and begin printing status messages to `stderr`. Once the query has been completed, a summary of performance statistics for both parties will be printed to `stdout` -- these timing outputs underly the evaluation in our paper.

### Repository structure

```
experiment.py             # convenience script to run prover & verifier and log output
eval/
    *.log                 # performance logs underlying paper evaluation
    eval-results.ipynb    # data process & figure generation
    eval.sh               # convenience script to rerun all main evaluation
src/
    config.rs             # project wide constants/configuration
    data.rs               # database loading/generation
    messages.rs           # prover <-> verifier serialization/communication
    pedersen.rs           # pedersen commitment implementation, heavily based on https://github.com/aled1027/tiny_ped_com
    bit_sigma.rs          # bit-Σ protocol implementation
    product_sigma.rs      # product-Σ protocol implementation
    bin/
        prover.rs         # primary Prover executable
        verifier.rs       # primary Verifier executable
```

### experiment.py

`experiment.py` allows you to set many configuration parameters and consistently run a prover and verifier against each other.

```
usage: experiment.py [-h] --db-size DB_SIZE --max-degree MAX_DEGREE [--dimension DIMENSION] --epsilon EPSILON [--delta DELTA] --sparsity SPARSITY [--debug] [--no-logs] [--skip-dishonest] [--num-queries NUM_QUERIES] [--sparsity-experiment]

options:
  -h, --help            show this help message and exit
  --db-size DB_SIZE     Size of the database
  --max-degree MAX_DEGREE
                        Maximum degree of query
  --dimension DIMENSION
                        Dimension of database entries
  --epsilon EPSILON     Epsilon for differential privacy
  --delta DELTA         Delta for differential privacy
  --sparsity SPARSITY   Sparsity of the query
  --debug               Run debug binaries
  --no-logs             Do not print logs
  --skip-dishonest      Skip dishonest commitment phase
  --num-queries NUM_QUERIES
                        Number of queries to execute; timing averaged over queries
  --sparsity-experiment
                        Run sparsity evaluation experiment
```

### Census-based query example

The Census-based query workload resides in a different `census` branch; details are in that branch's README.

`git checkout census`