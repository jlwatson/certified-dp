## Certified DP

### Overview

This repository contains a Rust-based implementation of a certified Binomial mechanism for arbitary differentially-private counting queries, backed by `curve25519-dalek`, which implements Pedersen commitments over the prime-
order Ristretto group.

The Prover and Verifier execute as separate processes and communicate through a localhost TCP socket.

The evaluation numbers presented in the paper were acquired on a 2.7 GHz Quad-Core Intel Core i7 processor with 16 GB RAM. 

### Getting started

1. This projects requires
  * A Rust installation: [(https://www.rust-lang.org/tools/install)](https://www.rust-lang.org/tools/install).
  * GCC: `apt install gcc`

2. To run both the prover and the verifier on a simple example with _ε=1_, _n=1024_ 7-bit database entries, and a query sparsity of 7, run:

  `$ python3 experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7`

Both processes will start and begin printing status messages to `stderr`. Once the query has been completed, a summary of performance statistics for both parties will be printed to `stdout` -- these timing outputs underly the evaluation in our paper.

### Repository structure

```
experiment.py             # convenience script to run prover & verifier and log output
eval/
    *.log                 # performance logs underlying paper evaluation
    eval-results.ipynb    # data processing & figure generation
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

The Census-based query workload resides in a different `census` branch that resides at [https://github.com/jlwatson/certified-dp/tree/census](https://github.com/jlwatson/certified-dp/tree/census); details are in that branch's README.
