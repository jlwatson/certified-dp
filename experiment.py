'''
experiment.py

Convenience script to run the prover and verifier binaries in parallel and print
their output. Log messages are prefixed with the name of the binary that
produced them and go to stderr, while the final output of each binary is printed
to stdout.

----

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
'''

import argparse
from time import sleep
import subprocess
import threading

def stderr_reader(proc, label):
    while True:
        line = proc.stderr.readline()
        if line:
            strl = line.decode("utf-8")
            print(f"{label}    {strl.strip()}")
        if proc.poll() is not None:
            break


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Run experiment.')
    parser.add_argument('--db-size', type=int, help='Size of the database', required=True)
    parser.add_argument('--max-degree', type=int, help='Maximum degree of query', required=True)
    parser.add_argument('--dimension', type=int, help='Dimension of database entries')
    parser.add_argument('--epsilon', type=float, help='Epsilon for differential privacy', required=True)
    parser.add_argument('--delta', type=float, help='Delta for differential privacy')
    parser.add_argument('--sparsity', type=int, help='Sparsity of the query', required=True)
    parser.add_argument('--debug', action='store_true', help='Run debug binaries', default=False)
    parser.add_argument('--no-logs', action='store_true', help='Do not print logs', default=False)
    parser.add_argument('--skip-dishonest', action='store_true', help='Skip dishonest commitment phase', default=False)
    parser.add_argument('--num-queries', type=int, help='Number of queries to execute; timing averaged over queries', default=100)
    parser.add_argument('--sparsity-experiment', action='store_true', help='Run sparsity evaluation experiment', default=False)

    args = parser.parse_args()

    cargo_command = ["cargo", "run"]
    if not args.debug:
        cargo_command.append("--release")

    flamegraph_command = ["cargo", "flamegraph", "-o=prover.svg"]
    if not args.debug:
        flamegraph_command.append("--release")

    prover_command = [
        *cargo_command,
        "--bin", "prover", "--",
        "--db-size", str(args.db_size),
        "--max-degree", str(args.max_degree),
        "--sparsity", str(args.sparsity),
        "--epsilon", str(args.epsilon),
    ]
    if args.delta:
        prover_command.append("--delta")
        prover_command.append(str(args.delta))
    if args.dimension:
        prover_command.append("--dimension")
        prover_command.append(str(args.dimension))
    if args.skip_dishonest:
        prover_command.append("--skip-dishonest")
    if args.num_queries:
        prover_command.append("--num-queries")
        prover_command.append(str(args.num_queries))
    if args.sparsity_experiment:
        prover_command.append("--sparsity-experiment")

    # start prover in background
    with open("prover.log", "w") as f:
        prover = subprocess.Popen(prover_command, stdout=f, stderr=subprocess.PIPE)
    prover_read_thread = threading.Thread(target=stderr_reader, args=(prover, "[prover  ]"))
    prover_read_thread.start()

    sleep(5)

    verifier_command = [
        *cargo_command,
        "--bin", "verifier", "--",
        "--db-size", str(args.db_size),
        "--epsilon", str(args.epsilon),
        "--sparsity", str(args.sparsity),
        "--prover-address", "127.0.0.1:10020"
    ]
    if args.delta:
        verifier_command.append("--delta")
        verifier_command.append(str(args.delta))
    if args.dimension:
        verifier_command.append("--dimension")
        verifier_command.append(str(args.dimension))
    if args.skip_dishonest:
        verifier_command.append("--skip-dishonest")
    if args.num_queries:
        verifier_command.append("--num-queries")
        verifier_command.append(str(args.num_queries))
    if args.sparsity_experiment:
        verifier_command.append("--sparsity-experiment")
        
    with open("verifier.log", "w") as f:
        verifier = subprocess.Popen(verifier_command, stdout=f, stderr=subprocess.PIPE)
    verifier_read_thread = threading.Thread(target=stderr_reader, args=(verifier, "[verifier]"))
    verifier_read_thread.start()

    prover.wait()
    verifier.wait()

    prover_read_thread.join()
    verifier_read_thread.join()

    if not args.no_logs:
        print()
        print("=== prover.log ===")
        with open("prover.log") as f:
            print(f.read())

        print("=== verifier.log ===")
        with open("verifier.log") as f:
            print(f.read())
