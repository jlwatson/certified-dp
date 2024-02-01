import argparse
from time import sleep
import subprocess

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Run experiment.')
    parser.add_argument('--db-size', type=int, help='Size of the database', required=True)
    parser.add_argument('--max-degree', type=int, help='Maximum degree of query', required=True)
    parser.add_argument('--epsilon', type=float, help='Epsilon for differential privacy', required=True)
    parser.add_argument('--sparsity', type=int, help='Sparsity of the query', required=True)

    args = parser.parse_args()

    # start prover in background
    with open("prover.log", "w") as f:
        prover = subprocess.Popen([
            "cargo", "run", "--release", "--bin", "prover", "--",
            "--db-size", str(args.db_size),
            "--max-degree", str(args.max_degree),
            "--epsilon", str(args.epsilon),
            "--db-path", "doesntmatter"
        ], stdout=f, stderr=f)

    sleep(5)
        
    with open("verifier.log", "w") as f:
        verifier = subprocess.Popen([
            "cargo", "run", "--release", "--bin", "verifier", "--",
            "--db-size", str(args.db_size),
            "--max-degree", str(args.max_degree),
            "--epsilon", str(args.epsilon),
            "--sparsity", str(args.sparsity),
            "--prover-address", "127.0.0.1:10020"
        ], stdout=f, stderr=f)

    prover.wait()
    verifier.wait()

    print()
    print("=== prover.log ===")
    with open("prover.log") as f:
        print(f.read())

    print()
    print("=== verifier.log ===")
    with open("verifier.log") as f:
        print(f.read())
