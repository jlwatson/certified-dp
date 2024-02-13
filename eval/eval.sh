# epsilon experiments
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=10 --sparsity=7 > eval/eval-epsilon-db-1024-d-7-e-10-s-7.log
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-epsilon-db-1024-d-7-e-1-s-7.log
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=0.1 --sparsity=7 > eval/eval-epsilon-db-1024-d-7-e-0,1-s-7.log

# database size experiements
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-size-db-1024-d-7-e-1-s-7.log
python experiment.py --db-size=2048 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-size-db-2048-d-7-e-1-s-7.log
python experiment.py --db-size=4096 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-size-db-4096-d-7-e-1-s-7.log
python experiment.py --db-size=8192 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-size-db-8192-d-7-e-1-s-7.log
python experiment.py --db-size=16384 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-size-db-16384-d-7-e-1-s-7.log

# sparsity experiment
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 --sparsity-experiment --skip-dishonest > eval/eval-sparsity-db-1024-d-7-e-1-s-7-nodishonest.log

# comparison experiment
python experiment.py --db-size=1000000 --max-degree=1 --dimension=1 --epsilon=0.095 --sparsity=1 --delta=0.0000000001 > eval/eval-comp-db-1000000-d-1-e-0,095-s-1-d-0,0000000001.log

# database dimension experiment
python experiment.py --db-size=1024 --max-degree=7 --dimension=7 --epsilon=1 --sparsity=7 > eval/eval-dimension-db-1024-d-7-e-1-s-7.log
python experiment.py --db-size=1024 --max-degree=10 --dimension=10 --epsilon=1 --sparsity=10 > eval/eval-dimension-db-1024-d-10-e-1-s-7.log
python experiment.py --db-size=1024 --max-degree=12 --dimension=12 --epsilon=1 --sparsity=12 > eval/eval-dimension-db-1024-d-12-e-1-s-7.log
python experiment.py --db-size=1024 --max-degree=14 --dimension=14 --epsilon=1 --sparsity=14 > eval/eval-dimension-db-1024-d-14-e-1-s-7.log
