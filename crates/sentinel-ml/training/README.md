# Payload classifier training

Trains the embedded char-n-gram logistic model (`../model/payload_ngram.json`)
used by `models::ngram_classifier`. The featurizer here is byte-identical to the
Rust inference path (normalize→lowercase, char n-grams {2,3,4}, FNV-1a % 4096,
binary presence) so train-time and inference-time features match exactly.

## Corpus (not committed — fetch locally; verify licenses before shipping)
- Morzeux/HttpParamsDataset — labeled param values (norm/anom) + ready split.
- Adversarial-benign augmentation (generated in `train.py`): real English prose
  phrases (Project Gutenberg), legit SQL queries, benign JSON/paths — all
  label=0. This is what stops the model flagging "SELECT in prose" as an attack.

## Run
    python3 -m venv venv && ./venv/bin/pip install numpy scikit-learn
    # place HttpParamsDataset/ and gb_*.txt (Gutenberg) next to train.py
    ./venv/bin/python train.py   # writes payload_ngram.json → copy to ../model/

## Integrity
GoTestWAF (and any benchmark) is kept EXTERNAL — never folded into training.
Measured held-out: 99.6% TPR / 0% FPR on HttpParamsDataset test; 1.1% FPR on the
lexical hard-benign set.
