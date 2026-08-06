# Payload classifier training

Trains the embedded char-n-gram logistic model (`../model/payload_ngram.json`) used by
`models::ngram_classifier`. The featurizer here is byte-identical to the Rust inference
path (normalize→lowercase, char n-grams {2,3,4}, FNV-1a hashing, binary presence) so
train-time and inference-time features match exactly.

`train_fp_suppression.py` is the script that produced the shipped model.

## Measuring generalisation — read this before quoting any number

Until the `HOLDOUT` split was added, **every metric this trainer printed was measured on
its own training data.** Concretely:

```python
adv_ben  = lines(ADV)          # ALL of adversarial_benign.txt
ben      = hard + fwaf + hp_ben + adv_ben + ...
allX     = atk + ben           # <- fitted on this
test_adv = lines(ADV)[:2000]   # <- "test" = first 2000 lines of a TRAINING file
```

The variable was named `test_adv`, but nothing was held out. The `hard-benign` figure had
the same defect (`hard` is inside `ben`), and the `gen-XSS/SQLi/CMDi` "sanity" recalls
draw from the same generators that produced the training attacks. Those numbers described
memorisation, so they could not tell you whether the model generalises at all.

### Run it honestly

```bash
python3 -m venv venv && ./venv/bin/pip install numpy scikit-learn scipy
HOLDOUT=0.15 ./venv/bin/python train_fp_suppression.py     # MEASURE
./venv/bin/python train_fp_suppression.py                  # SHIP (trains on everything)
```

`HOLDOUT` reserves a random slice of **both** pools before fitting. Default is `0` so a
plain run still reproduces the shipped model; every printed metric is tagged `TRAIN` or
`HELD-OUT` so the two cannot be confused.

## Measured results

`HOLDOUT=0.15`, K=32768, C=0.25 — **19,243 attack / 12,198 benign samples never seen
during the fit**:

| Metric | Value |
|---|---|
| Attack TPR @0.9 | **98.16%** |
| Benign TNR @0.15 | **99.12%** |
| Benign FPR | **0.88%** |

### What that number does and does not mean

This is an **in-distribution** estimate: the held-out slice is a random split of the same
corpora the model trained on. It says the model generalises well to unseen samples *of
the same kind*.

It is **not** an out-of-distribution estimate, and the difference is the whole precision
story. On GoTestWAF — a corpus the model has never been trained on and which is
deliberately kept external — the measured TN was ~89%, i.e. **FPR ~10.6%**. So:

| Setting | FPR |
|---|---|
| Held-out, same corpora | 0.88% |
| GoTestWAF (out-of-distribution) | ~10.6% |
| Commercial WAFs | 0.01–0.4% |

A 12× degradation from in-distribution to out-of-distribution points at **corpus
diversity**, not at regularisation or threshold tuning. Adding more of the same benign
data will keep improving the 0.88% and barely move the 10.6%. This is the single most
useful thing to know before spending effort on Fix 9's remaining items.

## Integrity

GoTestWAF (and any benchmark) is kept **EXTERNAL** — never folded into training. That is
what makes it a valid out-of-distribution measurement, and it is worth more than the
score it produces.

## ⚠ Reproducibility risk — the corpus lives in /tmp

`train_fp_suppression.py` reads its corpora from session scratchpad paths:

```
/tmp/claude-1000/-home-ayush3750-waf-development/<session-id>/scratchpad/{ml-corpus,evasion-corpus,benign-corpus,hard-benign}
```

They are currently present (~326 MB) but `/tmp` is cleared on reboot on most systems.
**If they are lost, the shipped model cannot be retrained, recalibrated, or improved** —
only used as-is. Every remaining Fix 9 item (threshold calibration, per-endpoint positive
security, shadow evaluation) requires retraining, so this is the blocker in front of all
of them, not a housekeeping note.

Archive the corpora somewhere durable and repoint `BASE` before doing any further model
work:

```bash
mkdir -p /opt/sentinel-ml-corpus
B=/tmp/claude-1000/-home-ayush3750-waf-development
cp -r "$B"/24905267-*/scratchpad/ml-corpus \
      "$B"/cbcb63a2-*/scratchpad/{evasion-corpus,benign-corpus,hard-benign} \
      /opt/sentinel-ml-corpus/
# then set BASE in train_fp_suppression.py to /opt/sentinel-ml-corpus
```

Licences were not re-verified during this change; check them before redistributing any
corpus.

## Still outstanding for Fix 9

- **Threshold calibration** against the measured curve rather than the hardcoded 0.9 /
  0.15 constants (0.15 is duplicated in `crates/sentinel-proxy/src/lib.rs` — the two
  must move together).
- **Per-endpoint positive security / OpenAPI learning** — the largest available FPR
  lever, and the thing F5 actually sells.
- **Real-traffic FPR via ClickHouse shadow evaluation**, gating releases.
- All three need the corpus archived first (see above).
