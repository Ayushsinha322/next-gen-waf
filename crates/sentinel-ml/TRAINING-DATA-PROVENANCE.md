# Payload classifier — training data provenance

This records where the classifier's training data came from, what is actually
redistributed, and the one question that remains open. It exists because the
pre-internal-beta licensing audit could not answer "what is this model trained
on?" from anything in the repository.

**This is a factual record, not a legal opinion.** Where a licence could not be
verified from the material on disk, it says so rather than guessing.

---

## What actually ships

`crates/sentinel-ml/model/payload_ngram.json`, compiled into the data-plane
binary. Verified contents:

| Field | Value |
|---|---|
| `k` | 32768 (hashed feature buckets) |
| `ngrams` | `[2, 3, 4]` (character n-gram sizes) |
| `bias` | a single float |
| `weights` | 32,768 floats |

That is the whole file. A scan for alphabetic tokens of six characters or more
returns exactly two hits — the JSON key names `ngrams` and `weights`. **No
training text is present, and none is recoverable**: features are character
n-grams hashed into 32,768 buckets, which is a lossy, one-way mapping with heavy
collision. The shipped artifact is a vector of numbers.

The corpora themselves are **not in this repository** and are not redistributed.
They live outside the tree (`~/waf-ml-corpora/`) and the trainer reads them from
a path given at training time.

This materially narrows the question. What is at issue is whether *training on*
the material was permitted, not whether we are redistributing it — we are not.

## Where the data came from

Roughly 1.57 million lines across four corpora. Upstream projects, counted by
the filename prefixes the collection scripts used:

| Upstream | Files | Licence file on disk? | Notes |
|---|---:|---|---|
| **HttpParamsDataset** (Morzeux) | 4 CSVs | ✅ **MIT**, `ml-corpus/HttpParamsDataset/LICENSE`, © 2016 Morzeux | The only corpus that carries its own licence locally |
| SecLists (danielmiessler) | 60 | ❌ none locally | Commonly MIT upstream — **verify against the repository, do not rely on this note** |
| payloadbox | 57 | ❌ none locally | Several separate repositories (sqli, xss, command-injection) |
| PayloadsAllTheThings (swisskyrepo) | 49 | ❌ none locally | |
| foospidy/payloads | 36 | ❌ none locally | |
| Project Gutenberg | 3 | ❌ none locally | `gb_1342`, `gb_2701`, `gb_84` — long-public-domain works, but Gutenberg attaches its own terms to *its* editions |
| brutelogic / rsnake / polyglot XSS lists | 3 | ❌ none locally | Historic published XSS cheat sheets |
| fwaf (`good_fwaf.txt`) | 1 | ❌ none locally | 1.29 M benign lines — the single largest input by volume |
| Self-authored (`hard-benign/`, `*_legit_*`) | 14 | n/a — ours | Curated from framework and documentation examples for FP suppression |

**An absent licence file is not permission.** Absent an express grant, the
default is all rights reserved, and that is the position to assume for every row
marked ❌ until someone checks the upstream repository.

## The open question

Whether training a model on these corpora — and shipping only derived,
non-invertible weights — is permitted. Points that bear on it, neutrally stated:

* Nothing textual is redistributed. The artifact is 32,768 floats.
* Much of the attack material is itself a compilation of publicly published
  exploit strings, much of it not original to the compiler.
* The largest single input by volume (`good_fwaf.txt`, 1.29 M lines) is the one
  with the least clear provenance.

**This needs a legal opinion. It is not an engineering call and nothing here
should be read as one.**

## If the answer is "retrain"

The pipeline already supports it, so this is a bounded piece of work rather than
a rebuild:

1. Train on the MIT-licensed HttpParamsDataset plus our own `hard-benign/`
   material and traffic we have collected ourselves.
2. Re-run the calibration guard: `crates/sentinel-ml/tests/fp_suppression_calibration.rs`.
3. Re-run the GoTestWAF benchmark before accepting the result.

⚠️ **Expect a measurable detection cost and budget for it.** The headline figure
(99.64% composite) was reached with the full corpus, and the detection-engineering
history for this model is that coverage of the *input space* mattered more than
any tuning. Dropping the majority of the attack corpus is not a cosmetic change
and must not be swapped in without re-benchmarking.

## Also worth knowing

The corpora are not in version control and exist on one workstation. They are
not backed up by anything in this repository. If the decision is to keep the
current model, the inputs that produced it should be preserved somewhere durable
— otherwise the model cannot be reproduced or audited later.
